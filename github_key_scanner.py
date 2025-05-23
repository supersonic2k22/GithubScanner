# -*- coding: utf-8 -*-
import aiohttp, asyncio, re, logging, os
from urllib.parse import quote
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from solders.keypair import Keypair
import aiofiles

# Шляхи (Windows)
BASE = r"C:\Users\user\Desktop\github scanner"
LOGS = os.path.join(BASE, "logs")
KEYS_DIR = os.path.join(BASE, "keys")

# Логування
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()
repo_log = logging.getLogger('repo')
repo_log.setLevel(logging.INFO)
repo_handler = logging.FileHandler(os.path.join(LOGS, 'repos.log'), encoding='utf-8')
repo_handler.setFormatter(logging.Formatter('%(message)s'))
repo_log.addHandler(repo_handler)

# Конфігурація
load_dotenv(os.path.join(BASE, ".env"))
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
HELIUS_KEY = os.getenv("HELIUS_API_KEY")
if not GITHUB_TOKEN:
    raise ValueError("GITHUB_TOKEN missing")
SOLANA_ON = bool(HELIUS_KEY)
if not SOLANA_ON:
    logger.warning("HELIUS_API_KEY missing. Solana balance check disabled.")

# Директорії
os.makedirs(LOGS, exist_ok=True)
os.makedirs(KEYS_DIR, exist_ok=True)
SOLANA_FILE = os.path.join(KEYS_DIR, "solana_keys.txt")
try:
    with open(SOLANA_FILE, "a", encoding="utf-8") as f:
        f.write("")
except Exception as e:
    logger.error(f"Cannot write to {SOLANA_FILE}: {e}")
    raise

# Константи
HEADERS = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"}
BASE_URL = "https://api.github.com"
SOLANA_RPC = f"https://mainnet.helius-rpc.com/?api-key={HELIUS_KEY}"
TIMEOUTS = {"repo": 10, "crypto": 5, "byte": 2, "write": 10}
MAX_SCANS = 2
MAX_FILES = 5
MAX_REQS = 10
ERR_PAUSE = 10
QUEUE_SIZE = 100
MAX_KEYS = 10
EXTS = {'.txt', '.py', '.js', '.json', '.md', '.yml', '.yaml', '.ts', '.jsx', '.tsx', '.html', '.css', '.java', '.cpp', '.c', '.h', '.cs', '.go', '.rb', '.php', '.sh', '.bat', '.xml', '.ini', '.conf'}
TEXT_TYPES = {'text/plain', 'application/json', 'text/x-python', 'application/javascript', 'text/javascript', 'text/x-yaml', 'text/html', 'text/css', 'text/x-markdown', 'text/x-sh', 'application/xml', 'text/xml'}

KEYS = set()
REPOS = set()
REPO_IDS = set()
COUNT = 0
KEY_LOCK = asyncio.Lock()
REQ_SEM = asyncio.Semaphore(MAX_REQS)
FILE_SEM = asyncio.Semaphore(MAX_FILES)
WRITE_SEM = asyncio.Semaphore(1)

# Оброблені репозиторії
def load_repos():
    repo_log_path = os.path.join(LOGS, "repos.log")
    if not os.path.exists(repo_log_path):
        return
    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    try:
        with open(repo_log_path, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(" - ")
                if len(parts) >= 3 and parts[2].startswith("Scanning "):
                    repo = parts[2].split(" (")[0].replace("Scanning ", "")
                    try:
                        if datetime.strptime(parts[1], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc) >= cutoff:
                            REPOS.add(repo)
                    except ValueError:
                        continue
        logger.info(f"Loaded {len(REPOS)} repos")
    except Exception as e:
        logger.error(f"Error loading repos: {e}")

load_repos()

def is_hex_key(data):
    if not re.match(r"^[0-9a-fA-F]{64}$", data) or data == "0" * 64:
        return False
    try:
        Keypair.from_seed(bytes.fromhex(data)[:32])
        return True
    except:
        return False

async def is_byte_array(data):
    if not re.match(r"(?:#|//)?\s*\[\s*(?:(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])(?:\s*,?\s*)){32}\s*\]", data, re.MULTILINE):
        return False
    try:
        async with asyncio.timeout(TIMEOUTS["byte"]):
            bytes_list = [int(x) for x in data.strip("[]#/\n").replace(" ", "").split(",") if x]
            if len(bytes_list) != 32 or any(b < 0 or b > 255 for b in bytes_list):
                return False
            hex_key = "".join([format(b, "02x") for b in bytes_list])
            return hex_key if is_hex_key(hex_key) else False
    except asyncio.TimeoutError:
        logger.warning(f"Timeout processing byte array: {data[:50]}...")
        return False
    except:
        return False

def to_sol_address(key):
    if not SOLANA_ON:
        return None
    try:
        return str(Keypair.from_seed(bytes.fromhex(key)[:32]).pubkey())
    except Exception as e:
        logger.error(f"Error converting key: {e}")
        return None

async def get_balance(session, key):
    if not SOLANA_ON:
        return {}
    addr = to_sol_address(key)
    if not addr:
        return {}
    try:
        async with REQ_SEM, session.post(SOLANA_RPC, json={"jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": [addr]}, timeout=TIMEOUTS["crypto"]) as resp:
            if resp.status != 200:
                logger.warning(f"Solana balance check failed for {addr}: HTTP {resp.status}")
                return {}
            data = await resp.json()
            sol = data.get("result", {}).get("value", 0) / 1_000_000_000
            return {"SOL": sol}
    except asyncio.TimeoutError:
        logger.warning(f"Timeout checking balance for {addr}")
        return {}
    except Exception as e:
        logger.error(f"Balance check error: {e}")
        return {}

async def scan_file(session, url, repo, pos, total):
    try:
        async with FILE_SEM, REQ_SEM, session.get(url, headers=HEADERS) as resp:
            if resp.status != 200:
                logger.warning(f"File fetch failed {url}: HTTP {resp.status}")
                return []
            if resp.headers.get('Content-Type', '').split(';')[0].lower() not in TEXT_TYPES:
                return []
            content = await resp.text()
    except Exception as e:
        logger.error(f"Error fetching file {url}: {e}")
        return []

    keys = []
    # Hex ключі
    for candidate in re.findall(r"(?:private_key\s*=\s*|key\s*=\s*|#|//|\s)([0-9a-fA-F]{64})(?:\s|$)", content, re.IGNORECASE):
        if is_hex_key(candidate):
            async with KEY_LOCK:
                if candidate in KEYS:
                    continue
                KEYS.add(candidate)
            logger.info(f"Found key in {repo} ({pos}/{total}): {candidate[:8]}...")
            balances = await get_balance(session, candidate)
            keys.append({"key": candidate, "repo": repo, "balances": balances, "type": "hex"})

    # Byte array ключі
    for candidate in re.findall(r"(?:#|//)?\s*\[\s*(?:(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])(?:\s*,?\s*)){32}\s*\]", content, re.MULTILINE):
        if hex_key := await is_byte_array(candidate):
            async with KEY_LOCK:
                if hex_key in KEYS:
                    continue
                KEYS.add(hex_key)
            logger.info(f"Found byte array key in {repo} ({pos}/{total}): {hex_key[:8]}...")
            balances = await get_balance(session, hex_key)
            keys.append({"key": hex_key, "repo": repo, "balances": balances, "type": "byte_array"})

    return keys

async def scan_repo(session, repo, pos, total):
    global COUNT
    name = repo["full_name"]
    async with KEY_LOCK:
        if name in REPOS:
            return []
        REPOS.add(name)

    COUNT += 1
    created = repo.get("created_at", "N/A")
    repo_log.info(f"{COUNT} - {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} - Scanning {name} ({pos}/{total})")
    logger.info(f"Scanning {name} ({pos}/{total})")

    try:
        async with REQ_SEM, session.get(f"{BASE_URL}/repos/{name}/contents", headers=HEADERS, timeout=TIMEOUTS["repo"]) as resp:
            if resp.status != 200:
                logger.warning(f"Contents fetch failed for {name}: HTTP {resp.status}")
                return []
            contents = await resp.json()
    except:
        logger.warning(f"Error fetching contents for {name}")
        return []

    tasks = [asyncio.create_task(scan_file(session, item["download_url"], name, pos, total))
             for item in contents
             if item["type"] == "file" and item["name"].lower() != "readme.md" and os.path.splitext(item["name"])[1].lower() in EXTS and item.get("download_url")]
    
    keys = []
    for result in await asyncio.gather(*tasks, return_exceptions=True):
        if isinstance(result, list):
            keys.extend(result)
    
    return keys[:MAX_KEYS]

async def save_keys(keys):
    if not keys:
        return
    lines = [f"{k['key']} | SOL: {k['balances'].get('SOL', 0):.8f} (${k['balances'].get('SOL', 0) * 150:.2f} USD) | Type: {k['type']} | Repo: {k['repo']}\n"
             if k["balances"].get("SOL") else f"{k['key']} | N/A | Type: {k['type']} | Repo: {k['repo']}\n"
             for k in keys]
    try:
        async with WRITE_SEM, asyncio.timeout(TIMEOUTS["write"]), aiofiles.open(SOLANA_FILE, "a", encoding="utf-8") as f:
            await f.writelines(lines)
            await f.flush()
        logger.info(f"Saved {len(keys)} keys to {SOLANA_FILE}")
    except asyncio.TimeoutError:
        logger.error(f"Timeout saving keys: exceeded {TIMEOUTS['write']}s")
    except Exception as e:
        logger.error(f"Failed to save keys: {e}")

async def fetch_repos(session, queue, start):
    query = f"sol OR solana OR pumpfun OR phantom created:{start.strftime('%Y-%m-%d')}"
    logger.info(f"Query: {query}")
    url = f"{BASE_URL}/search/repositories?q={quote(query)}&sort=created&order=desc"
    page = 1
    while queue.qsize() < QUEUE_SIZE:
        try:
            async with REQ_SEM, session.get(f"{url}&page={page}&per_page=100", headers=HEADERS) as resp:
                if resp.status == 403 and "rate limit" in (await resp.text()).lower():
                    wait = max(60, int(resp.headers.get("X-RateLimit-Reset", 0)) - int(datetime.now(timezone.utc).timestamp()) + 5)
                    logger.warning(f"Rate limit hit, waiting {wait}s")
                    await asyncio.sleep(wait)
                    continue
                if resp.status != 200:
                    logger.error(f"Repo fetch failed: HTTP {resp.status}")
                    break
                remaining = resp.headers.get("X-RateLimit-Remaining", "unknown")
                if remaining != "unknown" and int(remaining) < 5:
                    wait = max(60, int(resp.headers.get("X-RateLimit-Reset", 0)) - int(datetime.now(timezone.utc).timestamp()) + 5)
                    logger.warning(f"Low rate limit ({remaining}), waiting {wait}s")
                    await asyncio.sleep(wait)
                data = await resp.json()
                repos = data.get("items", [])
                logger.info(f"Found {data.get('total_count', 0)} repos for query: {query}")
                if not repos:
                    break
                async with KEY_LOCK:
                    for repo in repos:
                        if repo["id"] not in REPO_IDS and repo["full_name"] not in REPOS:
                            REPO_IDS.add(repo["id"])
                            await queue.put(repo)
                            logger.info(f"Queued {repo['full_name']} ({queue.qsize()}/{QUEUE_SIZE})")
        except Exception as e:
            logger.error(f"Error fetching page {page}: {e}")
            break
        page += 1

async def process_queue(session, queue):
    pos = 0
    total = queue.qsize()
    tasks = []
    while not queue.empty():
        pos += 1
        repo = await queue.get()
        tasks.append(asyncio.create_task(scan_repo(session, repo, pos, total)))
        if len(tasks) >= MAX_SCANS:
            for result in await asyncio.gather(*tasks, return_exceptions=True):
                if isinstance(result, list) and result:
                    await save_keys(result)
            tasks = []
        queue.task_done()
    if tasks:
        for result in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(result, list) and result:
                await save_keys(result)
        for _ in tasks:
            queue.task_done()
    if not tasks and queue.empty():
        logger.info("Queue exhausted, starting next cycle")

async def main():
    async with aiohttp.ClientSession() as session:
        cycle = 0
        last_scanned_day = None
        while True:
            try:
                cycle += 1
                global COUNT, REPO_IDS, KEYS
                COUNT = 0
                REPO_IDS = set()
                KEYS = set()
                logger.info(f"Cycle {cycle}")
                queue = asyncio.Queue()
                now = datetime.now(timezone.utc)
                # Start with two days ago if not scanned, or move to previous day
                if last_scanned_day is None:
                    start = now.replace(hour=0, minute=0, second=0, microsecond =0) - timedelta(days=2)
                else:
                    start = last_scanned_day - timedelta(days=1)
                logger.info(f"Scanning day: {start.strftime('%Y-%m-%d')}")
                await fetch_repos(session, queue, start)
                if queue.qsize() == 0:
                    logger.info(f"No repos found for {start.strftime('%Y-%m-%d')}, moving to previous day")
                    last_scanned_day = start
                    await asyncio.sleep(5)
                    continue
                await process_queue(session, queue)
                logger.info(f"Processed {COUNT} repos for {start.strftime('%Y-%m-%d')}")
                last_scanned_day = start
            except Exception as e:
                logger.error(f"Main loop error: {e}")
                await asyncio.sleep(ERR_PAUSE)

if __name__ == "__main__":
    asyncio.run(main())