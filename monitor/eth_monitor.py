import time
import logging
from web3 import Web3
from eth_account import Account

# RPC для Ethereum (можеш замінити на власний Infura або Alchemy)
RPC_URL = "https://eth.llamarpc.com"
w3 = Web3(Web3.HTTPProvider(RPC_URL))

# Тестова адреса для переказів
TARGET_WALLET = "0x5cFB0c77F63FDC8d0d2368c9Efd31D037007F05b".lower()

# Файл з приватними ключами
KEYS_FILE = "eth_keys.txt"

# Поріг у ETH
THRESHOLD_ETH = 0.00001

# Налаштування логування
logging.basicConfig(
    filename='eth_monitor.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    encoding='utf-8'  # <- додаємо це
)


def load_private_keys_from_file(filename):
    keys = []
    with open(filename, 'r') as file:
        for line in file:
            parts = line.strip().split('|')
            if len(parts) > 0:
                raw_key = parts[0].strip()
                if raw_key.startswith("0x") and len(raw_key) == 66:
                    keys.append(raw_key)
    return keys

def check_and_send(pk: str):
    acct = Account.from_key(pk)
    address = acct.address.lower()

    balance_wei = w3.eth.get_balance(address)
    balance_eth = w3.from_wei(balance_wei, 'ether')

    logging.info(f"[👀] Перевірка {address}, баланс: {balance_eth:.8f} ETH")

    if balance_eth > THRESHOLD_ETH:
        nonce = w3.eth.get_transaction_count(address)
        gas_price = w3.eth.gas_price
        gas_limit = 21000
        fee = gas_price * gas_limit

        if balance_wei <= fee:
            logging.warning(f"[⚠️] Баланс замалий для переказу на {address}")
            return

        tx = {
            'to': TARGET_WALLET,
            'value': balance_wei - fee,
            'gas': gas_limit,
            'gasPrice': gas_price,
            'nonce': nonce,
            'chainId': 1  # Ethereum mainnet
        }

        signed = w3.eth.account.sign_transaction(tx, pk)
        tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)

        logging.info(f"[✅] Відправлено {balance_eth:.6f} ETH з {address} → {TARGET_WALLET} | TX: https://etherscan.io/tx/{tx_hash.hex()}")

def main():
    logging.info("🔍 Старт моніторингу Ethereum-гаманців...")
    while True:
        try:
            private_keys = load_private_keys_from_file(KEYS_FILE)
            for pk in private_keys:
                check_and_send(pk)
        except Exception as e:
            logging.error(f"[❌] Загальна помилка: {e}")
        time.sleep(15)

if __name__ == "__main__":
    main()
