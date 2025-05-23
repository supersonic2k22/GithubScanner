from solders.hash import Hash
from solders.keypair import Keypair
from solders.message import MessageV0
from solders.system_program import TransferParams, transfer
from solders.transaction import VersionedTransaction
from solana.rpc.api import Client
from solders.pubkey import Pubkey
from solders.message import Message
from solders.transaction import Transaction
from solders.system_program import transfer, TransferParams
from solana.rpc.types import TxOpts

import logging
import sys
import time
import os
import base64
import base58
from dotenv import load_dotenv

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

load_dotenv()

RPC_URL = "https://api.mainnet-beta.solana.com"
DESTINATION_ADDRESS = Pubkey.from_string("3nRCpN6Zyrq3sxVNyhzVwPWjSB9zDQCRp2osP8YLBZua")
KEYS_FILE = "../keys/solana_keys.txt"
LAMPORTS_BUFFER = 5000
MIN_TRANSFER = 100_000  # 0.0001 SOL

client = Client(RPC_URL)

def load_private_keys(filename):
    keypairs = []
    with open(filename, 'r') as file:
        for line in file:
            raw = line.strip()
            key_str = raw.split(' ')[0]
            try:
                b = base64.b64decode(key_str)
                if len(b) == 64:
                    keypairs.append(Keypair.from_bytes(b))
                    continue
            except Exception:
                pass
            try:
                b = base58.b58decode(key_str)
                if len(b) == 64:
                    keypairs.append(Keypair.from_bytes(b))
            except Exception:
                pass
    return keypairs

def get_balance_rpc(pubkey: Pubkey) -> int:
    try:
        resp = client.get_balance(pubkey)
        lamports = resp.value
        return lamports
    except Exception as e:
        logger.error(f"Помилка при запиті балансу RPC: {e}")
        return 0

def check_and_send(kp: Keypair):
    pubkey = kp.pubkey()
    lamports = get_balance_rpc(pubkey)
    sol = lamports / 1e9
    logger.info(f"👀 {pubkey} — {sol:.6f} SOL")

    if lamports > (LAMPORTS_BUFFER + MIN_TRANSFER):

        ix = transfer(
            TransferParams(
                from_pubkey=pubkey,
                to_pubkey=DESTINATION_ADDRESS,
                lamports=lamports - LAMPORTS_BUFFER
            )
        )
        
        blockhash = client.get_latest_blockhash().value.blockhash
        if not blockhash:
            logger.error(f"❌ Не вдалося отримати recent blockhash для {pubkey}")
            return
        
        msg = MessageV0.try_compile(
            payer=pubkey,
            instructions=[ix],
            address_lookup_table_accounts=[],
            recent_blockhash=blockhash,
        )

        tx = VersionedTransaction(msg, [kp])
        
        client.send_transaction(
            tx
        )



def main():
    logger.info("🚀 Старт моніторингу через Solana RPC...")
    while True:
        try:
            keypairs = load_private_keys(KEYS_FILE)
            if not keypairs:
                logger.error("Не завантажено ключів. Перевір файл з ключами.")
                break
            for kp in keypairs:
                check_and_send(kp)
        except Exception as e:
            logger.error(f"❌ Глобальна помилка: {e}")
        time.sleep(10)

if __name__ == "__main__":
    main()
