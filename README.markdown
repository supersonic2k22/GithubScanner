# GitHub Private Key Scanner

## Purpose

**This tool is NOT intended for hacking or unauthorized access to accounts.** It is an educational and demonstration tool designed to highlight security vulnerabilities on GitHub, specifically the risks of accidentally exposing private cryptographic keys in public repositories. By scanning for private keys and checking their balances, this tool aims to raise awareness about secure coding practices and the importance of protecting sensitive information.

**Ethical Use**: This tool should only be used for educational purposes, security research, or with explicit permission from repository owners. Unauthorized use is strictly prohibited and may violate laws or platform policies.

## Description

The `github_key_scanner.py` script continuously monitors public GitHub repositories created within the last 5 minutes for private cryptographic keys in Base58, hex, or byte array formats, associated with Bitcoin, Ethereum, or Solana wallets. It checks the balance of detected keys and saves those with a balance equivalent to $10 or more to `found_keys.txt`. The tool uses the GitHub API for repository access and public blockchain APIs for balance checks, running scans every 60 seconds to catch new repositories.

### Features

- Scans repositories created in the last 5 minutes for private keys in `.py`, `.txt`, and `.json` files (excludes `README.md`).
- Supports Bitcoin (Base58 keys), Ethereum, and Solana (hex or byte array keys).
- Checks balances with a minimum threshold of $10 (based on fixed prices: BTC $60,000, ETH $2,500, SOL $150).
- Implements a 10-second timeout per repository to prevent hangs.
- Implements a 5-second timeout for Solana API requests.
- Logs all activities to `scanner.log` for debugging.
- Displays duplicate keys with a counter in the console.
- Avoids re-scanning processed repositories.
- Continuously monitors new repositories every 60 seconds.
- Searches using an extensive set of keywords, split into multiple queries to comply with GitHub API limits.

## Prerequisites

- Python 3.8 or higher.
- A GitHub Personal Access Token with `repo` scope.
- An Etherscan API key for Ethereum balance checks.
- An Alchemy Solana API key for Solana balance checks (optional).

## Installation

1. **Clone the repository** or download the script files.

2. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

3. **Create a** `.env` **file** in the project root with the following:

   ```plaintext
   GITHUB_TOKEN=your_github_personal_access_token
   ETHERSCAN_API_KEY=your_etherscan_api_key
   ALCHEMY_SOLANA_API_KEY=your_alchemy_solana_api_key
   ```

   - Obtain a GitHub token: GitHub &gt; Settings &gt; Developer settings &gt; Personal access tokens &gt; Generate new token (select `repo` scope).
   - Get an Etherscan API key: Etherscan.
   - Get an Alchemy Solana API key: Alchemy (optional; Solana checks disabled without it).

## Usage

1. Ensure the `.env` file is configured.

2. Run the script:

   ```bash
   python github_key_scanner.py
   ```

3. The script will:

   - Scan GitHub repositories created in the last 5 minutes, matching keywords like `crypto`, `solana`, `pumpfun`, etc.
   - Search for private keys in supported file types.
   - Check balances for Bitcoin, Ethereum, and Solana (if enabled).
   - Save keys with balances ≥ $10 to `found_keys.txt`.
   - Log activities to `scanner.log`.
   - Display progress, duplicates, and errors in the console.
   - Repeat the scan every 60 seconds to monitor new repositories.

### Example Console Output

```
Fetching repositories for keywords: crypto OR blockchain OR bitcoin OR ethereum OR solana OR wallet created after 2025-04-19T03:28...
API requests remaining: 4998
Fetching repositories for keywords: defi OR nft OR dex OR dapp OR token OR smartcontract created after 2025-04-19T03:28...
API requests remaining: 4997
Fetching repositories for keywords: web3 OR pumpfun OR raydium OR jupiter OR orca OR serum created after 2025-04-19T03:28...
API requests remaining: 4996
Fetching repositories for keywords: binance OR polygon OR avalanche OR arbitrum OR optimism created after 2025-04-19T03:28...
API requests remaining: 4995
Fetched 8 repositories created after 2025-04-19T03:28
Scanning user/pumpfun-dapp (created: 2025-04-19 03:29:50+00:00)
Found Hex key in user/pumpfun-dapp: a1b2c3d4...
Checking Ethereum balance for key: a1b2c3d4...
Found Ethereum balance: 0.50000000 ETH ($1250.00)
Saved 1 keys to found_keys.txt
Duplicate Hex key found in user/pumpfun-dapp: a1b2c3d4... (count: 2)
Scanning keidev123/solana-wallet (created: 2025-04-19 03:28:30+00:00)
Timeout scanning keidev123/solana-wallet: exceeded 10 seconds
Waiting 60 seconds for next scan...
```

### Output Files

- `found_keys.txt`: Contains private keys with balances ≥ $10, one per line.
- `scanner.log`: Logs all activities, errors, and timeouts for debugging.

## Configuration

- **GitHub Token**: Required for API access. Ensure it has `repo` scope.
- **Etherscan API Key**: Required for Ethereum balance checks.
- **Alchemy Solana API Key**: Optional. Without it, Solana balance checks are disabled.
- **Timeouts**:
  - Repository scan: 10 seconds (`REPO_SCAN_TIMEOUT`).
  - Solana API requests: 5 seconds (`SOLANA_REQUEST_TIMEOUT`).
- **Search Parameters**:
  - Scans repositories created in the last 5 minutes (`RECENT_MINUTES`).
  - Runs scans every 60 seconds (`SCAN_INTERVAL_SECONDS`).
- **Balance Threshold**: $10, based on fixed prices (BTC $60,000, ETH $2,500, SOL $150).
- **Search Keywords**: Includes `crypto`, `blockchain`, `bitcoin`, `ethereum`, `solana`, `wallet`, `defi`, `nft`, `dex`, `dapp`, `token`, `smartcontract`, `web3`, `pumpfun`, `raydium`, `jupiter`, `orca`, `serum`, `binance`, `polygon`, `avalanche`, `arbitrum`, `optimism`. Split into multiple queries to comply with GitHub API's limit of 5 OR operators.

## Troubleshooting

- **Error: "GITHUB_TOKEN not found"**:
  - Verify the `.env` file exists and contains a valid token.
- **Error: "401 Unauthorized"**:
  - Check if the GitHub token has `repo` scope and is not expired.
- **Error: "422 Unprocessable Entity"**:
  - Indicates an invalid search query, often due to:
    - Incorrect time format in `created:>=`. Ensure the script uses `YYYY-MM-DDTHH:MM`.
    - More than 5 `AND`/`OR`/`NOT` operators. The script splits keywords into subsets of 6 to stay within this limit.
  - Check `scanner.log` for the full error response from GitHub API.
  - Test the query manually via GitHub's API explorer: `https://api.github.com/search/repositories?q=crypto+OR+solana+OR+wallet+OR+pumpfun+OR+defi+OR+nft+created:>=2025-04-19T03:28`.
- **Solana balance check hangs or fails**:
  - Ensure `ALCHEMY_SOLANA_API_KEY` is set in `.env`.
  - Check your Alchemy account for rate limits or use another RPC provider.
- **ModuleNotFoundError**:
  - Run `pip install -r requirements.txt` to install dependencies.
  - Verify Python version (3.8+).
- **Timeout errors**:
  - Increase `REPO_SCAN_TIMEOUT` or `SOLANA_REQUEST_TIMEOUT` in the script if needed.
- **No repositories found**:
  - The 5-minute window may be too narrow. Ensure keywords match relevant repositories.
  - Check GitHub API status or try adjusting `CRYPTO_KEYWORDS` in the script.
- **High API usage**:
  - Multiple queries increase GitHub API usage. Monitor `API requests remaining` in the console.
  - Increase `SCAN_INTERVAL_SECONDS` (e.g., to 120) to reduce API calls if hitting rate limits.
- **General errors**:
  - Check `scanner.log` for detailed error messages.
  - Ensure stable internet connection and valid API keys.

## Security and Ethical Considerations

- **Do NOT use this tool to access or exploit accounts without permission.** Unauthorized use is illegal and unethical.
- **Purpose**: This tool demonstrates the dangers of exposing private keys in public repositories, encouraging developers to adopt secure practices like using `.gitignore`, environment variables, or secret management tools.
- **Responsibility**: If you find exposed keys, report them to the repository owner or GitHub support responsibly. Do not misuse the information.
- **Compliance**: Ensure compliance with GitHub’s terms of service and applicable laws.

## Contributing

This is an educational project. Contributions are welcome to improve functionality, security, or documentation. Please submit pull requests or open issues on the repository.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Disclaimer

This tool is provided for educational and research purposes only. The authors are not responsible for any misuse or damage caused by this tool. Use it responsibly and ethically.