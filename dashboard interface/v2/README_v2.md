# Aave Wallet Tracker v2.0 - API Edition

This is the API-powered version of the Aave Wallet Tracker, providing the same secure wallet tracking functionality without the need for browser automation or Selenium dependencies.

## 🚀 What's New in v2.0

- **API-Based Data Fetching**: Replaces Selenium web scraping with direct API calls
- **Faster Performance**: No browser automation means instant data retrieval
- **Lower Resource Usage**: Eliminates Chrome browser overhead
- **More Reliable**: No dependency on CSS selectors or website structure
- **Dual API Support**: Primary expand.network API with The Graph subgraph fallback
- **Same Trusted UI**: Maintains the familiar v1.3 interface with logo

## 📚 Features

- **Secure wallet storage**: Wallet addresses are encrypted locally using Fernet encryption
- **API-powered data**: Fetches live Aave protocol data via REST APIs and GraphQL
- **Real-time tracking**: Displays key financial stats including:
  - Health Factor
  - Total Borrowed
  - Available to Borrow
  - Supplied Asset Value
  - Net Asset Value (Networth)
- **User-friendly GUI**: Same polished interface from v1.3 with integrated logo
- **Automatic refresh**: Data updates at scheduled intervals
- **Cryptocurrency tracker**: Built-in price tracking for additional coins

## 🔧 Technologies Used

- **Python** — Main programming language
- **Tkinter** — For building the graphical interface (built-in with Python)
- **Requests** — For API calls to data sources
- **Cryptography (Fernet, PBKDF2-HMAC)** — For encrypting and securing wallet addresses
- **PIL (Pillow)** — For logo image processing
- **BeautifulSoup4** — For cryptocurrency price parsing

## 📦 Requirements

Install the necessary Python libraries:

```bash
pip install -r requirements.txt
```

Required libraries:
- `requests>=2.28.0`
- `cryptography>=3.4.8`
- `Pillow>=8.3.2`
- `beautifulsoup4>=4.10.0`

Note: `tkinter`, `json`, `os`, `time`, `base64`, and `logging` are standard Python libraries.

## 🌐 Data Sources

### Primary: Expand.network API
- **Endpoint**: `https://api.expand.network/lendborrow/getuserpositions`
- **Network**: Aave V3 on Polygon (Protocol ID: 1201)
- **Advantages**: Direct API access, comprehensive position data

### Fallback: The Graph Subgraphs  
- **Endpoint**: Aave Protocol V3 Polygon subgraph
- **Network**: GraphQL queries to protocol subgraph
- **Use case**: When primary API is unavailable or rate-limited

## 🔒 Security & Encryption

- **Same encryption as v1.x**: Fernet encryption with PBKDF2-HMAC (SHA256)
- **Backward compatible**: Existing `wallets.encrypted` and `salt.bin` files work unchanged
- **Local storage only**: No data sent to external services except for protocol queries
- **Password protection**: Passwords are never stored; lose password = lose access

## 🚀 How to Run

1. **First-time setup**:
   ```bash
   cd "dashboard interface/v2"
   python3 Combined_Dashboard_v2.py
   ```

2. **Subsequent runs**:
   - Enter your existing password to decrypt saved wallets
   - The GUI will automatically populate with your wallet data via API calls

3. **Required files**:
   - `Combined_Dashboard_v2.py` - Main application
   - `aave_api.py` - API client module
   - `logo_raw_b64.txt` - Application logo (base64 encoded)
   - `requirements.txt` - Python dependencies

## 🆚 Differences from v1.3

| Feature | v1.3 (Selenium) | v2.0 (API) |
|---------|-----------------|------------|
| **Data Source** | Web scraping defisim.xyz | Direct API calls |
| **Speed** | Slow (browser automation) | Fast (instant API response) |
| **Dependencies** | Chrome, ChromeDriver, Selenium | None (just Python libraries) |
| **Resource Usage** | High (browser overhead) | Low (HTTP requests only) |
| **Reliability** | Breaks if website changes | Stable API contracts |
| **Liquidation Data** | Available from scraping | Not available via API |
| **Setup Complexity** | Requires browser setup | Simple Python install |

## 📁 File Structure

```
dashboard interface/v2/
├── Combined_Dashboard_v2.py     # Main application
├── aave_api.py                  # API client module  
├── logo_raw_b64.txt            # Application logo
├── requirements.txt             # Python dependencies
├── README_v2.md                # This documentation
├── wallets.encrypted           # Your encrypted wallets (created on first use)
├── salt.bin                    # Encryption salt (created on first use)
├── crypto_coins_tracked.json   # Tracked cryptocurrency list
└── defi_dashboard_v2.log       # Application logs
```

## 🔄 Migration from v1.x

Your existing encrypted wallet files are **fully compatible**:

1. Copy your `wallets.encrypted` and `salt.bin` files to the v2 directory
2. Run the v2 application with the same password
3. Your wallets will load automatically with API-powered data

## 🌟 Pro Tips

- **API Reliability**: The app uses multiple data sources with automatic fallback
- **Rate Limits**: Built-in delays prevent API rate limiting issues
- **Performance**: Much faster than browser-based versions
- **Compatibility**: Works with the same encrypted wallet files as v1.x
- **Updates**: API-based approach is more stable for long-term use

## ⚠️ Known Limitations

- **Liquidation Scenarios**: Not available via current APIs (feature removed)
- **API Dependencies**: Requires internet connection for data fetching
- **Network Support**: Currently optimized for Polygon Aave V3 only

## 🛡️ License

This project is released under the MIT License.
Feel free to use, modify, and distribute it with proper attribution.

## 💬 Final Thoughts

v2.0 represents a major architectural improvement, trading web scraping complexity for clean API integration. You get the same trusted interface with better performance, reliability, and maintainability.

Your encrypted data remains secure and local, with faster access to your DeFi positions.

**Move fast, stay secure, and may your Health Factor always be high! 🚀**