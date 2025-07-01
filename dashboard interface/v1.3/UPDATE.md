Aave Wallet Tracker

This project provides a simple and secure way to track multiple Aave wallets on the Polygon network through a local Python application. It displays important financial information in a graphical user interface (GUI) and refreshes data automatically at regular intervals. The interface was created using AI, with my prompts and source code as reference.

🌟 Features
Secure Wallet Storage: Wallet addresses are encrypted locally using Fernet encryption with a password you set.

Automated Dashboard Scraping: Selenium automates data retrieval from DeFiSim, providing real-time Aave position data.

Real-time Aave Tracking: Displays key financial statistics for each wallet, including:

Health Factor (color-coded for risk assessment)

Total Borrowed

Available to Borrow

Supplied Asset Value

Net Asset Value (Networth)

Liquidation Scenario data (potential liquidation assets and prices).

Integrated Cryptocurrency Price Tracker:

Track custom crypto coins by name/slug.

View Top 10 coins from CoinMarketCap.

View Top 50 and Top 100 coins from CoinRanking.

Automatic price updates for tracked coins.

User-friendly GUI: An easy-to-use graphical interface for entering, viewing, and managing wallets and tracked cryptocurrencies.

Automatic Refresh: Data updates at scheduled intervals to keep your dashboard up-to-date.

🔧 Technologies Used
Python: Main programming language.

Tkinter: For building the graphical interface (built-in with Python).

Selenium: For web automation to scrape live wallet data.

Cryptography (Fernet, PBKDF2-HMAC): For encrypting and securing wallet addresses.

Requests & BeautifulSoup: For fetching cryptocurrency prices.

Pillow (PIL): For image handling (e.g., the logo).

Logging: To capture errors and important events.

📦 Requirements
Python 3.x

Installed Python Libraries:

Bash

pip install selenium cryptography requests beautifulsoup4 pillow
Google Chrome Browser: Selenium automates Chrome for data scraping.

ChromeDriver Executable: Download the ChromeDriver version compatible with your Chrome browser version and place it in your system's PATH or in the same directory as your script.

🔒 Encryption Details
Wallets are encrypted using Fernet encryption with a key derived from your password using PBKDF2-HMAC (SHA256). A random salt is generated for every encryption cycle to strengthen security. Encrypted wallet data is stored in wallets.encrypted, and the associated salt in salt.bin. Passwords are never stored anywhere — if you lose your password, you lose access to the stored wallets.

Security Tip: Treat your wallets.encrypted and salt.bin files like your crypto keys — store them safely!

🚀 How It Works
First-time setup:

Run the script.

Enter a new password.

Add your wallet addresses.

Wallets are encrypted and saved for future sessions.

Subsequent runs:

Enter your password to decrypt and load saved wallets.

The GUI will automatically populate and display real-time stats.

Managing wallets:

You can add, remove, or rename wallets at any time through the interface.

🧠 How Selenium is Used
Selenium WebDriver automates browser interactions by:

Opening the DeFiSim Aave dashboard.

Inputting each wallet address.

Scraping financial statistics at set intervals.

The browser will run quietly in the background while the application keeps your dashboard updated — like your personal DeFi spy who happens to be very punctual.

🗂️ File Structure
wallets.encrypted: Encrypted file storing your wallet addresses.

salt.bin: Salt used for password-based encryption key.

aave_dashboard_gui_encrypted.log (or defi_dashboard.log): Log file capturing errors and events.

Main script (.py): Runs the full application and handles logic.

logo_raw_b64.txt: Base64 encoded logo data for the GUI.

🌟 Pro Tips
Password Management: Losing your password means losing your stored wallets. Always store your password safely!

GUI Delay: Selenium scraping may cause a slight delay when refreshing data — patience brings profits.

Selenium Maintenance: Update your ChromeDriver and Selenium versions periodically to avoid compatibility issues.

🛡️ License
This project is released under the MIT License.
Feel free to use, modify, and distribute it with proper attribution.

💬 Final Thoughts
This tool is designed to keep you informed about your DeFi positions without connecting your wallet or putting your assets at risk. You own your data, you control your wallets, and your information stays encrypted on your machine.

Move fast, stay safe, and may your Health Factor always be high. 🚀