## Aave Wallet Tracker

This project provides a simple and secure way to track multiple Aave wallets on the Polygon network through a local Python application.
It displays important financial information in a GUI and refreshes data automatically at regular intervals.

## 📚 Features

Secure wallet storage:
Wallet addresses are encrypted locally using Fernet encryption with a password you set.
Automated dashboard scraping:
Selenium automates data retrieval from https://defisim.xyz/.
Real-time tracking:
Displays key financial stats including:
Health Factor
Total Borrowed
Available to Borrow
Supplied Asset Value
Net Asset Value (Networth)
User-friendly GUI:
Easy-to-use graphical interface for entering, viewing, and managing wallets.
Automatic refresh:
Data updates at scheduled intervals to keep your dashboard up-to-date.

## 🔧 Technologies Used

- Python — Main programming language.
- Tkinter — For building the graphical interface (comes built-in with Python).
- Selenium — For web automation to scrape live wallet data.
- Cryptography (Fernet, PBKDF2-HMAC) — For encrypting and securing wallet addresses.
- Logging — To capture errors and important events.

## 📦 Requirements

Install the necessary Python libraries:

pip install selenium cryptography

Note:

tkinter, json, os, time, webbrowser, base64, and logging are standard Python libraries and do not require separate installation.
Make sure you have Google Chrome installed, as Selenium will automate Chrome for data scraping.
You will also need the ChromeDriver executable compatible with your Chrome version.

## 🔒 Encryption Details

Wallets are encrypted using Fernet encryption with a key derived from your password using PBKDF2-HMAC (SHA256).
A random salt is generated for every encryption cycle to strengthen security.
Encrypted wallet data is stored in wallets.encrypted, and the associated salt is stored in salt.bin.
Passwords are never stored anywhere — if you lose your password, you lose access to the stored wallets.
Security Tip: Treat your wallets.encrypted and salt.bin files like your crypto keys — store them safely!

## 🚀 How It Works

First-time setup:

- Run the script.
- Enter a new password.
- Add your wallet addresses.
- Wallets are encrypted and saved for future sessions.

Subsequent runs:

- Enter your password to decrypt and load saved wallets.
- The GUI will automatically populate and display real-time stats.

Managing wallets:

- You can add or remove wallets at any time through the interface.

## 🧠 How Selenium is Used

Selenium WebDriver automates browser interactions by:

- Opening the DeFiSim Aave dashboard.
- Inputting each wallet address.
- Scraping financial statistics at set intervals.
- The browser will run quietly in the background while the application keeps your dashboard updated — like your personal DeFi spy who happens to be very punctual.

## 🗂️ File Structure

File	Purpose
- wallets.encrypted	Encrypted file storing your wallet addresses.
- salt.bin	Salt used for password-based encryption key.
- aave_dashboard_gui_encrypted.log	Log file capturing errors and events.
- Main script (.py)	Runs the full application and handles logic.

## 🌟 Pro Tips

First run? You’ll need to enter wallet addresses and create your encryption password.

- Password management: Losing your password means losing your stored wallets. Always store your password safely!
- GUI delay: Selenium scraping may cause a slight delay when refreshing data — patience brings profits.
- Selenium maintenance: Update your ChromeDriver and Selenium versions periodically to avoid compatibility issues.

## 🛡️ License

This project is released under the MIT License.
Feel free to use, modify, and distribute it with proper attribution.

## 💬 Final Thoughts

This tool is designed to keep you informed about your DeFi positions without connecting your wallet or putting your assets at risk.
You own your data, you control your wallets, and your information stays encrypted on your machine.

Move fast, stay safe, and may your Health Factor always be high. 🚀
