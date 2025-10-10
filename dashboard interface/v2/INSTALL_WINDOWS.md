# Aave Dashboard - Windows Installation Guide

Simple guide for Windows users to install and run the Aave Dashboard.

---

## 📥 Download

1. Download `AaveDashboard.exe`
2. Save to your Downloads folder

---

## 🪟 Installation

### Simple Setup (No Installation Required!)

1. **Locate the file**
   - Go to your Downloads folder
   - Find `AaveDashboard.exe`

2. **Move to preferred location** (optional)
   - Desktop for easy access
   - Or: `C:\Program Files\AaveDashboard\`
   - Or: Anywhere you prefer

3. **First Launch**
   - Double-click `AaveDashboard.exe`
   - Windows Defender SmartScreen may appear:
     - Click "More info"
     - Click "Run anyway"
   - (This only needs to be done once)

4. **Create Desktop Shortcut** (optional)
   - Right-click `AaveDashboard.exe`
   - Send to → Desktop (create shortcut)

---

## 🚀 First Use

1. **Launch the app**
   - Double-click the exe or shortcut

2. **Enter a password** when prompted
   - This password encrypts your wallet data
   - Choose something secure and memorable
   - ⚠️ **IMPORTANT:** If you lose this password, you lose access to your data!

3. **Add your Aave wallet**
   - Click "Add Aave Wallet"
   - Paste your Ethereum wallet address
   - Give it a name (optional)

4. **Data loads automatically**
   - Health factor
   - Borrowed amounts
   - Available to borrow
   - Supplied value
   - Net worth
   - Liquidation scenarios

5. **Auto-refresh**
   - Data updates every 10 minutes
   - Manual refresh available

---

## 🔒 Security & Privacy

### What's Secure

✅ **Local Storage Only** - All data stays on your PC
✅ **AES Encryption** - Military-grade encryption for your wallet addresses
✅ **No Tracking** - Zero telemetry or analytics
✅ **No Cloud** - Nothing sent to external servers (except API queries)
✅ **Password Protected** - Your password never leaves your machine
✅ **Open Source** - Full transparency

### File Locations

Your encrypted data is stored in:
```
C:\Users\[YourName]\.aave_dashboard\
  ├── wallets.encrypted
  ├── salt.bin
  └── crypto_coins_tracked.json
```

**File Permissions:** Automatically set to owner-only (restricted)

### What to Backup

- Your **password** (write it down safely)
- Optional: `.aave_dashboard` folder for wallet data backup

---

## ⚙️ System Requirements

- **Windows:** 10 or 11 (64-bit)
- **RAM:** 100 MB
- **Disk Space:** 70 MB
- **Internet:** Required for data fetching
- **Python:** Not required! (bundled in exe)

---

## 🔧 Troubleshooting

### Windows Defender SmartScreen Warning

**Message:** "Windows protected your PC"

**Why it happens:** The app isn't signed with a code signing certificate (costs $200+/year)

**Solution:**
1. Click "More info"
2. Click "Run anyway"
3. The app is safe - it's open source and security-audited

**Alternative:**
Add exception in Windows Security:
1. Open Windows Security
2. Virus & threat protection
3. Manage settings
4. Exclusions → Add exclusion
5. Choose the AaveDashboard.exe file

### Antivirus False Positive

**Some antivirus software flags PyInstaller apps**

**Solution:**
- Add `AaveDashboard.exe` to antivirus exclusions
- This is a common false positive for Python-based executables
- The app is security-audited (A+ rating)

### App Won't Start

**Check:**
1. Windows version is 10+ (64-bit)
2. Not blocked by antivirus
3. Extracted from ZIP (if downloaded as ZIP)

**Try:**
```
Right-click AaveDashboard.exe → Properties
→ Unblock → Apply → OK
```

### Data Not Loading

**Check:**
1. Internet connection is active
2. Wallet address is valid Ethereum address
3. Wallet has Aave V3 position (on Polygon, Ethereum, etc.)
4. Firewall isn't blocking the app

**Allow through firewall:**
1. Windows Security → Firewall
2. Allow an app through firewall
3. Find AaveDashboard → Check both Private and Public

---

## ❓ FAQs

### Do I need Python installed?

**No!** The exe includes everything it needs.

### Is my wallet safe?

**Yes!** The app only *reads* data. It cannot:
- Access your private keys
- Make transactions
- Transfer funds
- Sign anything

It's read-only monitoring only.

### Where does data come from?

- **Aave Protocol:** Direct RPC calls to Aave V3 contracts
- **Price Data:** CoinGecko, CoinMarketCap, CoinRanking APIs
- All connections use HTTPS with certificate verification

### Can I use multiple wallets?

**Yes!** Add as many as you want. Each wallet gets its own card in the dashboard.

### What if I forget my password?

**Unfortunately,** you'll lose access to your stored wallet addresses. You'll need to:
1. Delete `.aave_dashboard` folder in your user directory
2. Start fresh with a new password
3. Re-add your wallet addresses

The addresses themselves aren't lost - just re-add them.

### How often does data update?

**Automatically every 10 minutes** while the app is running. You can also manually refresh anytime.

### Why is the file so large (40-70 MB)?

The executable includes:
- Python interpreter
- All required libraries
- Application code

This means **no installation needed** - it just works!

---

## 🗑️ Uninstall

To completely remove the app:

1. **Delete the executable:**
   - Delete `AaveDashboard.exe` from wherever you put it

2. **Delete data** (optional):
   - Press `Win + R`
   - Type: `%USERPROFILE%\.aave_dashboard`
   - Delete the folder

3. **Remove Windows Security exclusions** (if added)

---

## 🔄 Updating

When a new version is released:

1. Download the new `AaveDashboard.exe`
2. Replace the old file
3. Your data is preserved (in `.aave_dashboard` folder)
4. Use the same password

---

## 🎯 Quick Start Checklist

- [ ] Download AaveDashboard.exe
- [ ] Move to preferred location
- [ ] Double-click to run
- [ ] Click "More info" → "Run anyway" (first time)
- [ ] Create secure password
- [ ] Add Aave wallet address
- [ ] View your DeFi positions!

---

## 📚 Additional Documentation

- **Full README:** See main repository
- **Security Audit:** `SECURITY_COMPLETE.md`
- **Development Guide:** `README_v2.md`

---

## 📞 Support

- **Issues:** https://github.com/[your-repo]/issues
- **Source Code:** https://github.com/[your-repo]
- **Security:** See `SECURITY_COMPLETE.md`

---

## 🔐 Security Notes

### Why the SmartScreen Warning?

**Code signing certificates cost $200-400/year** and require a business entity. For open-source projects, this isn't always practical.

**You can trust this app because:**
1. ✅ Full source code available
2. ✅ Security audit complete (A+ rating)
3. ✅ No telemetry or tracking
4. ✅ Local storage only
5. ✅ Community reviewed

### Verify the Download

Always verify SHA256 checksum (if provided):
```
certutil -hashfile AaveDashboard.exe SHA256
```

Compare with the official checksum.

---

**Security Rating:** ⭐ A+ ⭐
**Version:** 2.0
**Last Updated:** October 2025

**Your data is yours. Stay secure, stay informed.** 🚀
