# Aave Dashboard - macOS Installation Guide

Simple guide for macOS users to install and run the Aave Dashboard.

---

## 📥 Download

1. Download `AaveDashboard.app.zip` or `AaveDashboard.dmg`
2. Save to your Downloads folder

---

## 🍎 Installation

### Option 1: Using .app.zip (Simplest)

1. **Extract the ZIP file**
   - Double-click `AaveDashboard.app.zip` in Downloads
   - This creates `AaveDashboard.app`

2. **Move to Applications**
   - Drag `AaveDashboard.app` to your Applications folder

3. **First Launch**
   - Right-click `AaveDashboard.app` → Click "Open"
   - Click "Open" again when macOS warns about unknown developer
   - (This only needs to be done once)

4. **Subsequent Launches**
   - Double-click normally, or add to Dock

### Option 2: Using .dmg (Professional)

1. **Mount the DMG**
   - Double-click `AaveDashboard.dmg`
   - A window opens with the app

2. **Install**
   - Drag `AaveDashboard.app` to Applications folder

3. **Eject DMG**
   - Right-click the DMG icon on desktop → Eject

4. **First Launch**
   - Open Applications folder
   - Right-click `AaveDashboard.app` → Click "Open"
   - Click "Open" when warned
   - (Only needed first time)

---

## 🚀 First Use

1. **Launch the app**
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

✅ **Local Storage Only** - All data stays on your Mac
✅ **AES Encryption** - Military-grade encryption for your wallet addresses
✅ **No Tracking** - Zero telemetry or analytics
✅ **No Cloud** - Nothing sent to external servers (except API queries)
✅ **Password Protected** - Your password never leaves your machine
✅ **Open Source** - Full transparency

### File Locations

Your encrypted data is stored in:
```
~/.aave_dashboard/
  ├── wallets.encrypted    (Your wallet addresses)
  ├── salt.bin             (Encryption salt)
  └── crypto_coins_tracked.json
```

**File Permissions:** Automatically set to owner-only (600/700)

### What to Backup

- Your **password** (write it down safely)
- Optional: `~/.aave_dashboard/` folder for wallet data backup

---

## ⚙️ System Requirements

- **macOS:** 10.13 (High Sierra) or later
- **RAM:** 100 MB
- **Disk Space:** 80 MB
- **Internet:** Required for data fetching
- **Python:** Not required! (bundled in app)

---

## 🔧 Troubleshooting

### "App is Damaged" Error

**Solution:**
```bash
xattr -cr /Applications/AaveDashboard.app
```

Then try opening again.

### "Cannot be Opened" Error

**Solution:**
1. Go to System Preferences → Security & Privacy
2. Click "Open Anyway" next to the Aave Dashboard message
3. Try launching again

### Gatekeeper Warnings

**Why it happens:** The app isn't signed with an Apple Developer certificate ($99/year)

**Solution:**
- Right-click → Open (instead of double-click)
- This is safe - the app is open source and security-audited

### App Won't Start

**Check:**
1. macOS version is 10.13+
2. Not running from DMG (move to Applications first)
3. File permissions are correct

**Reset:**
```bash
rm -rf ~/.aave_dashboard
```

### Data Not Loading

**Check:**
1. Internet connection is active
2. Wallet address is valid Ethereum address
3. Wallet has Aave V3 position (on Polygon, Ethereum, etc.)

---

## ❓ FAQs

### Do I need Python installed?

**No!** The app includes everything it needs.

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
1. Delete `~/.aave_dashboard/`
2. Start fresh with a new password
3. Re-add your wallet addresses

The addresses themselves aren't lost - just re-add them.

### How often does data update?

**Automatically every 10 minutes** while the app is running. You can also manually refresh anytime.

---

## 🗑️ Uninstall

To completely remove the app:

```bash
# Remove application
rm -rf /Applications/AaveDashboard.app

# Remove data (optional)
rm -rf ~/.aave_dashboard
```

---

## 🔄 Updating

When a new version is released:

1. Download the new version
2. Replace old app in Applications
3. Your data (`~/.aave_dashboard/`) is preserved
4. Use the same password

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

## ✅ Quick Start Checklist

- [ ] Download AaveDashboard.app
- [ ] Move to Applications folder
- [ ] Right-click → Open (first time)
- [ ] Create secure password
- [ ] Add Aave wallet address
- [ ] View your DeFi positions!

---

**Security Rating:** ⭐ A+ ⭐
**Version:** 2.0
**Last Updated:** October 2025

**Your data is yours. Stay secure, stay informed.** 🚀
