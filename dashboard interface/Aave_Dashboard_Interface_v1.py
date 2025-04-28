import tkinter as tk
from tkinter import simpledialog, messagebox
import json
import os
import logging
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import TimeoutException, NoSuchElementException, ElementNotInteractableException
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import webbrowser
import time

logging.basicConfig(filename='aave_dashboard_gui_encrypted.log', level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')

WALLETS_FILE = "wallets.encrypted"
SALT_FILE = "salt.bin"

def generate_salt():
    return os.urandom(16)

def get_key_from_password(password, salt):
    password_encoded = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password_encoded))

def load_wallets(password):
    if not password:
        return []
    if os.path.exists(WALLETS_FILE) and os.path.exists(SALT_FILE):
        try:
            with open(SALT_FILE, "rb") as salt_file:
                salt = salt_file.read()
            key = get_key_from_password(password, salt)
            f = Fernet(key)
            with open(WALLETS_FILE, "rb") as encrypted_file:
                encrypted_data = encrypted_file.read()
            decrypted_data = f.decrypt(encrypted_data).decode()
            return json.loads(decrypted_data)
        except Exception as e:
            logging.error(f"Error loading and decrypting wallets: {e}")
            messagebox.showerror("Decryption Error", "Incorrect password or corrupted file.")
            return None
    return []

def save_wallets(data, password):
    if not password:
        return False
    try:
        salt = generate_salt()
        key = get_key_from_password(password, salt)
        f = Fernet(key)
        json_data = json.dumps(data)
        encrypted_data = f.encrypt(json_data.encode())
        with open(WALLETS_FILE, "wb") as encrypted_file:
            encrypted_file.write(encrypted_data)
        with open(SALT_FILE, "wb") as salt_file:
            salt_file.write(salt)
        return True
    except Exception as e:
        logging.error(f"Error saving and encrypting wallets: {e}")
        messagebox.showerror("Encryption Error", "Failed to save wallets securely.")
        return False

def is_valid_address(address):
    address = address.strip().lower()
    return (len(address) == 42 and address.startswith("0x")) or len(address) > 42

def get_wallet_health_factor(wallet_address, driver):
    """
    Gets the Health Factor for a given wallet address.

    Args:
        wallet_address: The wallet address to look up.
        driver: The Selenium WebDriver instance.

    Returns:
        The Health Factor as a string, or None if not found.
    """
    try:
        # 4. Wait for the Health Factor to load (adjust selector and wait time)
        mark_element = WebDriverWait(driver, 20).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "h3.mantine-Text-root.mantine-Title-root.mantine-1cydoyt mark.mantine-Mark-root.mantine-qhlhbb"))
        )

        # 5. Extract the Health Factor
        span_element = mark_element.find_element(By.CSS_SELECTOR, "span.mantine-Text-root.mantine-1r5e5bx")
        if span_element:
            return span_element.text.strip()
        else:
            logging.warning(f"Health Factor not found for {wallet_address}")
            return "N/A"

    except TimeoutException:
        logging.error(f"Timeout waiting for Health Factor for {wallet_address}")
        return "N/A"
    except NoSuchElementException:
        logging.error(f"Health Factor element not found for {wallet_address}")
        return "N/A"
    except Exception as e:
        logging.exception(f"Error getting Health Factor for {wallet_address}: {e}")
        return None

def get_total_borrowed(driver):
    """
    Gets the Total Borrowed value using a simpler selector.

    Args:
        driver: The Selenium WebDriver instance.

    Returns:
        The Total Borrowed value as a string, or None if not found.
    """
    try:
        total_borrowed_element = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "span.mantine-Text-root.mantine-agvbd3"))
        )
        if total_borrowed_element:
            return total_borrowed_element.text.strip()
        else:
            logging.warning("Total Borrowed not found (simple selector).")
            return "N/A"
    except TimeoutException:
        logging.error("Timeout waiting for Total Borrowed element (simple selector).")
        return "N/A"
    except NoSuchElementException:
        logging.error("Total Borrowed element not found (simple selector).")
        return "N/A"
    except Exception as e:
        logging.exception(f"Error getting Total Borrowed (simple selector): {e}")
        return None

def get_available_to_borrow(driver):
    """
    Gets the Available to Borrow value using a simple selector.

    Args:
        driver: The Selenium WebDriver instance.

    Returns:
        The Available to Borrow value as a string, or None if not found.
    """
    try:
        available_to_borrow_element = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "span.mantine-Text-root.mantine-1r8as59"))
        )
        if available_to_borrow_element:
            return available_to_borrow_element.text.strip()
        else:
            logging.warning("Available to Borrow not found (simple selector).")
            return "N/A"
    except TimeoutException:
        logging.error("Timeout waiting for Available to Borrow element (simple selector).")
        return "N/A"
    except NoSuchElementException:
        logging.error("Available to Borrow element not found (simple selector).")
        return "N/A"
    except Exception as e:
        logging.exception(f"Error getting Available to Borrow (simple selector): {e}")
        return None

def get_supplied_asset_value(driver):
    """
    Gets the Supplied Asset Value (Supply) by index.
    """
    try:
        span_elements = WebDriverWait(driver, 10).until(
            EC.presence_of_all_elements_located((By.CSS_SELECTOR, "span.mantine-Text-root.mantine-1r8as59"))
        )
        if len(span_elements) > 1:
            return span_elements[1].text.strip()  # Second instance
        else:
            logging.warning("Supplied Asset Value not found (by index).")
            return "N/A"
    except TimeoutException:
        logging.error("Timeout waiting for Supplied Asset Value element (by index).")
        return "N/A"
    except IndexError:
        logging.error("Supplied Asset Value element index out of range.")
        return "N/A"
    except Exception as e:
        logging.exception(f"Error getting Supplied Asset Value (by index): {e}")
        return None

def get_net_asset_value(driver):
    """
    Gets the Net Asset Value (Networth) by index.
    """
    try:
        span_elements = WebDriverWait(driver, 10).until(
            EC.presence_of_all_elements_located((By.CSS_SELECTOR, "span.mantine-Text-root.mantine-1r8as59"))
        )
        if len(span_elements) > 2:
            return span_elements[2].text.strip()  # Third instance
        else:
            logging.warning("Net Asset Value not found (by index).")
            return "N/A"
    except TimeoutException:
        logging.error("Timeout waiting for Net Asset Value element (by index).")
        return "N/A"
    except IndexError:
        logging.error("Net Asset Value element index out of range.")
        return "N/A"
    except Exception as e:
        logging.exception(f"Error getting Net Asset Value (by index): {e}")
        return None

def fetch_wallet_data(wallet_address, driver):
    """Fetches data for a single wallet address."""
    data = {}
    try:
        driver.get(f"https://defisim.xyz/")
        input_field = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "input.mantine-Input-input.mantine-TextInput-input.mantine-ukw606"))
        )
        input_field.send_keys(wallet_address)
        input_field.send_keys(Keys.ENTER)
        WebDriverWait(driver, 30).until(
            lambda driver: driver.execute_script('return document.readyState') == 'complete'
        )
        data["health_factor"] = get_wallet_health_factor(wallet_address, driver)
        data["total_borrowed"] = get_total_borrowed(driver)
        data["available_to_borrow"] = get_available_to_borrow(driver)
        data["supply"] = get_supplied_asset_value(driver)
        data["networth"] = get_net_asset_value(driver)
    except Exception as e:
        logging.error(f"Error processing wallet {wallet_address}: {e}")
        data["error"] = str(e)
    return data

def get_wallet_addresses_input():
    """Opens a dialog to get wallet addresses from the user."""
    addresses_str = simpledialog.askstring("Wallet Input", "Enter wallet addresses (comma-separated):")
    if addresses_str:
        return [addr.strip().lower() for addr in addresses_str.split(',')]
    return []

class WalletDashboardGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Aave Wallet Dashboard")
        self.wallet_frames = {}
        self.password = self._get_password()
        self.wallets_data = load_wallets(self.password)
        if self.wallets_data is None:
            self.destroy()
            return
        self.driver = self._initialize_webdriver()
        self._create_widgets()
        self._update_dashboard()
        self._schedule_refresh()
        self.protocol("WM_DELETE_WINDOW", self._close_app)

    def _get_password(self):
        """Prompts the user for a password."""
        password = simpledialog.askstring("Password", "Enter password to access wallet data:", show='*')
        return password

    def _initialize_webdriver(self):
        """Initializes the Selenium WebDriver."""
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        try:
            driver = webdriver.Chrome(options=chrome_options)
            driver.set_window_size(1200, 800)
            return driver
        except Exception as e:
            logging.error(f"Error initializing webdriver: {e}")
            return None

    def _create_widgets(self):
        """Creates the GUI widgets."""
        self.add_button = tk.Button(self, text="Add Wallets", command=self._add_new_wallets)
        self.add_button.pack(pady=5)

        self.refresh_button = tk.Button(self, text="Refresh Data", command=self._refresh_data)
        self.refresh_button.pack(pady=5)

        self.remove_button = tk.Button(self, text="Remove Wallets", command=self._open_remove_dialog)
        self.remove_button.pack(pady=5)

        self.dashboard_frame = tk.Frame(self)
        self.dashboard_frame.pack(padx=10, pady=10)

    def _add_new_wallets(self):
        """Adds new wallet addresses."""
        new_wallets = get_wallet_addresses_input()
        valid_new_wallets = [wallet for wallet in new_wallets if is_valid_address(wallet) and wallet not in self.wallets_data]
        invalid_wallets = [wallet for wallet in new_wallets if not is_valid_address(wallet)]

        if invalid_wallets:
            messagebox.showerror("Invalid Input", f"Invalid wallets entered: {', '.join(invalid_wallets)}")

        if valid_new_wallets:
            self.wallets_data.extend(valid_new_wallets)
            if not save_wallets(self.wallets_data, self.password):
                messagebox.showerror("Save Error", "Failed to save wallet data.")
            self._update_dashboard()

    def _refresh_data(self):
        """Refreshes the displayed data."""
        self._update_dashboard()
        self._schedule_refresh()

    def _schedule_refresh(self):
        """Schedules the next data refresh."""
        self.after(10 * 60 * 1000, self._refresh_data)

    def _open_remove_dialog(self):
        """Opens a dialog to remove wallets."""
        if not self.wallets_data:
            messagebox.showinfo("Info", "No wallets are currently being tracked.")
            return

        remove_dialog = tk.Toplevel(self)
        remove_dialog.title("Remove Wallets")
        self.remove_vars = {}

        for i, wallet in enumerate(self.wallets_data):
            var = tk.BooleanVar()
            cb = tk.Checkbutton(remove_dialog, text=f"{wallet[:8]}...{wallet[-8:]}", variable=var)
            cb.grid(row=i, column=0, sticky="w", padx=5, pady=2)
            self.remove_vars[wallet] = var

        remove_button = tk.Button(remove_dialog, text="Remove Selected", command=self._remove_selected_wallets)
        remove_button.grid(row=len(self.wallets_data), column=0, pady=10)

    def _remove_selected_wallets(self):
        """Removes the selected wallet addresses."""
        wallets_to_remove = [wallet for wallet, var in self.remove_vars.items() if var.get()]

        if wallets_to_remove:
            self.wallets_data = [wallet for wallet in self.wallets_data if wallet not in wallets_to_remove]
            if not save_wallets(self.wallets_data, self.password):
                messagebox.showerror("Save Error", "Failed to save wallet data.")
            self._update_dashboard()
            messagebox.showinfo("Wallets Removed", f"Removed wallets: {', '.join([w[:8] + '...' + w[-8:] for w in wallets_to_remove])}")

        if self.winfo_exists():
            for window in self.winfo_children():
                if window.winfo_ismapped() and window.title() == "Remove Wallets":
                    window.destroy()

    def _update_dashboard(self):
        """Updates the dashboard with the latest data."""
        for frame in self.wallet_frames.values():
            frame.destroy()
        self.wallet_frames = {}

        if self.driver and self.wallets_data:
            for wallet in self.wallets_data:
                data = fetch_wallet_data(wallet, self.driver)
                if data:
                    self._create_wallet_frame(wallet, data)
                else:
                    logging.warning(f"No data received for wallet: {wallet}")
        elif not self.wallets_data:
            messagebox.showinfo("Info", "No wallets loaded.")
        elif not self.driver:
            print("Webdriver not initialized. Cannot update dashboard.")

    def _create_wallet_frame(self, wallet_address, data):
        """Creates a frame to display wallet data."""

        def open_url(event):
            webbrowser.open_new_tab(f"https://defisim.xyz/?address={wallet_address}")

        frame = tk.Frame(self.dashboard_frame, borderwidth=2, relief="groove", padx=10, pady=10)
        frame.pack(side="left", padx=5, pady=5, anchor="n")
        self.wallet_frames[wallet_address] = frame

        tk.Label(frame, text=f"Wallet: {wallet_address[:8]}...{wallet_address[-8:]}", font=("Arial", 10, "bold")).pack()
        for key, value in data.items():
            tk.Label(frame, text=f"{key.title().replace('_', ' ')}: {value}").pack()

        url_label = tk.Label(frame, text="View on DefiSim", fg="blue", cursor="hand2")
        url_label.pack()
        url_label.bind("<Button-1>", open_url)

    def _close_app(self):
        """Closes the application and the WebDriver."""
        if self.driver:
            self.driver.quit()
        self.destroy()

if __name__ == "__main__":
    gui = WalletDashboardGUI()
    gui.mainloop()
