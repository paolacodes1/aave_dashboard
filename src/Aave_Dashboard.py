from bs4 import BeautifulSoup
import time
import requests
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

logging.basicConfig(filename='aave_dashboard.log', level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def is_valid_address(address):
    address = address.strip().lower()
    return (len(address) == 42 and address.startswith("0x")) or len(address) > 42  # Basic check

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
            return span_elements[1].text.strip()  # Third instance
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
            return span_elements[2].text.strip()  # Fourth instance
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

def previous_selection():
    WALLETS_FILE = "wallets.json"

    def load_wallets():
        if os.path.exists(WALLETS_FILE):
            try:
                with open(WALLETS_FILE, "r") as file:
                    return json.load(file)
            except json.JSONDecodeError:
                logging.error(f"Error decoding JSON from {WALLETS_FILE}. File may be corrupted.")
                return []
            except FileNotFoundError:
                logging.error(f"Error: {WALLETS_FILE} not found.")
                return []
        return []

    wallets_data = load_wallets()

    if not wallets_data:
        print("\nNo previously saved wallets found.")
        add_new = input("\nWould you like to add a new wallet to track now? (y/n): ").lower()
        if add_new == 'y':
            return add_wallets(wallets_data)
        else:
            return []

    print("\nLoading previous selection:")

    user_data = {}
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }

    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

    try:
        driver = webdriver.Chrome(options=chrome_options)
        driver.set_window_size(1200, 800)

        for wallet_address in wallets_data:
            data = {}  # Initialize data for each wallet
            try:
                driver.get(f"https://defisim.xyz/")  # Navigate to the base URL

                # 1. Find the input field (you'll need the correct selector)
                input_field = WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, "input.mantine-Input-input.mantine-TextInput-input.mantine-ukw606"))  #  Replace with the actual input selector!
                )

                # 2. Enter the wallet address
                input_field.send_keys(wallet_address)

                # 3. Simulate pressing Enter
                input_field.send_keys(Keys.ENTER)

                # 4. Wait for the page to fully load *after* entering the address
                WebDriverWait(driver, 30).until(
                    lambda driver: driver.execute_script('return document.readyState') == 'complete'
                )

                # 5. Extract data using helper functions
                data["health_factor"] = get_wallet_health_factor(wallet_address, driver)
                data["total_borrowed"] = get_total_borrowed(driver)
                data["available_to_borrow"] = get_available_to_borrow(driver)
                data["supply"] = get_supplied_asset_value(driver)
                data["networth"] = get_net_asset_value(driver)

                user_data[wallet_address] = data

            except Exception as e:
                logging.error(f"Error processing wallet {wallet_address}: {e}")
                data["error"] = str(e)  # Store the error message
                user_data[wallet_address] = data  # Store even with error

            time.sleep(1)

        for wallet, data in user_data.items():
            print(f"\n--- Wallet: {wallet} ---\n")
            if "error" in data:
                print(f"Error: {data['error']}")
            else:
                for key, value in data.items():
                    print(f"{key.title()}: {value}")

        driver.quit()

    except Exception as e:
        logging.exception(f"Error processing wallets: {e}")
        print("An error occurred while fetching data.")

    while True:
        menu_or_refresh = input("\nMenu or Refresh? (m/r): ").lower()
        if menu_or_refresh == 'r':
            previous_selection()
            break
        elif menu_or_refresh == 'm':
            break
        else:
            print("Invalid choice. Please enter 'm' for Menu or 'r' for Refresh.")

    return wallets_data

def add_wallets(wallets_data):
    from urllib.parse import quote_plus  # Import quote_plus here

    new_wallets_input = input("\nWhat wallets would you like to add to track? (Comma-separated) ").split(",")
    new_wallets = []
    invalid_wallets = []
    for wallet in new_wallets_input:
        wallet = wallet.strip().lower()
        if is_valid_address(wallet):
            new_wallets.append(wallet)
        else:
            invalid_wallets.append(wallet)

    if invalid_wallets:
        print(f"The following addresses are invalid and were not added: {', '.join(invalid_wallets)}")

    if new_wallets:  # Only save if there are valid new wallets
        wallets_data.extend(new_wallets)
        save_wallets(wallets_data)
        print(f"Wallet(s) '{', '.join(new_wallets)}' added!")
    else:
        print("No valid wallets to add.")

    return wallets_data

def save_wallets(data):
    WALLETS_FILE = "wallets.json"
    try:
        with open(WALLETS_FILE, "w") as file:
            json.dump(data, file, indent=4)
    except IOError as e:
        logging.error(f"Error writing to {WALLETS_FILE}: {e}")

def remove_addresses():
    WALLETS_FILE = "wallets.json"

    def load_wallets():
        if os.path.exists(WALLETS_FILE):
            try:
                with open(WALLETS_FILE, "r") as file:
                    return json.load(file)
            except json.JSONDecodeError:
                logging.error(f"Error decoding JSON from {WALLETS_FILE}. File may be corrupted.")
                return []
            except FileNotFoundError:
                logging.error(f"Error: {WALLETS_FILE} not found.")
                return []
        return []

    wallets_data = load_wallets()

    wallets_to_be_removed_input = input("\nWhat wallet addresses would you like to remove? (Comma-separated) ").split(",")
    wallets_to_be_removed = [wallet.strip().lower() for wallet in wallets_to_be_removed_input]

    valid_wallets_to_remove = []
    invalid_wallets_to_remove = []
    for wallet in wallets_to_be_removed:
        if wallet in wallets_data:
            valid_wallets_to_remove.append(wallet)
        else:
            invalid_wallets_to_remove.append(wallet)

    if invalid_wallets_to_remove:
        print(f"The following addresses are not being tracked: {', '.join(invalid_wallets_to_remove)}")

    if valid_wallets_to_remove:
        updated_wallets_data = [wallet for wallet in wallets_data if wallet not in valid_wallets_to_remove]
        save_wallets(updated_wallets_data)
        print(f"Wallet addresses '{', '.join(valid_wallets_to_remove)}' have been removed.")
    else:
        print("No valid wallet addresses to remove.")

# Menu Loop/ Wallet Addresses to Track

while True:
    print("\nPlease select an option")
    print("1. Load previous selection and display data")
    print("2. Add Addresses")
    print("3. Remove Addresses")
    print("4. Exit")

    choice = input("\nEnter a number: ")

    if choice == "1":
        previous_selection()
    elif choice == "2":
        # Load existing wallets before adding new ones
        WALLETS_FILE = "wallets.json"
        def load_wallets():
            if os.path.exists(WALLETS_FILE):
                try:
                    with open(WALLETS_FILE, "r") as file:
                        return json.load(file)
                except json.JSONDecodeError:
                    logging.error(f"Error decoding JSON from {WALLETS_FILE}. File may be corrupted.")
                    return []
                except FileNotFoundError:
                    logging.error(f"Error: {WALLETS_FILE} not found.")
                    return []
            return []

        wallets_data = load_wallets()
        if wallets_data is None:
            wallets_data = [] # Initialize if no wallets exist yet
        add_wallets(wallets_data)
    elif choice == "3":
        remove_addresses()
    elif choice == "4":
        print("\nGoodbye!")
        break
    else:
        print("\nInvalid choice, try again!")
