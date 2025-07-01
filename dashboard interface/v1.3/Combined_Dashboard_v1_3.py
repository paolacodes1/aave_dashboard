import tkinter as tk
from tkinter import simpledialog, messagebox, font as tkFont, ttk
import json
import os
import logging
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import TimeoutException, NoSuchElementException, ElementNotInteractableException, StaleElementReferenceException
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import webbrowser
import time
from PIL import Image, ImageTk
import sys
import io
import threading
import queue
import requests # For Crypto Price Tracker
from bs4 import BeautifulSoup # For Crypto Price Tracker

# --- Logging Setup ---
logging.basicConfig(filename='defi_dashboard.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(name)s - %(funcName)s - %(lineno)d - %(message)s',
                    filemode='w')

# --- Global Constants ---
WALLETS_FILE, SALT_FILE = "wallets.encrypted", "salt.bin"
CRYPTO_COINS_TRACKED_FILE = "crypto_coins_tracked.json"
BG_COLOR, FG_COLOR = "black", "white"
BUTTON_BG_COLOR, BUTTON_FG_COLOR, BUTTON_ACTIVE_BG_COLOR = "#DDDDDD", "black", "#C0C0C0"
LINK_COLOR, BORDER_COLOR, CHECKBOX_SELECT_COLOR = "#66B2FF", "#444444", "#555555"
TEXT_AREA_BG_COLOR = "#1A1A1A"
HEADING_FONT_TUPLE = ("Arial", 16, "bold"); REGULAR_FONT_TUPLE = ("Arial", 14); SMALL_REGULAR_FONT_TUPLE = ("Arial", 12)
LINK_FONT_TUPLE = ("Arial", 9, "underline"); DROPDOWN_FONT_TUPLE = ("Arial", 10); CRYPTO_DISPLAY_FONT_TUPLE = ("Monaco", 11)
HF_HIGH_RISK_COLOR="red"; HF_MED_RISK_COLOR1="#FF4500"; HF_MED_RISK_COLOR2="orange"
HF_SAFE_COLOR="#32CD32"; HF_VERY_SAFE_COLOR="#4D94FF"
CRYPTO_HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}

# --- Helper Functions ---
def resource_path(relative_path):
    try: base_path = sys._MEIPASS
    except AttributeError: base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)
def generate_salt(): return os.urandom(16)
def get_key_from_password(password, salt):
    pw_bytes = password.encode()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    return base64.urlsafe_b64encode(kdf.derive(pw_bytes))

# --- Aave Wallet File Handling ---
def load_wallets(password):
    if not password: logging.warning("Load Aave: No password."); return []
    loaded_data, needs_resave = [], False
    if os.path.exists(WALLETS_FILE) and os.path.exists(SALT_FILE):
        try:
            with open(SALT_FILE,"rb") as sf: salt=sf.read()
            key=get_key_from_password(password,salt); f=Fernet(key)
            with open(WALLETS_FILE,"rb") as ef: enc_data=ef.read()
            if not enc_data: logging.warning(f"Load Aave: '{WALLETS_FILE}' empty."); return []
            parsed_data=json.loads(f.decrypt(enc_data).decode())
            if isinstance(parsed_data, list):
                if not parsed_data: loaded_data = []
                elif isinstance(parsed_data[0], str):
                    logging.info("Load Aave: Converting old format."); loaded_data=[{"address":addr,"name":""} for addr in parsed_data]; needs_resave=True
                elif isinstance(parsed_data[0],dict) and 'address' in parsed_data[0]:
                    if all(isinstance(i,dict) and 'address' in i for i in parsed_data): loaded_data=parsed_data; logging.info(f"Loaded {len(loaded_data)} Aave wallets.")
                    else: logging.error("Load Aave: New format error."); messagebox.showerror("Data Error","Aave format error."); return None
                else: logging.error("Load Aave: Unknown list format."); messagebox.showerror("Data Error","Aave format error."); return None
            else: logging.error("Load Aave: Data not list."); messagebox.showerror("Data Error","Aave format error."); return None
        except Exception as e: logging.error(f"Error load/decrypt Aave: {e}",exc_info=True); messagebox.showerror("Decryption Error","Incorrect password or corrupted Aave file."); return None
    else: logging.info("Load Aave: File(s) not found."); return []
    if needs_resave and loaded_data is not None:
        if not save_wallets(loaded_data, password): logging.warning("Failed immediate resave after conversion.")
        else: logging.info("Successfully saved in new format.")
    return loaded_data if loaded_data is not None else []
def save_wallets(data, password):
    if not password: logging.warning("Save Aave: No password."); return False
    if not isinstance(data,list): logging.error("Save Aave: Data not list."); return False
    if data and not all(isinstance(i,dict) and 'address' in i for i in data): logging.error("Save Aave: Bad data items."); return False
    try:
        salt=generate_salt(); key=get_key_from_password(password,salt); f=Fernet(key)
        data_to_save=[{"address":i['address'],"name":str(i.get('name',''))} for i in data]
        enc_data=f.encrypt(json.dumps(data_to_save).encode())
        with open(WALLETS_FILE,"wb") as ef: ef.write(enc_data)
        with open(SALT_FILE,"wb") as sf: sf.write(salt)
        logging.info(f"Saved {len(data_to_save)} Aave wallets."); return True
    except Exception as e: logging.error(f"Error save/encrypt Aave: {e}",exc_info=True); messagebox.showerror("Encryption Error","Failed save Aave."); return False

# --- Input Validation ---
def is_valid_address(address):
    addr=address.strip().lower(); return (len(addr)==42 and addr.startswith("0x")) or (len(addr)>4 and '.' in addr and ' ' not in addr)

# --- Selenium Scraping Functions ---
def get_wallet_health_factor(wallet_address, driver):
    hf_value = "N/A"
    h3_hf_container_selector = "h3.mantine-Text-root.mantine-Title-root.mantine-1cydoyt"
    selector_normal_hf_value = f"{h3_hf_container_selector} mark.mantine-Mark-root.mantine-qhlhbb span.mantine-Text-root.mantine-1r5e5bx"
    selector_high_hf_mark_class = "mantine-1ykdmdk"
    selector_high_hf_value = f"{h3_hf_container_selector} mark.mantine-Mark-root.{selector_high_hf_mark_class} span.mantine-Text-root.mantine-1r5e5bx > span"
    selector_high_hf_mark_tag = f"mark.{selector_high_hf_mark_class}"
    try:
        logging.debug(f"HF: Attempting normal selector for {wallet_address}")
        value_element = WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, selector_normal_hf_value)))
        hf_value = value_element.text.strip(); logging.info(f"HF: Found (normal) for {wallet_address}: {hf_value}")
    except (TimeoutException, NoSuchElementException):
        logging.warning(f"HF: Normal selector failed for {wallet_address}. Trying alternative.")
        try:
            high_hf_mark_element = WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, selector_high_hf_mark_tag)))
            value_span = high_hf_mark_element.find_element(By.CSS_SELECTOR, "span.mantine-Text-root.mantine-1r5e5bx > span")
            if value_span: hf_value = value_span.text.strip(); logging.info(f"HF: Found (high HF) for {wallet_address}: {hf_value}")
            else: logging.warning(f"HF: High HF mark found, but inner span not for {wallet_address}.")
        except (TimeoutException, NoSuchElementException): logging.error(f"HF: Both selectors failed for {wallet_address}.")
        except Exception as e_alt: logging.error(f"HF: Alt selector error for {wallet_address}: {e_alt}", exc_info=True)
    except StaleElementReferenceException: logging.error(f"HF: Stale element for {wallet_address}."); hf_value = "N/A (Stale)"
    except Exception as e_main: logging.error(f"HF: Main error for {wallet_address}: {e_main}", exc_info=True)
    return hf_value
def get_total_borrowed(driver):
    try: return WebDriverWait(driver,10).until(EC.presence_of_element_located((By.CSS_SELECTOR,"span.mantine-Text-root.mantine-agvbd3"))).text.strip()
    except Exception as e: logging.error(f"TotalBorrowed Error: {e}", exc_info=True); return "N/A"
def get_available_to_borrow(driver):
    try: return WebDriverWait(driver,10).until(EC.presence_of_element_located((By.CSS_SELECTOR,"span.mantine-Text-root.mantine-1r8as59"))).text.strip()
    except Exception as e: logging.error(f"AvailableBorrow Error: {e}", exc_info=True); return "N/A"
def get_supplied_asset_value(driver):
    try: elements=WebDriverWait(driver,10).until(EC.presence_of_all_elements_located((By.CSS_SELECTOR,"span.mantine-Text-root.mantine-1r8as59"))); return elements[1].text.strip() if len(elements)>1 else "N/A"
    except Exception as e: logging.error(f"SupplyVal Error: {e}", exc_info=True); return "N/A"
def get_net_asset_value(driver):
    try: elements=WebDriverWait(driver,10).until(EC.presence_of_all_elements_located((By.CSS_SELECTOR,"span.mantine-Text-root.mantine-1r8as59"))); return elements[2].text.strip() if len(elements)>2 else "N/A"
    except Exception as e: logging.error(f"NetVal Error: {e}", exc_info=True); return "N/A"
def parse_coin_from_alt_text(alt_text):
    if alt_text and alt_text.startswith("Logo for "): return alt_text.split("Logo for ")[1]
    elif alt_text: return alt_text.strip()
    logging.warning(f"Could not parse coin alt: '{alt_text}'"); return "N/A"
def get_liquidation_scenario_data_iteratively(driver):
    found_items=[]; block_sel="div.mantine-1cwruym"; item_sel="div.mantine-Badge-root.mantine-wtoc6h"
    coin_sel="img.mantine-9rx0rd.mantine-Avatar-image"; price_sel="span.mantine-1t45alw.mantine-Badge-inner"
    try:
        block=WebDriverWait(driver,10).until(EC.presence_of_element_located((By.CSS_SELECTOR,block_sel)))
        rows=block.find_elements(By.CSS_SELECTOR,item_sel); logging.info(f"LIQ_ITER: Found {len(rows)} rows.")
        for i, row in enumerate(rows):
            cn,pt="N/A","N/A"
            try: cn=parse_coin_from_alt_text(row.find_element(By.CSS_SELECTOR,coin_sel).get_attribute("alt"))
            except: logging.debug(f"LIQ_ITER: Row {i}: Coin ID not found.")
            try: pt=row.find_element(By.CSS_SELECTOR,price_sel).text.strip()
            except: logging.debug(f"LIQ_ITER: Row {i}: Price not found.")
            if pt.startswith("$"): found_items.append({"coin":cn,"price":pt})
            elif cn!="N/A": logging.warning(f"LIQ_ITER: Coin {cn}, Price {pt} not '$'.")
    except Exception as e: logging.exception(f"LIQ_ITER Error: {e}")
    return found_items
def fetch_wallet_data(wallet_address, driver): # Fetches all Aave data
    data={k:"N/A" for k in ["health_factor","total_borrowed","available_to_borrow","supply","networth"]}
    try:
        logging.info(f"FETCH_WALLET_DATA: Navigating for {wallet_address}")
        driver.get("https://defisim.xyz/");
        input_field=WebDriverWait(driver,20).until(EC.presence_of_element_located((By.CSS_SELECTOR,"input.mantine-Input-input.mantine-TextInput-input.mantine-ukw606")))
        input_field.clear();input_field.send_keys(wallet_address);input_field.send_keys(Keys.ENTER)

        hf_value_selector = "h3.mantine-Text-root.mantine-Title-root.mantine-1cydoyt mark.mantine-Mark-root.mantine-qhlhbb span.mantine-Text-root.mantine-1r5e5bx"
        alt_hf_value_selector = f"h3.mantine-Text-root.mantine-Title-root.mantine-1cydoyt mark.mantine-Mark-root.mantine-1ykdmdk span.mantine-Text-root.mantine-1r5e5bx > span"
        logging.info(f"FETCH_WALLET_DATA: Waiting for HF value (normal or alt) for {wallet_address}")
        WebDriverWait(driver,30).until(EC.any_of(EC.presence_of_element_located((By.CSS_SELECTOR,hf_value_selector)),EC.presence_of_element_located((By.CSS_SELECTOR,alt_hf_value_selector))))
        logging.info(f"FETCH_WALLET_DATA: HF value element appeared for {wallet_address}.")
        time.sleep(2)

        data.update({"health_factor":get_wallet_health_factor(wallet_address,driver),"total_borrowed":get_total_borrowed(driver),"available_to_borrow":get_available_to_borrow(driver),"supply":get_supplied_asset_value(driver),"networth":get_net_asset_value(driver)})
        liq_items=get_liquidation_scenario_data_iteratively(driver)
        if liq_items:
            for i,item in enumerate(liq_items):data[f"liquidation_item_{i+1}_coin"],data[f"liquidation_item_{i+1}_price"]=item.get("coin","N/A"),item.get("price","N/A")
    except TimeoutException as e_timeout: logging.error(f"FETCH_WALLET_DATA: TIMEOUT for {wallet_address}: {e_timeout}", exc_info=False); data["error"]="Timeout loading page data"
    except Exception as e: logging.error(f"Error processing wallet {wallet_address}: {e}",exc_info=True);data["error"]="Fetch Error"

    for k in ["health_factor","total_borrowed","available_to_borrow","supply","networth"]: data.setdefault(k,"N/A")
    if not any(k.startswith("liquidation_item_") for k in data): data["liquidation_item_1_coin"],data["liquidation_item_1_price"]="N/A","N/A"
    if data.get("error") and data.get("error") != "N/A":
         for k in list(data.keys()):
             if k!="error" and data[k]=="N/A":data[k]="Error"
         if not any(k.startswith("liquidation_item_") and data[k] not in ["N/A","Error"] for k in data ):
             data.setdefault("liquidation_item_1_coin","Error");data.setdefault("liquidation_item_1_price","Error")
    return data

# --- CRYPTO PRICE TRACKER FUNCTIONS ---
def load_tracked_crypto_coin_names():
    if os.path.exists(CRYPTO_COINS_TRACKED_FILE):
        try:
            with open(CRYPTO_COINS_TRACKED_FILE,"r") as f:coins=json.load(f)
            if isinstance(coins,list) and all(isinstance(c,str) for c in coins):return coins
        except Exception as e:logging.error(f"CRYPTO_LOAD Error: {e}");
    return[]
def save_tracked_crypto_coin_names(coin_list):
    try:
        with open(CRYPTO_COINS_TRACKED_FILE,"w") as f:json.dump(sorted(list(set(coin_list))),f,indent=4);return True
    except Exception as e:logging.error(f"CRYPTO_SAVE Error: {e}");return False
def fetch_prices_for_coins(coin_list):
    if not coin_list: return {}
    prices={};logging.info(f"CRYPTO_FETCH: prices for: {coin_list}")
    for name_orig in coin_list:
        name_slug=name_orig.strip().lower().replace(' ','-'); url=f"https://coinmarketcap.com/currencies/{name_slug}/"
        try:
            r=requests.get(url,headers=CRYPTO_HEADERS,timeout=10);r.raise_for_status()
            soup=BeautifulSoup(r.text,'html.parser');price_el=soup.find('span',attrs={'data-test':'text-cdp-price-display'})
            prices[name_orig]=price_el.text.strip() if price_el else "Price N/A (CMC)";time.sleep(0.3)
        except requests.exceptions.HTTPError as e: prices[name_orig]=f"Coin N/A (CMC)" if e.response.status_code==404 else f"HTTP Err {e.response.status_code}";logging.error(f"CRYPTO HTTP Err {name_orig}: {e}")
        except Exception as e:prices[name_orig]="Fetch Error (CMC)";logging.exception(f"CRYPTO Error {name_orig}: {e}")
    return prices
def fetch_top_10_cmc():
    logging.info("CRYPTO: Fetching Top 10 CMC..."); results=[]; url = "https://coinmarketcap.com/"
    try:
        r = requests.get(url, headers=CRYPTO_HEADERS, timeout=15); r.raise_for_status(); soup = BeautifulSoup(r.text, 'html.parser')
        table = soup.find('table', class_=lambda x:x and 'cmc-table' in x);
        if not table: table = soup.select_one("div[class*='cmc-body-wrapper'] table") # More general table search
        if not table: logging.error("T10_CMC Table not found");return [{"error":"Table not found"}]
        tbody = table.find('tbody');
        if not tbody: logging.error("T10_CMC tbody not found");return [{"error":"tbody not found"}]
        rows = tbody.find_all('tr', limit=12); count = 0
        for row in rows:
            if count>=10: break
            try:
                cells=row.find_all('td');
                if len(cells)<4: continue
                rank_el = cells[1].find('p'); rank = rank_el.text.strip() if rank_el else str(count+1)
                name_cell = cells[2]; name_el = name_cell.find('p', class_=lambda x: x and 'coin-item-name' in x);
                if not name_el: name_el = name_cell.find('p', class_=lambda x: x and 'sc-' in x and 'Text' in x) # Try another common pattern
                if not name_el: name_el = name_cell.select_one('a div p') # More nested
                if not name_el: name_el = name_cell.find('p')
                name = name_el.text.strip() if name_el else "N/A"
                price_cell = cells[3]; price_el = price_cell.find('span');
                if not price_el : price_el = price_cell.select_one('div > a > span')
                if not price_el : price_el = price_cell.select_one('div > span') # Simpler span if not in link
                price = price_el.text.strip() if price_el else "N/A"
                results.append({'rank':rank,'name':name,'price':price}); count+=1
            except Exception as e: logging.error(f"T10_CMC Row {count+1} Error: {e}")
        if not results:return [{"error":"No data parsed"}]
    except Exception as e: logging.exception(f"T10_CMC Error: {e}"); return [{"error": f"Error: {e}"}]
    return results
def fetch_top_50_cr():
    logging.info("CRYPTO: Fetching Top 50 from CoinRanking...")
    results, url = [], "https://coinranking.com/coins"
    try:
        r = requests.get(url, headers=CRYPTO_HEADERS, timeout=15)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, 'html.parser')

        # Use the specific row selector from your HTML
        rows = soup.find_all('tr', attrs={'data-hx-boost': 'false'})
        logging.info(f"CRYPTO_TOP50: Found {len(rows)} rows using 'tr[data-hx-boost=false]'.")

        if not rows:
            logging.warning("CRYPTO_TOP50: No coin rows found with the specified selector.")
            return [{"error": "No coin rows found on CoinRanking"}]

        for i, row in enumerate(rows[:50]): # Limit to top 50
            try:
                rank_el = row.find('td', class_='semibold small align-center')
                rank = rank_el.text.strip() if rank_el else f"{i+1}" # Default if class not found

                name_el = row.select_one('a.coin-profile span.coin-profile__name')
                name = name_el.text.strip() if name_el else "N/A"

                price_el = row.find('real-time-price')
                price_text = price_el.text.strip() if price_el else "N/A"
                price = f"${price_text}" if price_text != "N/A" and not price_text.startswith('$') else price_text

                if name != "N/A" and price_text != "N/A": # Only add if we have a name and some price text
                    results.append({'rank': rank, 'name': name, 'price': price})
                else:
                    logging.warning(f"CRYPTO_TOP50: Row {i+1}: Could not extract full data (Name: {name}, Price Text: {price_text})")

            except Exception as e_row:
                logging.error(f"CRYPTO_TOP50: Error parsing row {i+1}: {e_row}")

        if not results:
            logging.warning("CRYPTO_TOP50: No data successfully parsed from rows.")
            return [{"error":"No data parsed from CoinRanking rows"}]

    except requests.exceptions.RequestException as e_req:
        logging.error(f"CRYPTO_TOP50: Request Error: {e_req}"); return [{"error": f"Network Error: {e_req}"}]
    except Exception as e:
        logging.exception(f"CRYPTO_TOP50: General error: {e}"); return [{"error": f"Failed to fetch Top 50: {e}"}]

    logging.info(f"CRYPTO_TOP50: Fetched {len(results)} items."); return results

def fetch_top_100_cr():
    logging.info("CRYPTO: Fetching Top 100 from CoinRanking...")
    results, base_url = [], "https://coinranking.com/coins"
    all_fetched_rows_count = 0
    try:
        for page_num in [1, 2]:
            if len(results) >= 100: break
            url = f"{base_url}?page={page_num}" if page_num > 1 else base_url
            logging.info(f"CRYPTO_TOP100: Fetching page {page_num} from {url}")
            r = requests.get(url, headers=CRYPTO_HEADERS, timeout=15); r.raise_for_status()
            soup = BeautifulSoup(r.text, 'html.parser')

            rows = soup.find_all('tr', attrs={'data-hx-boost': 'false'})
            logging.info(f"CRYPTO_TOP100: Page {page_num}, found {len(rows)} rows.")
            all_fetched_rows_count += len(rows)
            if not rows and page_num==1:
                logging.warning("CRYPTO_TOP100: No rows found on page 1.")
                return [{"error": "No coin rows found on CoinRanking page 1"}]

            for row in rows:
                if len(results) >= 100: break
                try:
                    rank_el = row.find('td', class_='semibold small align-center')
                    rank = rank_el.text.strip() if rank_el else "N/A"

                    name_el = row.select_one('a.coin-profile span.coin-profile__name')
                    name = name_el.text.strip() if name_el else "N/A"

                    price_el = row.find('real-time-price')
                    price_text = price_el.text.strip() if price_el else "N/A"
                    price = f"${price_text}" if price_text != "N/A" and not price_text.startswith('$') else price_text

                    # Add if we got critical data and to avoid too many N/A rank duplicates
                    if name != "N/A" and price_text != "N/A":
                        # Check for duplicates based on name AND price if rank is N/A
                        is_duplicate = False
                        if rank == "N/A":
                            is_duplicate = any(item.get('name') == name and item.get('price') == price for item in results)
                        else: # If rank is not N/A, check for duplicate rank (should be unique ideally)
                            is_duplicate = any(item.get('rank') == rank for item in results)

                        if not is_duplicate:
                            results.append({'rank': rank, 'name': name, 'price': price})
                        elif rank != "N/A": # If rank is supposed to be unique but already exists
                             logging.warning(f"CRYPTO_TOP100: Duplicate rank {rank} for {name} ignored.")


                except Exception as e_row:
                    logging.error(f"CRYPTO_TOP100: Error parsing row on page {page_num}: {e_row}")

            if page_num == 1 and len(rows) > 0: # Delay only if first page yielded results
                time.sleep(0.5)

        if not results:
            logging.warning("CRYPTO_TOP100: No data successfully parsed from rows.")
            if all_fetched_rows_count > 0: return [{"error": "Could not parse any coin data from rows."}]
            return [{"error":"No data parsed from CoinRanking."}]

    except requests.exceptions.RequestException as e_req:
        logging.error(f"CRYPTO_TOP100: Request Error: {e_req}"); return [{"error": f"Network Error: {e_req}"}]
    except Exception as e:
        logging.exception(f"CRYPTO_TOP100: General error: {e}"); return [{"error": f"Failed to fetch Top 100: {e}"}]

    # Sort by rank if possible
    valid_rank_items = [item for item in results if str(item.get('rank','N/A')).isdigit()]
    other_items = [item for item in results if not str(item.get('rank','N/A')).isdigit()]
    try:
        results_sorted = sorted(valid_rank_items, key=lambda x: int(x['rank'])) + other_items
    except ValueError:
        results_sorted = results
        logging.warning("CRYPTO_TOP100: Could not sort by rank due to non-integer rank values for some items.")

    logging.info(f"CRYPTO_TOP100: Fetched and processed {len(results_sorted)} items."); return results_sorted[:100]
# --- Tkinter GUI Class ---
class WalletDashboardGUI(tk.Tk):
    ESTIMATED_CARD_WIDTH = 290; CARD_PADDING_X = 7; CARD_PADDING_Y = 7
    def __init__(self):
        super().__init__()
        self.title("DeFi Dashboard"); self.geometry("1400x850")
        self.configure(bg=BG_COLOR)
        self.logo_image_tk=None; self.wallet_frames={}; self.no_wallets_label=None
        self.after_id=None; self.driver=None; self.data_queue=queue.Queue()
        self.after_id_crypto_queue=None; self.current_crypto_action=None
        self.after_id_crypto_refresh = None; self.wallets_data_list = []; self.rename_entries = {}
        self.last_aave_render_data = {}; self._last_aave_canvas_width = 0
        self.heading_font=HEADING_FONT_TUPLE; self.regular_font=REGULAR_FONT_TUPLE
        self.small_regular_font=SMALL_REGULAR_FONT_TUPLE; self.link_font=LINK_FONT_TUPLE
        self.dropdown_font=DROPDOWN_FONT_TUPLE; self.crypto_display_font=CRYPTO_DISPLAY_FONT_TUPLE
        self.password = self._get_password()
        if self.password is None: self.destroy(); return
        loaded_wallets = load_wallets(self.password)
        if loaded_wallets is None: self.destroy(); return
        self.wallets_data_list = loaded_wallets
        threading.Thread(target=self._initialize_webdriver_threaded, daemon=True).start()
        self._create_widgets()
        self.check_driver_and_update()
        self.after(200, self._load_initial_crypto_data)
        self.after(300, self._check_crypto_queue)
        self.after(400, self._schedule_crypto_refresh)
        self.protocol("WM_DELETE_WINDOW", self._close_app)

    def _get_password(self): return simpledialog.askstring("Password", "Enter password:", show='*', parent=self)
    def _initialize_webdriver_threaded(self):
        logging.info("GUI: Initializing WebDriver...")
        options=Options();options.add_argument("--headless");options.add_argument("--disable-gpu");options.add_argument("--no-sandbox");options.add_argument("--disable-dev-shm-usage")
        options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        try:
            self.driver = webdriver.Chrome(options=options); self.driver.set_window_size(1200, 800)
            logging.info("GUI: WebDriver initialized."); self.after(100, self._initial_dashboard_load)
        except Exception as e:
            logging.error(f"GUI: WebDriver init Error: {e}", exc_info=True); self.driver = None
            self.after(0, lambda: messagebox.showerror("WebDriver Error", f"Failed init: {e}\nAave features disabled."))
    def check_driver_and_update(self):
        if self.driver: self._initial_dashboard_load()
        elif not hasattr(self,'_init_attempts') or self._init_attempts < 20:
            self._init_attempts = getattr(self, '_init_attempts',0)+1; self.after(500, self.check_driver_and_update)
        elif not self.driver: messagebox.showerror("WebDriver Error", "WebDriver could not be initialized.")
    def _initial_dashboard_load(self):
        if not self.driver: logging.warning("GUI: Driver not ready for Aave load."); return
        if self.wallets_data_list: self._refresh_data_threaded()
        else: self._show_no_wallets_message()
    def _create_widgets(self):
        try:
            logo_file_path=resource_path("logo_raw_b64.txt");
            with open(logo_file_path,"r") as f:b64_str=f.read().strip()
            if not b64_str:raise ValueError("Logo file empty.")
            img_data=base64.b64decode(b64_str);stream=io.BytesIO(img_data);img=Image.open(stream).resize((220,107),Image.Resampling.LANCZOS)
            self.logo_image_tk=ImageTk.PhotoImage(img);tk.Label(self,image=self.logo_image_tk,bg=BG_COLOR).pack(pady=10,side=tk.TOP)
        except Exception as e:logging.error(f"Logo Error: {e}",exc_info=True);tk.Label(self,text="Logo Error",bg=BG_COLOR,fg="red").pack(pady=10,side=tk.TOP)
        self.main_content_frame=tk.Frame(self,bg=BG_COLOR);self.main_content_frame.pack(padx=10,pady=0,fill=tk.BOTH,expand=True,side=tk.TOP)
        self.main_content_frame.grid_columnconfigure(0,weight=1,minsize=350,uniform='panel');self.main_content_frame.grid_columnconfigure(1,weight=3,uniform='panel')
        self.main_content_frame.grid_rowconfigure(0,weight=0);self.main_content_frame.grid_rowconfigure(1,weight=1);self.main_content_frame.grid_rowconfigure(2,weight=0)
        tk.Label(self.main_content_frame,text="Price Tracker",font=self.heading_font,bg=BG_COLOR,fg=FG_COLOR).grid(row=0,column=0,pady=(5,2),sticky='n')
        tk.Label(self.main_content_frame,text="Aave Dashboard",font=self.heading_font,bg=BG_COLOR,fg=FG_COLOR).grid(row=0,column=1,pady=(5,2),sticky='n')
        self.crypto_panel_frame=tk.Frame(self.main_content_frame,bd=1,relief=tk.SOLID,padx=10,pady=10,bg=BG_COLOR,highlightbackground=BORDER_COLOR,highlightthickness=1)
        self.crypto_panel_frame.grid(row=1,column=0,padx=(0,5),pady=(0,5),sticky='nsew')
        self.crypto_display_text=tk.Text(self.crypto_panel_frame,bg=TEXT_AREA_BG_COLOR,fg=FG_COLOR,font=self.crypto_display_font,relief=tk.FLAT,wrap=tk.WORD,state=tk.DISABLED,bd=0,highlightthickness=0,height=10)
        self.crypto_display_text.pack(fill=tk.BOTH,expand=True,pady=(0,10),side=tk.TOP)
        style=ttk.Style(self);style.theme_use('clam');style.configure('TCombobox.Listbox',background=BG_COLOR,foreground=FG_COLOR,fieldbackground=BG_COLOR);style.configure('Custom.TCombobox',fieldbackground=BG_COLOR,foreground=FG_COLOR,selectbackground=BORDER_COLOR,selectforeground=FG_COLOR,background=BG_COLOR,arrowcolor=FG_COLOR,borderwidth=1,lightcolor=BG_COLOR,darkcolor=BG_COLOR,relief=tk.FLAT)
        style.map('Custom.TCombobox',fieldbackground=[('readonly',BG_COLOR)],foreground=[('readonly',FG_COLOR)],arrowcolor=[('readonly',FG_COLOR)],selectbackground=[('readonly',BORDER_COLOR)],selectforeground=[('readonly',FG_COLOR)])
        self.crypto_action_var=tk.StringVar(self.crypto_panel_frame);self.crypto_actions=["Choose action...","Show My Tracked Coins","Add Coin to Track","Remove Tracked Coin","Show Top 10 (CMC)","Show Top 50 (CR)","Show Top 100 (CR)","Refresh Current View"];self.crypto_action_var.set(self.crypto_actions[0])
        try:
            self.crypto_action_dropdown=ttk.Combobox(self.crypto_panel_frame,textvariable=self.crypto_action_var,values=self.crypto_actions,state="readonly",font=self.dropdown_font,width=23,style='Custom.TCombobox')
            self.crypto_action_dropdown.bind("<<ComboboxSelected>>",lambda e:self._handle_crypto_tracker_action(self.crypto_action_var.get()))
            logging.info("Using ttk.Combobox for crypto actions.")
        except tk.TclError as e_ttk:
            logging.warning(f"ttk Combobox failed ({e_ttk}), using tk.OptionMenu.")
            self.crypto_action_dropdown=tk.OptionMenu(self.crypto_panel_frame,self.crypto_action_var,*self.crypto_actions,command=self._handle_crypto_tracker_action)
            self.crypto_action_dropdown.config(bg=BG_COLOR,fg=FG_COLOR,relief=tk.FLAT,activebackground=BORDER_COLOR,activeforeground=FG_COLOR,highlightthickness=1,highlightbackground=BORDER_COLOR,width=25,font=self.dropdown_font,anchor='w')
            try: menu=self.crypto_action_dropdown.nametowidget(self.crypto_action_dropdown.cget('menu')); menu.config(bg=BG_COLOR,fg=FG_COLOR,relief=tk.FLAT,bd=0,font=self.dropdown_font,activebackground=BORDER_COLOR,activeforeground=FG_COLOR)
            except Exception as e_menu:logging.warning(f"Could not style OptionMenu menu: {e_menu}")
        self.crypto_action_dropdown.pack(side=tk.BOTTOM,pady=5,fill=tk.X)
        aave_canvas_container=tk.Frame(self.main_content_frame,bg=BG_COLOR);aave_canvas_container.grid(row=1,column=1,padx=(5,0),pady=(0,5),sticky='nsew')
        aave_canvas_container.grid_rowconfigure(0,weight=1);aave_canvas_container.grid_columnconfigure(0,weight=1)
        self.aave_cards_canvas=tk.Canvas(aave_canvas_container,bg=BG_COLOR,highlightthickness=0);self.aave_cards_canvas.grid(row=0,column=0,sticky='nsew')
        aave_scrollbar=ttk.Scrollbar(aave_canvas_container,orient="vertical",command=self.aave_cards_canvas.yview);aave_scrollbar.grid(row=0,column=1,sticky='ns');self.aave_cards_canvas.configure(yscrollcommand=aave_scrollbar.set)
        self.aave_scrollable_cards_frame=tk.Frame(self.aave_cards_canvas,bg=BG_COLOR);self.aave_canvas_window=self.aave_cards_canvas.create_window((0,0),window=self.aave_scrollable_cards_frame,anchor="nw")
        self.aave_scrollable_cards_frame.bind("<Configure>",self._on_configure_scrollable_area);self.aave_cards_canvas.bind("<Configure>",self._on_canvas_configure)
        self.aave_cards_canvas.bind('<Enter>',lambda e,w=self.aave_cards_canvas:self._bind_mousewheel(e,w));self.aave_cards_canvas.bind('<Leave>',lambda e,w=self.aave_cards_canvas:self._unbind_mousewheel(e,w))
        self.button_style={"bg":BUTTON_BG_COLOR,"fg":BUTTON_FG_COLOR,"activebackground":BUTTON_ACTIVE_BG_COLOR,"activeforeground":BUTTON_FG_COLOR,"relief":tk.FLAT,"padx":10,"pady":5,"font":("Arial",10,"bold")}
        aave_btn_bar=tk.Frame(self.main_content_frame,bg=BG_COLOR);aave_btn_bar.grid(row=2,column=1,sticky='n',pady=(5,10))
        aave_inner_btn=tk.Frame(aave_btn_bar,bg=BG_COLOR);aave_inner_btn.pack(anchor=tk.CENTER)
        self.add_wallet_btn=tk.Button(aave_inner_btn,text="Add Aave Wallet",command=self._add_new_wallets,**self.button_style);self.add_wallet_btn.pack(side=tk.LEFT,padx=5,pady=5)
        self.refresh_aave_btn=tk.Button(aave_inner_btn,text="Refresh Aave Data",command=self._refresh_data_threaded,**self.button_style);self.refresh_aave_btn.pack(side=tk.LEFT,padx=5,pady=5)
        self.remove_wallet_btn=tk.Button(aave_inner_btn,text="Remove Aave Wallet",command=self._open_remove_dialog,**self.button_style);self.remove_wallet_btn.pack(side=tk.LEFT,padx=5,pady=5)
        self.rename_wallet_btn=tk.Button(aave_inner_btn,text="Rename Wallets",command=self._open_rename_dialog,**self.button_style);self.rename_wallet_btn.pack(side=tk.LEFT,padx=5,pady=5)

    def _on_configure_scrollable_area(self, event): self.aave_cards_canvas.configure(scrollregion=self.aave_cards_canvas.bbox("all"))
    def _on_canvas_configure(self, event):
        canvas_width = event.width; self.aave_cards_canvas.itemconfig(self.aave_canvas_window, width=canvas_width)
        if hasattr(self,'last_aave_render_data') and self.last_aave_render_data and hasattr(self,'_last_aave_canvas_width') and abs(canvas_width-self._last_aave_canvas_width)>20:
            logging.info(f"Aave Canvas reconfigured to width {canvas_width}, re-rendering cards.")
            self._render_dashboard_gui(self.last_aave_render_data)
        self._last_aave_canvas_width=canvas_width; self.after(50,self._update_scroll_region_aave)
    def _bind_mousewheel(self,event,widget): widget.bind_all("<MouseWheel>",lambda e,w=widget: self._on_mousewheel(e,w)); widget.bind_all("<Button-4>",lambda e,w=widget: self._on_mousewheel(e,w)); widget.bind_all("<Button-5>",lambda e,w=widget: self._on_mousewheel(e,w))
    def _unbind_mousewheel(self,event,widget): widget.unbind_all("<MouseWheel>"); widget.unbind_all("<Button-4>"); widget.unbind_all("<Button-5>")
    def _on_mousewheel(self,event,canvas_widget): delta=1 if event.num==5 or event.delta<0 else (-1 if event.num==4 or event.delta>0 else 0); canvas_widget.yview_scroll(delta,"units")
    def _update_scroll_region_aave(self):
        if hasattr(self,'aave_cards_canvas') and self.aave_cards_canvas.winfo_exists(): self.aave_cards_canvas.configure(scrollregion=self.aave_cards_canvas.bbox("all"))
    def _handle_crypto_tracker_action(self,action):
        logging.info(f"GUI: Crypto action: {action}")
        if action == "Choose action...": return
        action_map = {"Show My Tracked Coins": (fetch_prices_for_coins,True), "Add Coin to Track": (self._add_crypto_coin_dialog,False), "Remove Tracked Coin": (self._remove_crypto_coin_dialog,False), "Show Top 10 (CMC)": (fetch_top_10_cmc,False), "Show Top 50 (CR)": (fetch_top_50_cr,False),"Show Top 100 (CR)": (fetch_top_100_cr,False), "Refresh Current View": (self._refresh_crypto_view,False)}
        self.current_crypto_action = action
        if action in action_map:
            func, needs_list = action_map[action]
            if callable(func) and func not in [self._add_crypto_coin_dialog,self._remove_crypto_coin_dialog,self._refresh_crypto_view]:
                args = [load_tracked_crypto_coin_names()] if needs_list else []
                self._update_crypto_display(f"Loading {action}..."); threading.Thread(target=self._run_crypto_fetcher_threaded, args=(func,args,action),daemon=True).start()
            elif callable(func): func()
        self.after(100, lambda: self.crypto_action_var.set(self.crypto_actions[0]))
    def _run_crypto_fetcher_threaded(self,func,args,action_name):
        try: result = func(*args); self.data_queue.put(("crypto_result", action_name, result))
        except Exception as e: logging.exception(f"THREAD_CRYPTO Error: {e}"); self.data_queue.put(("crypto_error", action_name, str(e)))
    def _check_crypto_queue(self):
        try:
            while True: msg_type, action, data = self.data_queue.get_nowait(); self._process_crypto_queue_item(msg_type, action, data)
        except queue.Empty: pass
        finally: self.after_id_crypto_queue = self.after(100, self._check_crypto_queue)
    def _process_crypto_queue_item(self, msg_type, action_name, data):
         if msg_type == "crypto_result": self._format_and_display_crypto_results(action_name, data)
         elif msg_type == "crypto_error": self._update_crypto_display(f"Error for '{action_name}':\n{data}")

    def _format_and_display_crypto_results(self, action, data):
        logging.info(f"GUI_CRYPTO_DISPLAY: Formatting action='{action}', type(data)='{type(data)}'")
        content = f"--- {action} ---\n\n"

        # We are not using explicit tabs for this formatting approach
        try:
            self.crypto_display_text.configure(tabs=())
        except tk.TclError:
            pass

        if action == "Show My Tracked Coins":
            if isinstance(data, dict) and data:
                for coin, price in data.items():
                    # Corrected Format: "CoinName: $Price" with minimal space
                    content += f"{str(coin).title()}: {price}\n"
            elif not data:
                content += "No tracked coins or no prices available."
            else:
                content += f"Unexpected data for tracked coins. Expected dict, got {type(data)}.\nContent: {str(data)[:250]}"

        elif action in ["Show Top 10 (CMC)", "Show Top 50 (CR)", "Show Top 100 (CR)"]:
            if isinstance(data, list) and data:
                if isinstance(data[0], dict) and 'error' in data[0]:
                    content += f"Error: {data[0]['error']}"
                else:
                    for item in data:
                        rank = str(item.get('rank', '')).strip()
                        name = str(item.get('name', 'N/A')).strip()
                        price = str(item.get('price', 'N/A')).strip()

                        rank_display = f"{rank}." if rank.isdigit() and rank else rank

                        # Corrected Format: "Rank. Name: Price"
                        content += f"{rank_display} {name}: {price}\n"
            elif not data:
                content += "No data returned for Top N list."
            else:
                content += f"Unexpected data format for Top N list: {type(data)}"

        else:
            logging.warning(f"GUI_CRYPTO_DISPLAY: Unhandled action_name: '{action}'")
            content += f"Data for '{action}':\n" # Corrected variable name to action
            try:
                text_to_add = json.dumps(data, indent=2) if data else f"No data for '{action}'."
            except TypeError:
                 text_to_add = str(data) if data else f"No data for '{action}'."
            content += text_to_add # Append the processed string

        self._update_crypto_display(content)
    def _update_crypto_display(self, text):
        self.crypto_display_text.config(state=tk.NORMAL); self.crypto_display_text.delete('1.0',tk.END); self.crypto_display_text.insert(tk.END,text); self.crypto_display_text.config(state=tk.DISABLED)
    def _add_crypto_coin_dialog(self):
        coins=simpledialog.askstring("Add Coins","Coin names/slugs (CoinMarketCap, comma-sep):",parent=self)
        if coins:
            new=[c.strip().lower() for c in coins.split(',') if c.strip()]; current=load_tracked_crypto_coin_names(); added=0
            for n in new:
                if n not in current: current.append(n); added+=1
            if added:
                if save_tracked_crypto_coin_names(current): messagebox.showinfo("Success",f"Added {added}.",parent=self); self._handle_crypto_tracker_action("Show My Tracked Coins")
                else: messagebox.showerror("Error","Failed save.",parent=self)
            else: messagebox.showinfo("Info","No new coins added.",parent=self)
    def _remove_crypto_coin_dialog(self):
        current=load_tracked_crypto_coin_names()
        if not current: messagebox.showinfo("Info","No coins to remove.",parent=self); return
        coins=simpledialog.askstring("Remove Coins",f"Coin names to remove (comma-sep).\nTracking: {', '.join(current)}",parent=self)
        if coins:
            rem={c.strip().lower() for c in coins.split(',') if c.strip()}; upd=[c for c in current if c.lower() not in rem]
            if len(upd)<len(current):
                if save_tracked_crypto_coin_names(upd): messagebox.showinfo("Success","Coins removed.",parent=self); self._handle_crypto_tracker_action("Show My Tracked Coins")
                else: messagebox.showerror("Error","Failed save.",parent=self)
            else: messagebox.showinfo("Info","No matching coins found.",parent=self)
    def _refresh_crypto_view(self):
        action=getattr(self,'current_crypto_action',"Show My Tracked Coins"); action="Show My Tracked Coins" if action in ["Choose action...","Refresh Current View"] else action; self._handle_crypto_tracker_action(action)
    def _load_initial_crypto_data(self):
         self.current_crypto_action = "Show My Tracked Coins"; self._handle_crypto_tracker_action(self.current_crypto_action)
    def _schedule_crypto_refresh(self):
        if hasattr(self,'after_id_crypto_refresh') and self.after_id_crypto_refresh: self.after_cancel(self.after_id_crypto_refresh); self.after_id_crypto_refresh=None
        interval_ms = 10*60*1000; logging.info(f"Scheduling crypto refresh: {interval_ms}ms")
        self.after_id_crypto_refresh = self.after(interval_ms, self._refresh_crypto_auto_threaded)
    def _refresh_crypto_auto_threaded(self):
        logging.info("AUTO_REFRESH_CRYPTO: Triggered."); coins = load_tracked_crypto_coin_names()
        if coins: threading.Thread(target=self._run_crypto_fetcher_threaded, args=(fetch_prices_for_coins, [coins], "Show My Tracked Coins"), daemon=True).start()
        else: logging.info("AUTO_REFRESH_CRYPTO: No coins.")
        self._schedule_crypto_refresh()

    def _clear_no_wallets_message(self):
        if self.no_wallets_label and self.no_wallets_label.winfo_exists(): self.no_wallets_label.destroy(); self.no_wallets_label = None
    def _show_no_wallets_message(self):
        self._clear_no_wallets_message(); parent = self.aave_scrollable_cards_frame if hasattr(self,'aave_scrollable_cards_frame') and self.aave_scrollable_cards_frame.winfo_exists() else self.main_content_frame # Fallback
        if parent and parent.winfo_exists():
            self.no_wallets_label = tk.Label(parent, text="No Aave wallets loaded.",bg=BG_COLOR, fg=FG_COLOR, font=("Arial",14)); self.no_wallets_label.pack(pady=30, expand=True, anchor=tk.CENTER)
        else: logging.error("Cannot show 'no Aave wallets': target parent gone.")
    def _add_new_wallets(self):
        logging.info("--- Add Aave Wallet: START ---")
        new_in=simpledialog.askstring("Add Aave Wallet(s)","Enter wallet addresses (comma-separated):",parent=self)
        if not new_in or not new_in.strip(): logging.info("Add Aave: Cancelled."); return
        self._clear_no_wallets_message(); valid,invalid,dup=[],[],[]
        if self.wallets_data_list is None: self.wallets_data_list = []
        current_adds = {w_info['address'] for w_info in self.wallets_data_list}
        for w_str in new_in.split(','):
            w = w_str.strip().lower();
            if not w: continue
            if not is_valid_address(w): invalid.append(w)
            elif w in current_adds: dup.append(w)
            else: valid.append({"address":w,"name":""})
        if invalid: messagebox.showerror("Invalid Input", f"Invalid Aave format:\n{', '.join(invalid)}", parent=self)
        if dup: messagebox.showwarning("Duplicates", f"Aave already tracked:\n{', '.join(dup)}", parent=self)
        if valid:
            original_list = self.wallets_data_list[:]; self.wallets_data_list.extend(valid)
            if not save_wallets(self.wallets_data_list,self.password): messagebox.showerror("Save Error","Failed save Aave.",parent=self); self.wallets_data_list=original_list
            else: logging.info("Aave save successful. Refreshing."); self._refresh_data_threaded()
        elif not self.wallets_data_list: self._show_no_wallets_message()
        elif new_in.strip(','): messagebox.showinfo("Info", "No new valid wallets to add.", parent=self)
        logging.info("--- Add Aave Wallet: END ---")
    def _refresh_data_threaded(self): # Aave
        if not self.driver: messagebox.showwarning("Driver Not Ready","WebDriver init...",parent=self); return
        if not self.wallets_data_list: messagebox.showinfo("Info","No Aave wallets.",parent=self); self._show_no_wallets_message(); return
        if hasattr(self,'refresh_aave_btn') and self.refresh_aave_btn: self.refresh_aave_btn.config(state=tk.DISABLED,text="Refreshing Aave...")
        self._clear_no_wallets_message()
        if hasattr(self,'loading_label_aave') and self.loading_label_aave.winfo_exists(): self.loading_label_aave.destroy()
        parent = self.aave_scrollable_cards_frame if hasattr(self, 'aave_scrollable_cards_frame') and self.aave_scrollable_cards_frame.winfo_exists() else self.main_content_frame
        self.loading_label_aave=tk.Label(parent,text="Fetching Aave data...",bg=BG_COLOR,fg="orange",font=("Arial",14))
        # Use grid to place the loading label
        if parent == self.aave_scrollable_cards_frame:
            self.loading_label_aave.grid(row=0, column=0, columnspan=5, sticky="ew", pady=30)
        # 'columnspan' is used to make it span across potential columns of wallet cards
        # 'sticky="ew"' makes it stretch horizontally
        else:
            self.loading_label_aave.pack(pady=30) # Fallback to pack if parent is main_content_frame
        self.update_idletasks()
        threading.Thread(target=self._update_dashboard_worker,daemon=True).start()
    def _update_dashboard_worker(self): # Aave worker
        re_enable=True
        if not self.driver or not self.wallets_data_list: logging.warning("Aave worker: Driver/list not ready.")
        else:
            self.last_aave_render_data={}
            for wallet_info in self.wallets_data_list:
                address = wallet_info['address']
                fetched_data = fetch_wallet_data(address, self.driver)
                self.last_aave_render_data[address] = {"info": wallet_info, "fetched": fetched_data}
            self.after(0,self._render_dashboard_gui, self.last_aave_render_data)
            re_enable=False
        if re_enable and hasattr(self,'refresh_aave_btn') and self.refresh_aave_btn:
            self.after(0,lambda: self.refresh_aave_btn.config(state=tk.NORMAL,text="Refresh Aave Data"))
    def _render_dashboard_gui(self, all_render_data):
        logging.info("Rendering Aave cards...")
        if hasattr(self,'loading_label_aave') and self.loading_label_aave.winfo_exists(): self.loading_label_aave.destroy()
        if not (hasattr(self, 'aave_scrollable_cards_frame') and self.aave_scrollable_cards_frame.winfo_exists()): logging.error("Cannot render Aave cards: scrollable_card_area missing!"); return
        for widget in self.aave_scrollable_cards_frame.winfo_children(): widget.destroy()
        self.wallet_frames = {}
        if not all_render_data and self.wallets_data_list: messagebox.showerror("Data Error","Failed fetch Aave.",parent=self)
        elif not self.wallets_data_list: self._show_no_wallets_message()
        else:
            self.update_idletasks(); canvas_width = self.aave_cards_canvas.winfo_width()
            if canvas_width <= 1: canvas_width = getattr(self, '_last_aave_canvas_width', 800)
            self._last_aave_canvas_width = canvas_width
            est_card_width = self.ESTIMATED_CARD_WIDTH + (2 * self.CARD_PADDING_X); num_cols = max(1, canvas_width // est_card_width)
            logging.info(f"CanvasW: {canvas_width}, Est. card W: {est_card_width}, Cols: {num_cols}")
            for i in range(num_cols): self.aave_scrollable_cards_frame.grid_columnconfigure(i, weight=0) # Let cards define their width naturally
            for i, wallet_info_orig in enumerate(self.wallets_data_list):
                 addr = wallet_info_orig['address']; render_d = all_render_data.get(addr)
                 if render_d:
                     row,col=i//num_cols, i%num_cols
                     card_f=self._create_wallet_card_widget(self.aave_scrollable_cards_frame,render_d['info'],render_d['fetched'])
                     card_f.grid(row=row,column=col,padx=self.CARD_PADDING_X,pady=self.CARD_PADDING_Y,sticky='nw')
                     self.wallet_frames[addr]=card_f
                 else: logging.error(f"Render: Data missing for {addr}")
        if hasattr(self,'refresh_aave_btn') and self.refresh_aave_btn: self.refresh_aave_btn.config(state=tk.NORMAL,text="Refresh Aave Data")
        self.after(50, self._update_scroll_region_aave); self._schedule_refresh() # Reschedule Aave timer
    def _create_wallet_card_widget(self, parent, wallet_info, fetched_data):
        address = wallet_info['address']; frame=tk.Frame(parent,bd=1,relief=tk.SOLID,padx=10,pady=10,bg=BG_COLOR,highlightbackground=BORDER_COLOR,highlightthickness=1)
        display_name = wallet_info.get('name','').strip(); header_text = display_name if display_name else f"{address[:6]}...{address[-4:]}"
        tk.Label(frame,text=f"{header_text}",font=self.heading_font,bg=BG_COLOR,fg=FG_COLOR).pack(anchor="w",pady=(0,1))
        tk.Label(frame,text=address,font=self.link_font,bg=BG_COLOR,fg="#AAAAAA",justify=tk.LEFT,wraplength=250).pack(anchor="w",pady=(0,3))
        err=fetched_data.get("error");
        if err and err not in ["N/A","Fetch Error","Error"]: tk.Label(frame,text=f"Error: {err}",bg=BG_COLOR,fg="orange",font=self.regular_font,wraplength=180).pack(anchor="w"); return frame
        items=[("Health Factor",fetched_data.get("health_factor","N/A")),("Total Borrowed",fetched_data.get("total_borrowed","N/A")),("Available To Borrow",fetched_data.get("available_to_borrow","N/A")),("Supply",fetched_data.get("supply","N/A")),("Networth",fetched_data.get("networth","N/A"))]
        for kd,v in items:
            tc,f=FG_COLOR,self.regular_font;
            if v in ["N/A",None,"Fetch Error","Error"]:tc="#AAAAAA"
            if kd=="Health Factor":
                f=self.heading_font
                try:hfv=float(v);tc=HF_HIGH_RISK_COLOR if hfv<1 else (HF_MED_RISK_COLOR1 if hfv<1.1 else (HF_MED_RISK_COLOR2 if hfv<1.5 else (HF_VERY_SAFE_COLOR if hfv>=2.0 else HF_SAFE_COLOR)))
                except:pass
            tk.Label(frame,text=f"{kd}: {v}",bg=BG_COLOR,fg=tc,font=f).pack(anchor="w")
        lip=False
        for i in range(1,5):
            ck,pk=f"liquidation_item_{i}_coin",f"liquidation_item_{i}_price";cv,pv=fetched_data.get(ck),fetched_data.get(pk)
            if cv and cv not in ["N/A","Fetch Error","Error"]:
                if not lip:tk.Label(frame,text="Liquidation Scenario:",bg=BG_COLOR,fg=FG_COLOR,font=self.regular_font).pack(anchor="w",pady=(5,0));lip=True
                tk.Label(frame,text=f"  {cv}: {pv if pv else 'N/A'}",bg=BG_COLOR,fg=FG_COLOR,font=(self.regular_font[0],self.regular_font[1]-2)).pack(anchor="w")
            elif ck not in fetched_data:break
        if not lip and fetched_data.get("liquidation_item_1_coin","N/A") in ["N/A","Fetch Error","Error",None]: tk.Label(frame,text="Liquidation Scenario: N/A",bg=BG_COLOR,fg="#AAAAAA",font=self.regular_font).pack(anchor="w",pady=(5,0))
        urll=tk.Label(frame,text="View on DefiSim",fg=LINK_COLOR,cursor="hand2",bg=BG_COLOR,font=self.link_font);urll.pack(anchor="w",pady=(8,0));urll.bind("<Button-1>",lambda e,addr=address:webbrowser.open_new_tab(f"https://defisim.xyz/?address={addr}")) # Corrected URL
        return frame
    def _schedule_refresh(self): # Aave
        if self.after_id: self.after_cancel(self.after_id); self.after_id = None
        interval_ms = 10*60*1000; logging.info(f"Scheduling Aave refresh: {interval_ms}ms")
        self.after_id=self.after(interval_ms, self._refresh_data_auto_threaded)
    def _refresh_data_auto_threaded(self): # Aave trigger
        if self.wallets_data_list and self.driver: logging.info("GUI: Auto-refresh Aave."); self._refresh_data_threaded()
    def _open_remove_dialog(self): # RENAMING: Updated
        if not self.wallets_data_list: messagebox.showinfo("Info","No Aave wallets.",parent=self); return
        rd=tk.Toplevel(self);rd.title("Remove Aave Wallets");rd.configure(bg=BG_COLOR);rd.transient(self);rd.grab_set();rd.geometry(f"+{self.winfo_x()+50}+{self.winfo_y()+50}")
        self.remove_vars={}; cf=tk.Frame(rd,bg=BG_COLOR); cf.pack(padx=20,pady=10)
        cbs={"bg":BG_COLOR,"fg":FG_COLOR,"selectcolor":CHECKBOX_SELECT_COLOR,"activebackground":BG_COLOR,"activeforeground":FG_COLOR,"highlightthickness":0,"font":("Arial",10)}
        for i,w_info in enumerate(self.wallets_data_list):
             addr = w_info['address']; name = w_info.get('name', ''); display = name if name else f"{addr[:10]}...{addr[-8:]}"
             var=tk.BooleanVar(); tk.Checkbutton(cf,text=display,variable=var,**cbs).grid(row=i,column=0,sticky="w",padx=5,pady=3); self.remove_vars[addr]=var
        tk.Button(rd,text="Remove Selected",command=lambda:self._remove_selected_wallets(rd),**self.button_style).pack(pady=(5,15))
    def _remove_selected_wallets(self, dialog): # RENAMING: Updated
        to_rem={addr for addr,v in self.remove_vars.items() if v.get()}
        if to_rem:
            original_count=len(self.wallets_data_list); self.wallets_data_list=[w for w in self.wallets_data_list if w['address'] not in to_rem]; removed_count=original_count-len(self.wallets_data_list)
            if removed_count > 0:
                if not save_wallets(self.wallets_data_list,self.password): messagebox.showerror("Save Error","Failed save Aave.",parent=self)
                self._refresh_data_threaded(); messagebox.showinfo("Wallets Removed",f"Removed {removed_count} wallet(s).",parent=self)
        dialog.destroy();
        if not self.wallets_data_list:self._show_no_wallets_message()
    def _open_rename_dialog(self): # RENAMING: New
        if not self.wallets_data_list: messagebox.showinfo("Info","No Aave wallets to rename.",parent=self); return
        rd = tk.Toplevel(self); rd.title("Rename Aave Wallets"); rd.configure(bg=BG_COLOR); rd.transient(self); rd.grab_set(); rd.geometry(f"600x400+{self.winfo_x()+100}+{self.winfo_y()+100}")
        self.rename_entries = {}
        hf=tk.Frame(rd,bg=BG_COLOR); hf.pack(pady=(10,5),padx=10,fill=tk.X)
        tk.Label(hf,text="Address",font=("Arial",10,"bold"),bg=BG_COLOR,fg=FG_COLOR,width=25,anchor='w').pack(side=tk.LEFT,padx=(0,20))
        tk.Label(hf,text="Custom Name",font=("Arial",10,"bold"),bg=BG_COLOR,fg=FG_COLOR,anchor='w').pack(side=tk.LEFT)
        cf=tk.Canvas(rd,bg=BG_COLOR,highlightthickness=0); sb=ttk.Scrollbar(rd,orient="vertical",command=cf.yview); sf=tk.Frame(cf,bg=BG_COLOR)
        sf.bind("<Configure>",lambda e: cf.configure(scrollregion=cf.bbox("all"))); canvas_window_id_rename_dialog=cf.create_window((0,0),window=sf,anchor="nw"); cf.configure(yscrollcommand=sb.set) # Store id locally
        cf.pack(side=tk.LEFT,fill=tk.BOTH,expand=True,padx=(10,0),pady=(0,5)); sb.pack(side=tk.RIGHT,fill="y",pady=(0,5))
        cf.bind('<Enter>',lambda e,w=cf: self._bind_mousewheel(e,w)); cf.bind('<Leave>',lambda e,w=cf: self._unbind_mousewheel(e,w))
        cf.bind("<Configure>", lambda event, c=cf, cw_id=canvas_window_id_rename_dialog: c.itemconfig(cw_id, width=event.width)) # Adjust frame width
        entry_style = {"bg": TEXT_AREA_BG_COLOR, "fg": FG_COLOR, "insertbackground": FG_COLOR, "relief": tk.SOLID, "bd": 1}
        for w_info in self.wallets_data_list:
            addr, name = w_info['address'], w_info.get('name', '')
            rf = tk.Frame(sf, bg=BG_COLOR)
            tk.Label(rf, text=f"{addr[:10]}...{addr[-8:]}",font=("Monaco",10),bg=BG_COLOR,fg=FG_COLOR,width=25,anchor='w').pack(side=tk.LEFT,padx=5,pady=3)
            entry = tk.Entry(rf, width=35, **entry_style); entry.insert(0, name); entry.pack(side=tk.LEFT, padx=5, pady=3)
            self.rename_entries[addr] = entry
            rf.pack(fill=tk.X)
        bf = tk.Frame(rd, bg=BG_COLOR); bf.pack(pady=10)
        tk.Button(bf, text="Cancel", command=rd.destroy, **self.button_style).pack(side=tk.RIGHT, padx=10)
        tk.Button(bf, text="Save Names", command=lambda d=rd: self._save_renamed_wallets(d), **self.button_style).pack(side=tk.RIGHT)
    def _save_renamed_wallets(self, dialog): # RENAMING: New
        logging.info("Saving renamed Aave wallets...")
        updated = False
        for w_info in self.wallets_data_list:
            addr = w_info['address']
            if addr in self.rename_entries:
                new_name = self.rename_entries[addr].get().strip()
                if w_info.get('name', '') != new_name: w_info['name'] = new_name; updated = True; logging.info(f"Updated name for {addr} to '{new_name}'")
        if updated:
            if save_wallets(self.wallets_data_list, self.password): messagebox.showinfo("Success", "Names saved.", parent=self); self._refresh_data_threaded()
            else: logging.error("Failed to save renamed wallets.")
        else: logging.info("No names changed."); messagebox.showinfo("No Changes", "No names were changed.", parent=self)
        dialog.destroy()
    def _close_app(self):
        logging.info("GUI: Close app called.")
        if hasattr(self,'after_id_crypto_queue') and self.after_id_crypto_queue: self.after_cancel(self.after_id_crypto_queue)
        if self.after_id: self.after_cancel(self.after_id)
        if hasattr(self,'after_id_crypto_refresh') and self.after_id_crypto_refresh: self.after_cancel(self.after_id_crypto_refresh)
        if self.driver: logging.info("GUI: Quitting WebDriver."); self.driver.quit()
        self.destroy()

# --- Main Execution ---
if __name__ == "__main__":
    try: from PIL import Image, ImageTk
    except ImportError: messagebox.showerror("Missing Library", "Pillow not installed."); exit()
    gui = WalletDashboardGUI()
    try:
        if gui.winfo_exists(): gui.mainloop()
    except tk.TclError as e:
        if "application has been destroyed" not in str(e).lower(): raise
        logging.info("GUI: App destroyed before mainloop.")
