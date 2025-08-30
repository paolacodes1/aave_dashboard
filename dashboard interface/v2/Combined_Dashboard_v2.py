import tkinter as tk
from tkinter import simpledialog, messagebox, font as tkFont, ttk
import json
import os
import logging
import base64
import webbrowser
import time
from PIL import Image, ImageTk
import sys
import io
import threading
import queue
import requests
from bs4 import BeautifulSoup
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Import our new API client
from aave_api import aave_api

# --- Logging Setup ---
logging.basicConfig(filename='defi_dashboard_v2.log', level=logging.INFO,
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

# --- NEW API-BASED DATA FETCHING (REPLACES SELENIUM) ---
def fetch_wallet_data(wallet_address):
    """
    Fetch wallet data using API instead of Selenium scraping
    Returns data in the same format as the original function
    """
    try:
        logging.info(f"API_FETCH: Getting data for {wallet_address}")
        
        # Get data from our API client
        api_data = aave_api.get_wallet_data(wallet_address)
        
        # Convert to the format expected by the GUI
        data = {
            "health_factor": api_data.get('health_factor', 'N/A'),
            "total_borrowed": api_data.get('total_borrowed', 'N/A'),
            "available_to_borrow": api_data.get('available_to_borrow', 'N/A'),
            "supply": api_data.get('supplied_value', 'N/A'),
            "networth": api_data.get('net_worth', 'N/A'),
            # Map liquidation data from API
            "liquidation_item_1_coin": api_data.get('liquidation_item_1_coin', 'N/A'),
            "liquidation_item_1_price": api_data.get('liquidation_item_1_price', 'N/A'),
            "liquidation_item_2_coin": api_data.get('liquidation_item_2_coin', 'N/A'),
            "liquidation_item_2_price": api_data.get('liquidation_item_2_price', 'N/A')
        }
        
        logging.info(f"API_FETCH: Successfully fetched data for {wallet_address}")
        return data
        
    except Exception as e:
        logging.error(f"API_FETCH Error for {wallet_address}: {e}", exc_info=True)
        return {
            "health_factor": "Error",
            "total_borrowed": "Error", 
            "available_to_borrow": "Error",
            "supply": "Error",
            "networth": "Error",
            "liquidation_item_1_coin": "Error",
            "liquidation_item_1_price": "Error",
            "liquidation_item_2_coin": "Error",
            "liquidation_item_2_price": "Error",
            "error": "API Error"
        }

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
        if not table: table = soup.select_one("div[class*='cmc-body-wrapper'] table")
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
                if not name_el: name_el = name_cell.find('p', class_=lambda x: x and 'sc-' in x and 'Text' in x)
                if not name_el: name_el = name_cell.select_one('a div p')
                if not name_el: name_el = name_cell.find('p')
                name = name_el.text.strip() if name_el else "N/A"
                price_cell = cells[3]; price_el = price_cell.find('span');
                if not price_el : price_el = price_cell.select_one('div > a > span')
                if not price_el : price_el = price_cell.select_one('div > span')
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

        rows = soup.find_all('tr', attrs={'data-hx-boost': 'false'})
        logging.info(f"CRYPTO_TOP50: Found {len(rows)} rows using 'tr[data-hx-boost=false]'.")

        if not rows:
            logging.warning("CRYPTO_TOP50: No coin rows found with the specified selector.")
            return [{"error": "No coin rows found on CoinRanking"}]

        for i, row in enumerate(rows[:50]):
            try:
                rank_el = row.find('td', class_='semibold small align-center')
                rank = rank_el.text.strip() if rank_el else f"{i+1}"

                name_el = row.select_one('a.coin-profile span.coin-profile__name')
                name = name_el.text.strip() if name_el else "N/A"

                price_el = row.find('real-time-price')
                price_text = price_el.text.strip() if price_el else "N/A"
                price = f"${price_text}" if price_text != "N/A" and not price_text.startswith('$') else price_text

                if name != "N/A" and price_text != "N/A":
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
            logging.info(f"CRYPTO_TOP100: Page {page_num}: Found {len(rows)} rows.")
            all_fetched_rows_count += len(rows)

            for i, row in enumerate(rows):
                if len(results) >= 100: break
                try:
                    rank_el = row.find('td', class_='semibold small align-center')
                    rank = rank_el.text.strip() if rank_el else str(len(results) + 1)

                    name_el = row.select_one('a.coin-profile span.coin-profile__name')
                    name = name_el.text.strip() if name_el else "N/A"

                    price_el = row.find('real-time-price')
                    price_text = price_el.text.strip() if price_el else "N/A"
                    price = f"${price_text}" if price_text != "N/A" and not price_text.startswith('$') else price_text

                    if name != "N/A" and price_text != "N/A":
                        results.append({'rank': rank, 'name': name, 'price': price})
                    else:
                        logging.debug(f"CRYPTO_TOP100: Page {page_num} Row {i+1}: Incomplete data (Name: {name}, Price: {price_text})")

                except Exception as e_row:
                    logging.error(f"CRYPTO_TOP100: Page {page_num} Row {i+1} Error: {e_row}")

            time.sleep(0.5)

        if not results:
            logging.warning(f"CRYPTO_TOP100: No data parsed from {all_fetched_rows_count} rows across pages.")
            return [{"error": "No valid data parsed from CoinRanking"}]

    except requests.exceptions.RequestException as e_req:
        logging.error(f"CRYPTO_TOP100: Request Error: {e_req}"); return [{"error": f"Network Error: {e_req}"}]
    except Exception as e:
        logging.exception(f"CRYPTO_TOP100: General error: {e}"); return [{"error": f"Failed to fetch Top 100: {e}"}]

    logging.info(f"CRYPTO_TOP100: Successfully fetched {len(results)} items."); return results

# --- MAIN GUI CLASS (EXACT COPY OF V1.3 LAYOUT) ---
class WalletDashboardGUI(tk.Tk):
    ESTIMATED_CARD_WIDTH = 290; CARD_PADDING_X = 7; CARD_PADDING_Y = 7
    def __init__(self):
        super().__init__()
        self.title("DeFi Dashboard v2.0 - API Edition")
        self.geometry("1400x850")
        self.configure(bg=BG_COLOR)
        self.logo_image_tk=None; self.wallet_frames={}; self.no_wallets_label=None
        self.after_id=None; self.data_queue=queue.Queue()
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
        
        self._create_widgets()
        self._initial_dashboard_load()
        self.after(200, self._load_initial_crypto_data)
        self.after(300, self._check_crypto_queue)
        self.after(400, self._schedule_crypto_refresh)
        self.protocol("WM_DELETE_WINDOW", self._close_app)

    def _get_password(self): 
        return simpledialog.askstring("Password", "Enter password:", show='*', parent=self)

    def _initial_dashboard_load(self):
        logging.info("GUI: Starting initial API data load...")
        if self.wallets_data_list: self._refresh_data_threaded()
        else: self._show_no_wallets_message()

    def _create_widgets(self):
        # Logo loading (exactly like v1.3)
        try:
            logo_file_path=resource_path("logo_raw_b64.txt");
            with open(logo_file_path,"r") as f:b64_str=f.read().strip()
            if not b64_str:raise ValueError("Logo file empty.")
            img_data=base64.b64decode(b64_str);stream=io.BytesIO(img_data);img=Image.open(stream).resize((220,107),Image.Resampling.LANCZOS)
            self.logo_image_tk=ImageTk.PhotoImage(img);tk.Label(self,image=self.logo_image_tk,bg=BG_COLOR).pack(pady=10,side=tk.TOP)
        except Exception as e:logging.error(f"Logo Error: {e}",exc_info=True);tk.Label(self,text="Logo Error",bg=BG_COLOR,fg="red").pack(pady=10,side=tk.TOP)
        
        # Main content frame setup (exactly like v1.3)
        self.main_content_frame=tk.Frame(self,bg=BG_COLOR);self.main_content_frame.pack(padx=10,pady=0,fill=tk.BOTH,expand=True,side=tk.TOP)
        self.main_content_frame.grid_columnconfigure(0,weight=1,minsize=350,uniform='panel');self.main_content_frame.grid_columnconfigure(1,weight=3,uniform='panel')
        self.main_content_frame.grid_rowconfigure(0,weight=0);self.main_content_frame.grid_rowconfigure(1,weight=1);self.main_content_frame.grid_rowconfigure(2,weight=0)
        
        # Headers
        tk.Label(self.main_content_frame,text="Price Tracker",font=self.heading_font,bg=BG_COLOR,fg=FG_COLOR).grid(row=0,column=0,pady=(5,2),sticky='n')
        tk.Label(self.main_content_frame,text="Aave Dashboard",font=self.heading_font,bg=BG_COLOR,fg=FG_COLOR).grid(row=0,column=1,pady=(5,2),sticky='n')
        
        # Crypto panel (left column)
        self.crypto_panel_frame=tk.Frame(self.main_content_frame,bd=1,relief=tk.SOLID,padx=10,pady=10,bg=BG_COLOR,highlightbackground=BORDER_COLOR,highlightthickness=1)
        self.crypto_panel_frame.grid(row=1,column=0,padx=(0,5),pady=(0,5),sticky='nsew')
        self.crypto_display_text=tk.Text(self.crypto_panel_frame,bg=TEXT_AREA_BG_COLOR,fg=FG_COLOR,font=self.crypto_display_font,relief=tk.FLAT,wrap=tk.WORD,state=tk.DISABLED,bd=0,highlightthickness=0,height=10)
        self.crypto_display_text.pack(fill=tk.BOTH,expand=True,pady=(0,10),side=tk.TOP)
        
        # Crypto dropdown setup
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
        
        # Aave cards canvas (right column)
        aave_canvas_container=tk.Frame(self.main_content_frame,bg=BG_COLOR);aave_canvas_container.grid(row=1,column=1,padx=(5,0),pady=(0,5),sticky='nsew')
        aave_canvas_container.grid_rowconfigure(0,weight=1);aave_canvas_container.grid_columnconfigure(0,weight=1)
        self.aave_cards_canvas=tk.Canvas(aave_canvas_container,bg=BG_COLOR,highlightthickness=0);self.aave_cards_canvas.grid(row=0,column=0,sticky='nsew')
        aave_scrollbar=ttk.Scrollbar(aave_canvas_container,orient="vertical",command=self.aave_cards_canvas.yview);aave_scrollbar.grid(row=0,column=1,sticky='ns');self.aave_cards_canvas.configure(yscrollcommand=aave_scrollbar.set)
        self.aave_scrollable_cards_frame=tk.Frame(self.aave_cards_canvas,bg=BG_COLOR);self.aave_canvas_window=self.aave_cards_canvas.create_window((0,0),window=self.aave_scrollable_cards_frame,anchor="nw")
        self.aave_scrollable_cards_frame.bind("<Configure>",self._on_configure_scrollable_area);self.aave_cards_canvas.bind("<Configure>",self._on_canvas_configure)
        self.aave_cards_canvas.bind('<Enter>',lambda e,w=self.aave_cards_canvas:self._bind_mousewheel(e,w));self.aave_cards_canvas.bind('<Leave>',lambda e,w=self.aave_cards_canvas:self._unbind_mousewheel(e,w))
        
        # Button bar
        self.button_style={"bg":BUTTON_BG_COLOR,"fg":BUTTON_FG_COLOR,"activebackground":BUTTON_ACTIVE_BG_COLOR,"activeforeground":BUTTON_FG_COLOR,"relief":tk.FLAT,"padx":10,"pady":5,"font":("Arial",10,"bold")}
        aave_btn_bar=tk.Frame(self.main_content_frame,bg=BG_COLOR);aave_btn_bar.grid(row=2,column=1,sticky='n',pady=(5,10))
        aave_inner_btn=tk.Frame(aave_btn_bar,bg=BG_COLOR);aave_inner_btn.pack(anchor=tk.CENTER)
        self.add_wallet_btn=tk.Button(aave_inner_btn,text="Add Aave Wallet",command=self._add_new_wallets,**self.button_style);self.add_wallet_btn.pack(side=tk.LEFT,padx=5,pady=5)
        self.refresh_aave_btn=tk.Button(aave_inner_btn,text="Refresh Aave Data",command=self._refresh_data_threaded,**self.button_style);self.refresh_aave_btn.pack(side=tk.LEFT,padx=5,pady=5)
        self.remove_wallet_btn=tk.Button(aave_inner_btn,text="Remove Aave Wallet",command=self._open_remove_dialog,**self.button_style);self.remove_wallet_btn.pack(side=tk.LEFT,padx=5,pady=5)
        self.rename_wallet_btn=tk.Button(aave_inner_btn,text="Rename Wallets",command=self._open_rename_dialog,**self.button_style);self.rename_wallet_btn.pack(side=tk.LEFT,padx=5,pady=5)

    # Canvas and scroll handling methods (exact copy from v1.3)
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

    # Data fetching and rendering methods
    def _refresh_data_threaded(self):
        if hasattr(self,'refresh_aave_btn') and self.refresh_aave_btn: self.refresh_aave_btn.config(state=tk.DISABLED,text="Fetching...")
        self._clear_wallet_cards()
        threading.Thread(target=self._fetch_aave_data_background,daemon=True).start()
        self.after(100, self._check_data_queue)

    def _fetch_aave_data_background(self):
        wallet_data_results = {}
        for wallet_info in self.wallets_data_list:
            try:
                addr = wallet_info['address']
                logging.info(f"BACKGROUND: Fetching data for {addr}")
                fetched_data = fetch_wallet_data(addr)
                wallet_data_results[addr] = {'info': wallet_info, 'fetched': fetched_data}
                time.sleep(0.2)  # Small delay between API calls
            except Exception as e:
                logging.error(f"Background fetch error for {wallet_info['address']}: {e}")
                wallet_data_results[wallet_info['address']] = {'info': wallet_info, 'fetched': {'error': 'Fetch Error'}}
        
        self.data_queue.put(wallet_data_results)

    def _check_data_queue(self):
        try:
            wallet_data_results = self.data_queue.get_nowait()
            self._render_dashboard_gui(wallet_data_results)
        except queue.Empty:
            self.after(100, self._check_data_queue)

    def _render_dashboard_gui(self, all_render_data):
        if not all_render_data:
            self._show_no_wallets_message()
            return
        
        self.last_aave_render_data = all_render_data
        self._clear_wallet_cards()
        
        if hasattr(self,'refresh_aave_btn') and self.refresh_aave_btn: self.refresh_aave_btn.config(state=tk.DISABLED,text="Rendering...")
        
        # Calculate grid layout (same as v1.3)
        try:
            self.update_idletasks(); canvas_width = self.aave_cards_canvas.winfo_width()
            if canvas_width <= 1: canvas_width = getattr(self, '_last_aave_canvas_width', 800)
            self._last_aave_canvas_width = canvas_width
            est_card_width = self.ESTIMATED_CARD_WIDTH + (2 * self.CARD_PADDING_X); num_cols = max(1, canvas_width // est_card_width)
            logging.info(f"CanvasW: {canvas_width}, Est. card W: {est_card_width}, Cols: {num_cols}")
            for i in range(num_cols): self.aave_scrollable_cards_frame.grid_columnconfigure(i, weight=0)
            for i, wallet_info_orig in enumerate(self.wallets_data_list):
                 addr = wallet_info_orig['address']; render_d = all_render_data.get(addr)
                 if render_d:
                     row,col=i//num_cols, i%num_cols
                     card_f=self._create_wallet_card_widget(self.aave_scrollable_cards_frame,render_d['info'],render_d['fetched'])
                     card_f.grid(row=row,column=col,padx=self.CARD_PADDING_X,pady=self.CARD_PADDING_Y,sticky='nw')
                     self.wallet_frames[addr]=card_f
                 else: logging.error(f"Render: Data missing for {addr}")
        except Exception as e:
            logging.error(f"Error in render: {e}")
        
        if hasattr(self,'refresh_aave_btn') and self.refresh_aave_btn: self.refresh_aave_btn.config(state=tk.NORMAL,text="Refresh Aave Data")
        self.after(50, self._update_scroll_region_aave); self._schedule_refresh()

    def _create_wallet_card_widget(self, parent, wallet_info, fetched_data):
        """Create wallet card widget exactly like v1.3"""
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
        urll=tk.Label(frame,text="View on DefiSim",fg=LINK_COLOR,cursor="hand2",bg=BG_COLOR,font=self.link_font);urll.pack(anchor="w",pady=(8,0));urll.bind("<Button-1>",lambda e,addr=address:webbrowser.open_new_tab(f"https://defisim.xyz/?address={addr}"))
        return frame

    def _clear_wallet_cards(self):
        for widget in self.aave_scrollable_cards_frame.winfo_children():
            widget.destroy()
        self.wallet_frames = {}

    def _show_no_wallets_message(self):
        self._clear_wallet_cards()
        if hasattr(self, 'no_wallets_label') and self.no_wallets_label:
            self.no_wallets_label.destroy()
        self.no_wallets_label = tk.Label(self.aave_scrollable_cards_frame, text="No Aave wallets added yet.\nClick 'Add Aave Wallet' to get started.", font=self.regular_font, fg="#AAAAAA", bg=BG_COLOR, justify=tk.CENTER)
        self.no_wallets_label.pack(expand=True)

    def _schedule_refresh(self):
        if self.after_id: self.after_cancel(self.after_id); self.after_id = None
        interval_ms = 10*60*1000; logging.info(f"Scheduling Aave refresh: {interval_ms}ms")
        self.after_id=self.after(interval_ms, self._refresh_data_auto_threaded)

    def _refresh_data_auto_threaded(self):
        if self.wallets_data_list: logging.info("GUI: Auto-refresh Aave."); self._refresh_data_threaded()

    # Wallet management methods
    def _add_new_wallets(self):
        new_address = simpledialog.askstring("Add Aave Wallet", "Enter wallet address:", parent=self)
        if not new_address: return
        if not is_valid_address(new_address):
            messagebox.showerror("Invalid Address", "Please enter a valid address.", parent=self)
            return
        if any(w['address'].lower() == new_address.lower() for w in self.wallets_data_list):
            messagebox.showwarning("Duplicate", "Wallet already exists.", parent=self)
            return
        
        name = simpledialog.askstring("Wallet Name", "Enter wallet name (optional):", parent=self) or ""
        self.wallets_data_list.append({"address": new_address, "name": name})
        
        if save_wallets(self.wallets_data_list, self.password):
            messagebox.showinfo("Success", "Wallet added!", parent=self)
            self._refresh_data_threaded()
        else:
            messagebox.showerror("Error", "Failed to save wallet.", parent=self)

    def _open_remove_dialog(self):
        if not self.wallets_data_list: messagebox.showinfo("Info","No Aave wallets.",parent=self); return
        rd=tk.Toplevel(self);rd.title("Remove Aave Wallets");rd.configure(bg=BG_COLOR);rd.transient(self);rd.grab_set()
        # Center the dialog on the main window
        self.update_idletasks()
        dialog_width = 400; dialog_height = 300
        main_x = self.winfo_x(); main_y = self.winfo_y()
        main_width = self.winfo_width(); main_height = self.winfo_height()
        center_x = main_x + (main_width - dialog_width) // 2
        center_y = main_y + (main_height - dialog_height) // 2
        rd.geometry(f"{dialog_width}x{dialog_height}+{center_x}+{center_y}")
        self.remove_vars={}; cf=tk.Frame(rd,bg=BG_COLOR); cf.pack(padx=20,pady=10)
        cbs={"bg":BG_COLOR,"fg":FG_COLOR,"selectcolor":CHECKBOX_SELECT_COLOR,"activebackground":BG_COLOR,"activeforeground":FG_COLOR,"highlightthickness":0,"font":("Arial",10)}
        for i,w_info in enumerate(self.wallets_data_list):
             addr = w_info['address']; name = w_info.get('name', ''); display = name if name else f"{addr[:10]}...{addr[-8:]}"
             var=tk.BooleanVar(); tk.Checkbutton(cf,text=display,variable=var,**cbs).grid(row=i,column=0,sticky="w",padx=5,pady=3); self.remove_vars[addr]=var
        tk.Button(rd,text="Remove Selected",command=lambda:self._remove_selected_wallets(rd),**self.button_style).pack(pady=(5,15))

    def _remove_selected_wallets(self, dialog):
        to_rem={addr for addr,v in self.remove_vars.items() if v.get()}
        if to_rem:
            original_count=len(self.wallets_data_list); self.wallets_data_list=[w for w in self.wallets_data_list if w['address'] not in to_rem]; removed_count=original_count-len(self.wallets_data_list)
            if removed_count > 0:
                if not save_wallets(self.wallets_data_list,self.password): messagebox.showerror("Save Error","Failed save Aave.",parent=self)
                self._refresh_data_threaded(); messagebox.showinfo("Wallets Removed",f"Removed {removed_count} wallet(s).",parent=self)
        dialog.destroy();
        if not self.wallets_data_list:self._show_no_wallets_message()

    def _open_rename_dialog(self):
        if not self.wallets_data_list: messagebox.showinfo("Info","No Aave wallets to rename.",parent=self); return
        rd = tk.Toplevel(self); rd.title("Rename Aave Wallets"); rd.configure(bg=BG_COLOR); rd.transient(self); rd.grab_set()
        # Center the dialog on the main window
        self.update_idletasks()
        dialog_width = 600; dialog_height = 400
        main_x = self.winfo_x(); main_y = self.winfo_y()
        main_width = self.winfo_width(); main_height = self.winfo_height()
        center_x = main_x + (main_width - dialog_width) // 2
        center_y = main_y + (main_height - dialog_height) // 2
        rd.geometry(f"{dialog_width}x{dialog_height}+{center_x}+{center_y}")
        self.rename_entries = {}; cf=tk.Frame(rd,bg=BG_COLOR); cf.pack(padx=20,pady=10,fill=tk.BOTH,expand=True)
        for i,w_info in enumerate(self.wallets_data_list):
            addr = w_info['address']; name = w_info.get('name', '')
            tk.Label(cf,text=f"{addr[:20]}...",bg=BG_COLOR,fg=FG_COLOR,font=self.small_regular_font).grid(row=i,column=0,sticky="w",padx=5,pady=3)
            entry=tk.Entry(cf,bg=TEXT_AREA_BG_COLOR,fg=FG_COLOR,insertbackground=FG_COLOR,width=20,font=self.small_regular_font); entry.insert(0,name); entry.grid(row=i,column=1,sticky="ew",padx=5,pady=3); self.rename_entries[addr]=entry
        cf.grid_columnconfigure(1,weight=1)
        tk.Button(rd,text="Save Changes",command=lambda:self._save_rename_changes(rd),**self.button_style).pack(pady=(5,15))

    def _save_rename_changes(self, dialog):
        for w_info in self.wallets_data_list:
            addr = w_info['address']
            if addr in self.rename_entries:
                w_info['name'] = self.rename_entries[addr].get().strip()
        if save_wallets(self.wallets_data_list, self.password):
            messagebox.showinfo("Success", "Names updated!", parent=self)
            self._refresh_data_threaded()
        else:
            messagebox.showerror("Error", "Failed to save changes.", parent=self)
        dialog.destroy()

    # Crypto price tracker methods
    def _handle_crypto_tracker_action(self,action):
        logging.info(f"GUI: Crypto action: {action}")
        if action == "Choose action...": return
        action_map = {"Show My Tracked Coins": (fetch_prices_for_coins,True), "Add Coin to Track": (self._add_crypto_coin_dialog,False), "Remove Tracked Coin": (self._remove_crypto_coin_dialog,False), "Show Top 10 (CMC)": (fetch_top_10_cmc,False), "Show Top 50 (CR)": (fetch_top_50_cr,False), "Show Top 100 (CR)": (fetch_top_100_cr,False), "Refresh Current View": (self._refresh_crypto_view,False)}
        self.current_crypto_action = action
        if action in action_map:
            func, needs_list = action_map[action]
            if callable(func) and func not in [self._add_crypto_coin_dialog,self._remove_crypto_coin_dialog,self._refresh_crypto_view]:
                args = [load_tracked_crypto_coin_names()] if needs_list else []
                self._update_crypto_display(f"Loading {action}..."); threading.Thread(target=self._run_crypto_fetcher_threaded, args=(func,args,action),daemon=True).start()
            elif callable(func): func()
        self.after(100, lambda: self.crypto_action_var.set(self.crypto_actions[0]))

    def _run_crypto_fetcher_threaded(self, func, args, action_name):
        try:
            result = func(*args) if args else func()
            self.crypto_queue = queue.Queue()
            self.crypto_queue.put((action_name, result))
            self.after(0, self._process_crypto_result)
        except Exception as e:
            logging.error(f"Crypto fetch error: {e}")
            self.crypto_queue = queue.Queue()
            self.crypto_queue.put((action_name, [{"error": f"Error: {e}"}]))
            self.after(0, self._process_crypto_result)

    def _process_crypto_result(self):
        try:
            action_name, result = self.crypto_queue.get_nowait()
            if action_name == "Show My Tracked Coins":
                display_text = "\n".join([f"{coin}: {price}" for coin, price in result.items()]) if result else "No tracked coins."
            elif action_name in ["Show Top 10 (CMC)", "Show Top 50 (CR)", "Show Top 100 (CR)"]:
                if result and not any("error" in item for item in result):
                    display_text = "\n".join([f"{item['rank']}. {item['name']}: {item['price']}" for item in result])
                else:
                    display_text = f"Error fetching {action_name} data"
            else:
                display_text = str(result)
            self._update_crypto_display(display_text)
        except queue.Empty:
            pass

    def _update_crypto_display(self, text):
        self.crypto_display_text.config(state=tk.NORMAL)
        self.crypto_display_text.delete(1.0, tk.END)
        self.crypto_display_text.insert(tk.END, text)
        self.crypto_display_text.config(state=tk.DISABLED)

    def _add_crypto_coin_dialog(self):
        coin = simpledialog.askstring("Add Cryptocurrency", "Enter coin name (e.g., bitcoin, ethereum):", parent=self)
        if coin:
            tracked = load_tracked_crypto_coin_names()
            if coin.lower() not in tracked:
                tracked.append(coin.lower())
                save_tracked_crypto_coin_names(tracked)
                messagebox.showinfo("Success", f"Added {coin}", parent=self)
            else:
                messagebox.showwarning("Duplicate", "Coin already tracked", parent=self)

    def _remove_crypto_coin_dialog(self):
        tracked = load_tracked_crypto_coin_names()
        if not tracked:
            messagebox.showinfo("No Coins", "No coins tracked", parent=self)
            return
        coin = simpledialog.askstring("Remove Coin", f"Enter coin to remove from: {', '.join(tracked)}", parent=self)
        if coin and coin.lower() in tracked:
            tracked.remove(coin.lower())
            save_tracked_crypto_coin_names(tracked)
            messagebox.showinfo("Success", f"Removed {coin}", parent=self)

    def _refresh_crypto_view(self):
        if hasattr(self, 'current_crypto_action') and self.current_crypto_action:
            self._handle_crypto_tracker_action(self.current_crypto_action)
        else:
            self._handle_crypto_tracker_action("Show My Tracked Coins")

    def _load_initial_crypto_data(self):
        tracked = load_tracked_crypto_coin_names()
        if tracked:
            self._handle_crypto_tracker_action("Show My Tracked Coins")
        else:
            self._update_crypto_display("No cryptocurrency data yet.\nUse the dropdown to add coins or view top coins.")

    def _check_crypto_queue(self):
        if hasattr(self, 'crypto_queue'):
            try:
                self._process_crypto_result()
            except:
                pass
        self.after(500, self._check_crypto_queue)

    def _schedule_crypto_refresh(self):
        if self.after_id_crypto_refresh: self.after_cancel(self.after_id_crypto_refresh)
        self.after_id_crypto_refresh = self.after(300000, lambda: self._handle_crypto_tracker_action("Show My Tracked Coins"))  # 5 minutes

    def _close_app(self):
        logging.info("GUI: Closing app...")
        if self.after_id: self.after_cancel(self.after_id)
        if self.after_id_crypto_refresh: self.after_cancel(self.after_id_crypto_refresh)
        self.destroy()

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    try:
        app = WalletDashboardGUI()
        app.mainloop()
    except Exception as e:
        logging.error(f"App error: {e}", exc_info=True)
    finally:
        logging.info("App shutdown complete")