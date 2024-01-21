import requests
import json
import pycountry
import pandas as pd
import tkinter as tk
from tkinter import messagebox
from pandastable import Table, TableModel
import threading
import queue
import ipaddress

# Define the column headers for the data table
COLUMN_HEADERS = ['IP Address', 'Abuse Confidence Score', 'ISP', 'Country', 'OTX_Malicious Count']

data_queue = queue.Queue()
data_table = []

def get_otx_data(ip):
    api_key = '9b49d5c8ccf3e99705ed62153bd7583df6f0648f9097620752312affe76cd85c'  # Replace with your OTX API key
    url = f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general'
    headers = {'X-OTX-API-KEY': api_key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            malicious_count = data['pulse_info']['count']
            return malicious_count
        else:
            return None
    except requests.RequestException as e:
        print(f"Error fetching OTX data: {e}")
        return None

def get_ipabuse_dat(ip):
    try:
        otx_malicious_count = get_otx_data(ip)
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {
            'ipAddress': ip,
            'maxAgeInDays': '90'
        }
        headers = {
            'Accept': 'application/json',
            'Key': 'a16d336f0c8cf90316a674a89588eece5b3b125de595043ba0ab40d9b0164fd79f25c97e3597087e'  # Replace with your API key
        }
        response = requests.get(url, headers=headers, params=querystring)
        decodedResponse = json.loads(response.text)

        country = pycountry.countries.get(alpha_2=decodedResponse["data"]["countryCode"])
        data = {
            'IP Address': decodedResponse["data"]["ipAddress"],
            'Abuse Confidence Score': decodedResponse["data"]["abuseConfidenceScore"],
            'ISP': decodedResponse["data"]["isp"],
            'Country': country.name if country else 'Unknown',
            'OTX_Malicious Count': otx_malicious_count
        }
        data_queue.put(data)
    except requests.RequestException as e:
        print(f"Error fetching AbuseIPDB data: {e}")
        messagebox.showerror("Network Error", f"An error occurred while fetching data: {e}")

def update_ui():
    while not data_queue.empty():
        data = data_queue.get()
        data_table.append(data)
    
    if data_table:
        df = pd.DataFrame(data_table, columns=COLUMN_HEADERS)
        table.model = TableModel(dataframe=df)
        table.redraw()
    
    root.after(1000, update_ui)

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def on_enter_key(event):
    current_line = ip_text.get("insert linestart", "insert lineend").strip()
    if is_valid_ip(current_line) or not current_line:
        ip_text.insert("insert", "\n")
        return 'break'

def fetch_data():
    ip_data = ip_text.get("1.0", tk.END).strip()
    ip_list = [ip.strip() for ip in ip_data.splitlines() if ip.strip()]
    
    invalid_ips = [ip for ip in ip_list if not is_valid_ip(ip)]
    if invalid_ips:
        error_message = "The following are not valid IP addresses:\n" + "\n".join(invalid_ips)
        messagebox.showerror("Invalid IP Address", error_message)
        return

    data_table.clear()
    for ip in ip_list:
        threading.Thread(target=get_ipabuse_dat, args=(ip,)).start()

# Custom Table class to modify menu options
class CustomTable(Table):
    def setupMenu(self):
        super(CustomTable, self).setupMenu()
        # Remove Import and Export menu options
        self.popupMenu.delete("Import")
        self.popupMenu.delete("Export")

root = tk.Tk()
root.title("IP Threat Intelligence Tool")

ip_text = tk.Text(root, height=10, width=50)
ip_text.pack()
ip_text.bind('<Return>', on_enter_key)

fetch_button = tk.Button(root, text="Fetch Data", command=fetch_data)
fetch_button.pack()

frame = tk.Frame(root)
frame.pack(fill='both', expand=True)
df = pd.DataFrame([], columns=COLUMN_HEADERS)

# Try-catch block for instantiating CustomTable
try:
    table = CustomTable(frame, dataframe=df, showtoolbar=True, showstatusbar=True)
except TypeError as e:
    if 'warn_bad_lines' in str(e):
        print("Caught incompatible argument error in pandastable.")
    else:
        raise
table.show()

root.after(1000, update_ui)

root.mainloop()
