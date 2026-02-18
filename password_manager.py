import warnings
warnings.filterwarnings("ignore") 

import json
import os
import base64
import sys
import secrets 
import string
import pyperclip 
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# 2. DETERMINE PATH (Makes it truly portable on USBs)
if getattr(sys, 'frozen', False):
    # If running as compiled .exe
    application_path = os.path.dirname(sys.executable)
else:
    # If running as python script
    application_path = os.path.dirname(os.path.abspath(__file__))

DATA_FILE = os.path.join(application_path, "my_passwords.json")

# --- CORE SECURITY LOGIC ---
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def load_data(master_password):
    if not os.path.exists(DATA_FILE):
        return {}, None 

    try:
        with open(DATA_FILE, "rb") as f:
            file_content = f.read()
        
        salt = file_content[:16]
        encrypted_data = file_content[16:]
        
        key = derive_key(master_password, salt)
        cipher = Fernet(key)
        
        decrypted_data = cipher.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode()), salt
    except Exception:
        return None, None

def save_data(data, master_password, salt=None):
    if salt is None:
        salt = os.urandom(16)
        
    key = derive_key(master_password, salt)
    cipher = Fernet(key)
    
    json_string = json.dumps(data, indent=2)
    encrypted_data = cipher.encrypt(json_string.encode())
    
    with open(DATA_FILE, "wb") as f:
        f.write(salt + encrypted_data)
    
    return salt

# --- UTILITIES ---
def generate_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    pwd = ''.join(secrets.choice(chars) for _ in range(length))
    return pwd

# --- MENU ACTIONS ---
def add_entry(data, master_pwd, current_salt):
    print("\n--- ADD NEW ---")
    title = input("Title / Site: ").strip()
    if not title: return current_salt
    
    url = input("URL (optional): ").strip()
    user = input("Username: ").strip()
    
    choice = input("Generate strong password? (y/n): ").lower()
    if choice == 'y':
        pwd = generate_password()
        print(f"Generated: {pwd}")
    else:
        pwd = input("Password: ").strip()

    data[title] = {"url": url, "username": user, "password": pwd}
    
    new_salt = save_data(data, master_pwd, current_salt)
    print(f"Saved: {title}")
    return new_salt

def get_entry(data):
    print("\n--- GET PASSWORD ---")
    search = input("Search site name: ").strip().lower()
    
    found = False
    for title, info in data.items():
        if search in title.lower():
            print(f"\n--- {title} ---")
            print(f"URL:  {info['url']}")
            print(f"User: {info['username']}")
            print(f"Pass: {info['password']}")
            try:
                pyperclip.copy(info['password'])
                print("(Password copied to clipboard!)")
            except:
                pass
            found = True
    
    if not found:
        print("No matches found.")

def delete_entry(data, master_pwd, current_salt):
    print("\n--- DELETE ---")
    title = input("Exact site title to delete: ").strip()
    if title in data:
        del data[title]
        save_data(data, master_pwd, current_salt)
        print(f"Deleted {title}.")
    else:
        print("Site not found.")

def list_sites(data):
    print("\n--- SAVED SITES ---")
    if not data:
        print("(Empty)")
    for i, title in enumerate(sorted(data.keys()), 1):
        print(f"{i}. {title}")

# --- MAIN LOOP ---
def main():
    print("="*30)
    print("  SECURE PASSWORD MANAGER")
    print("="*30)
    
    if os.path.exists(DATA_FILE):
        master_pwd = input("ENTER MASTER PASSWORD: ").strip()
        data, salt = load_data(master_pwd)
        
        if data is None:
            print("\n!!! ACCESS DENIED !!!")
            input("Press Enter to exit...")
            return
    else:
        print("No database found. Creating new setup.")
        master_pwd = input("Create a MASTER PASSWORD: ").strip()
        if not master_pwd:
            print("Password cannot be empty.")
            return
        data = {}
        salt = None 

    while True:
        print("\n[1] Add New   [2] Get/Search   [3] List All")
        print("[4] Delete    [5] Generate Only  [Q] Quit")
        choice = input("> ").strip().lower()
        
        if choice == '1':
            salt = add_entry(data, master_pwd, salt)
        elif choice == '2':
            get_entry(data)
        elif choice == '3':
            list_sites(data)
        elif choice == '4':
            delete_entry(data, master_pwd, salt)
        elif choice == '5':
            p = generate_password()
            print(f"\nGenerated: {p}")
            pyperclip.copy(p)
            print("(Copied to clipboard)")
        elif choice in ('q', 'quit', 'exit'):
            break

if __name__ == "__main__":
    main()