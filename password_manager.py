import warnings
warnings.filterwarnings("ignore") 

import json
import os
import sys
import base64
import secrets 
import string
import time
import threading
import subprocess 
import atexit 
from datetime import datetime
from zxcvbn import zxcvbn 

import pyperclip 
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- 1. SETUP & FOLDER STRUCTURE (VAKIOINTI) ---

if getattr(sys, 'frozen', False):
    APP_PATH = os.path.dirname(sys.executable)
else:
    APP_PATH = os.path.dirname(os.path.abspath(__file__))

# Määritellään alikansiot
DB_DIR      = os.path.join(APP_PATH, "databases")
LOG_DIR     = os.path.join(APP_PATH, "logs")
BACKUP_DIR  = os.path.join(APP_PATH, "backups")

# Määritellään tiedostot
LOG_FILE  = os.path.join(LOG_DIR, "history.log")
LOCK_FILE = os.path.join(DB_DIR, "app.lock") # Lukko piilotetaan db-kansioon

def init_folders():
    """Luo tarvittavat kansiot automaattisesti, jos ne puuttuvat."""
    for folder in [DB_DIR, LOG_DIR, BACKUP_DIR]:
        if not os.path.exists(folder):
            try:
                os.makedirs(folder)
                print(f"Created system folder: {folder}")
            except Exception as e:
                print(f"Error creating folder {folder}: {e}")

# --- SINGLE INSTANCE LOCK ---
def acquire_lock():
    if os.path.exists(LOCK_FILE):
        print(f"\n[ERROR] App is locked. Check '{LOCK_FILE}'")
        sys.exit()
    try:
        with open(LOCK_FILE, 'w') as f: f.write("locked")
    except: pass

def release_lock():
    if os.path.exists(LOCK_FILE):
        try: os.remove(LOCK_FILE)
        except: pass

atexit.register(release_lock)

# --- PERMISSIONS ---
def restrict_file_permissions(filepath):
    if os.name != 'nt' or not os.path.exists(filepath): return
    try:
        cmd = f'icacls "{filepath}" /inheritance:r /grant:r "%USERNAME%":F /grant:r *S-1-5-32-544:F'
        subprocess.run(cmd, check=True, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except: pass

# --- SECURITY CORE ---
def check_master_strength(password):
    res = zxcvbn(password)
    if res['score'] < 3:
        print(f"\n[WEAK] Score: {res['score']}/4. {res['feedback']['warning']}")
        return False
    return True

def derive_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def load_data(filepath, master_password):
    if not os.path.exists(filepath): return {}, None 
    try:
        with open(filepath, "rb") as f:
            content = f.read()
        salt, enc_data = content[:16], content[16:]
        key = derive_key(master_password, salt)
        cipher = Fernet(key)
        return json.loads(cipher.decrypt(enc_data).decode()), salt
    except: return None, None

def save_data(filepath, data, master_password, salt=None):
    if salt is None: salt = os.urandom(16)
    key = derive_key(master_password, salt)
    cipher = Fernet(key)
    try:
        enc_data = cipher.encrypt(json.dumps(data, indent=2).encode())
        with open(filepath, "wb") as f: f.write(salt + enc_data)
        restrict_file_permissions(filepath)
    except Exception as e: print(f"\n[ERROR] Save failed: {e}")
    return salt

# --- TOOLS ---
def log_action(action):
    try:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a", encoding="utf-8") as f: f.write(f"[{ts}] {action}\n")
        restrict_file_permissions(LOG_FILE)
    except: pass

def copy_to_clipboard_secure(text):
    def clear(): time.sleep(30); pyperclip.copy("")
    try:
        pyperclip.copy(text)
        print("(Copied to clipboard. Clears in 30s.)")
        threading.Thread(target=clear, daemon=True).start()
    except: pass

def generate_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(chars) for _ in range(length))

# --- DATABASE MANAGEMENT ---
def select_database_file():
    """Listaa tiedostot 'databases'-alikansiosta."""
    while True:
        files = [f for f in os.listdir(DB_DIR) if f.endswith('.json')]
        print(f"\n--- SELECT DATABASE (Folder: {DB_DIR}) ---")
        if not files: print("(No databases yet)")
        
        for i, f in enumerate(files, 1): print(f"[{i}] {f}")
        print(f"[{len(files)+1}] Create New Database")
        
        choice = input("> ").strip()
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(files):
                return os.path.join(DB_DIR, files[idx])
            elif idx == len(files):
                new = input("New filename: ").strip()
                if not new: continue
                if not new.endswith(".json"): new += ".json"
                return os.path.join(DB_DIR, new)

# --- IMPORT / EXPORT ---
def export_database(current_data, current_pwd):
    """Tallentaa varmuuskopion 'backups'-kansioon."""
    print("\n--- EXPORT TO BACKUPS ---")
    name = input("Backup filename (e.g. 'safe_copy'): ").strip()
    if not name: return
    if not name.endswith(".json"): name += ".json"
    
    # Tallennetaan BACKUP_DIR kansioon
    path = os.path.join(BACKUP_DIR, name)
    save_data(path, current_data, current_pwd)
    print(f"Backup saved to: {path}")
    log_action(f"Backup created: {name}")

def import_database(current_data, current_pwd, current_salt, db_filepath):
    print("\n--- IMPORT DATA ---")
    # Käyttäjä voi antaa täyden polun tai vain nimen (oletus: databases-kansio)
    target = input("File to import (path or filename in databases/): ").strip()
    
    # Tarkistetaan onko se databases-kansiossa
    if os.path.exists(os.path.join(DB_DIR, target)):
        target_path = os.path.join(DB_DIR, target)
    # Tarkistetaan onko se backups-kansiossa
    elif os.path.exists(os.path.join(BACKUP_DIR, target)):
        target_path = os.path.join(BACKUP_DIR, target)
    # Tarkistetaan onko se täysi polku
    elif os.path.exists(target):
        target_path = target
    else:
        print("File not found.")
        return

    target_pwd = input(f"Enter MASTER PASSWORD for '{os.path.basename(target_path)}': ").strip()
    imported_data, _ = load_data(target_path, target_pwd)
    
    if imported_data is None:
        print("Import failed.")
        return
    
    count = 0
    for k, v in imported_data.items():
        if k not in current_data:
            current_data[k] = v
            count += 1
            
    save_data(db_filepath, current_data, current_pwd, current_salt)
    print(f"Imported {count} items.")
    log_action(f"Imported {count} items from {os.path.basename(target_path)}")

# --- MAIN ---
def main():
    # 1. Init folders
    init_folders()
    acquire_lock()
    
    print("="*30)
    print("  PASSWORD MANAGER: ORGANIZED")
    print("="*30)
    
    try:
        db_path = select_database_file()
        
        # Login Logic
        if not os.path.exists(db_path):
            print(f"Creating: {os.path.basename(db_path)}")
            while True:
                pwd = input("Set MASTER PASSWORD: ").strip()
                if not pwd: continue
                if check_master_strength(pwd):
                    if input("Confirm: ") == pwd:
                        data, master_pwd, salt = {}, pwd, None
                        break
                    print("Mismatch.")
        else:
            print(f"Opening: {os.path.basename(db_path)}")
            attempts = 0
            while attempts < 3:
                pwd = input(f"Password ({attempts+1}/3): ").strip()
                data, salt = load_data(db_path, pwd)
                if data is not None:
                    master_pwd = pwd
                    log_action(f"Login: {os.path.basename(db_path)}")
                    break
                attempts += 1
                time.sleep(2)
            else:
                print("Locked out."); sys.exit()

        print("\nAccess Granted.")
        while True:
            print("\n[1] Add    [2] Get    [3] List")
            print("[4] Delete [5] Backup [6] Import")
            print("[7] Gen PW [8] History [Q] Quit")
            c = input("> ").strip().lower()
            
            if c == '1': 
                t = input("Title: ").strip()
                if t:
                    u = input("User: ")
                    p = generate_password() if input("Gen? (y/n): ")=='y' else input("Pass: ")
                    data[t] = {"url": "", "username": u, "password": p}
                    salt = save_data(db_path, data, master_pwd, salt)
                    print("Saved.")
            elif c == '2':
                s = input("Search: ").lower()
                for k,v in data.items():
                    if s in k.lower():
                        print(f"\n{k} | {v['username']}")
                        copy_to_clipboard_secure(v['password'])
            elif c == '3':
                for i,k in enumerate(sorted(data.keys()),1): print(f"{i}. {k}")
            elif c == '4':
                t = input("Delete: ")
                if t in data:
                    del data[t]; save_data(db_path, data, master_pwd, salt)
                    print("Deleted.")
            elif c == '5': export_database(data, master_pwd)
            elif c == '6': import_database(data, master_pwd, salt, db_path)
            elif c == '7': p=generate_password(); print(p); copy_to_clipboard_secure(p)
            elif c == '8': 
                if os.path.exists(LOG_FILE):
                    with open(LOG_FILE) as f: print(f.read()[-500:])
            elif c in ('q', 'quit'): break

    except KeyboardInterrupt: print("\nBye.")
    except Exception as e: print(f"Error: {e}"); input()
    finally: release_lock()

if __name__ == "__main__":
    main()