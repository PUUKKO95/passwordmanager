"""Turvallinen salasananhallinta komentorivillä.

Tämä skripti toteuttaa yksinkertaisen salasananhallinnan, joka salaa
JSON‑tietokannan käyttäjän antamalla pääsalasanalla. Tiedosto
``my_passwords.json`` sijaitsee aina ajettavan ohjelman tai skriptin
vieressä, ja sen sisällä on 16 tavua suolaa, jota seuraa Fernet‑salattu
JSON‑neste.

Riippuvuudet
------------
* Python 3.6+
* ``cryptography`` ja ``pyperclip`` (asennus: ``pip install cryptography pyperclip``)

Käännös
-------
Luodaksesi itsenäisen Windowsin suoritettavan tiedoston PyInstallerilla:

    python -m PyInstaller --onefile --name="PassManager" password_manager.py

Tuloksena syntyvää ``PassManager.exe``-tiedostoa voi jakaa ilman erillistä
Python‑asennusta.
"""
import warnings
# piilotetaan harmittomat varoitukset (esim. 32/64-bittiset) siistimmän konsolin vuoksi
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

# --- TIEDOSTOPOLUN MÄÄRITYS ---
# Varmistetaan, että 'my_passwords.json' luodaan aina samaan hakemistoon
# missä ohjelma (exe tai skripti) sijaitsee.
if getattr(sys, 'frozen', False):
    # Jos ohjelmaa ajetaan käännettynä .exe-tiedostona:
    application_path = os.path.dirname(sys.executable)
else:
    # Jos ohjelmaa ajetaan tavallisena Python‑skriptinä (.py):
    application_path = os.path.dirname(os.path.abspath(__file__))

# Yhdistetään kansion polku ja tiedoston nimi
DATA_FILE = os.path.join(application_path, "my_passwords.json")

# --- TIETOTURVA JA SALAUS ---

def derive_key(password: str, salt: bytes) -> bytes:
    """Johdetaan 32‑tavua pitkä Fernet‑avain salasanasta ja suolasta.

    Käytetään PBKDF2‑HMAC(SHA256):a 100 000 iteraatiolla; palautettu avain
    on base64‑url‑turvallinen ja yhteensopiva ``cryptography.Fernet``-kirjaston
    kanssa.

    :param password: käyttäjän antama pääsalasana
    :param salt: 16 tavun satunnainen suola, luetaan tai kirjoitetaan levylle
    :return: Fernet‑yhteensopivat base64‑koodatut avain‑tavut
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,  # vaikeuttaa brute-force -hyökkäyksiä huomattavasti
        iterations=100000,
    )
    # Fernet vaatii base64-koodatun 32-tavuisen avaimen
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def load_data(master_password: str) -> tuple[dict, bytes] | tuple[None, None]:
    """Lataa ja purkaa salasanasanakirja.

    Tiedoston odotetaan sisältävän 16 tavua suolaa, jota seuraa
    Fernet-salattu JSON‑data. Jos tiedostoa ei ole, palautetaan tyhjä
    sanakirja ja ``None`` suolana; ``save_data`` luo silloin suolan.

    Jos purku epäonnistuu (väärä salasana tai korruptoitunut tiedosto),
    funktio palauttaa ``(None, None)`` merkkinä epäonnistumisesta.

    :param master_password: käyttäjän syöttämä pääsalasana
    :return: ``(tietosanakirja, suola)`` onnistuneesti, tai ``(None, None)`` epäonnistumisen
    """
    if not os.path.exists(DATA_FILE):
        return {}, None  # aloitetaan alusta, jos tiedostoa ei ole

    try:
        with open(DATA_FILE, "rb") as f:
            file_content = f.read()

        # tiedoston rakenne: [16 tavua suolaa] + [salattu sisältö]
        salt = file_content[:16]
        encrypted_data = file_content[16:]

        key = derive_key(master_password, salt)
        cipher = Fernet(key)
        decrypted_data = cipher.decrypt(encrypted_data)

        return json.loads(decrypted_data.decode()), salt
    except Exception:
        # purkuvirhe (todennäköisesti väärä salasana)
        return None, None

def save_data(data: dict, master_password: str, salt: bytes | None = None) -> bytes:
    """Salaus ja tallennus levylle password‑sanakirjalle.

    Jos ``salt`` on ``None``, generoidaan uusi 16‑tavun suola. Suola
    kirjoitetaan aina tiedoston alkuun selkokielisenä, jotta se voidaan
    käyttää uudelleen avaimen johdannassa.

    :param data: sanakirja, jossa salasanat
    :param master_password: käytössä oleva pääsalasana
    :param salt: olemassa oleva suola tai ``None`` jos halutaan uusi
    :return: käytetty suola (uusi tai olemassa oleva)
    """
    if salt is None:
        salt = os.urandom(16)  # luodaan uusi suola ensimmäisellä tallennuksella

    key = derive_key(master_password, salt)
    cipher = Fernet(key)

    json_string = json.dumps(data, indent=2)
    encrypted_data = cipher.encrypt(json_string.encode())

    with open(DATA_FILE, "wb") as f:
        f.write(salt + encrypted_data)

    return salt

# --- APUTOIMINNOT ---

def generate_password(length: int = 16) -> str:
    """Palauttaa satunnaisesti luodun salasanan.

    Salasana muodostuu ASCII‑kirjaimista, númeroista ja muutamasta
    erikoismerkistä. Oletuspituus on 16 merkkiä.

    :param length: haluttu pituus
    :return: luotu salasana merkkijonona
    """
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(chars) for _ in range(length))

# --- KÄYTTÖLIITTYMÄN TOIMINNOT ---

def add_entry(data: dict, master_pwd: str, current_salt: bytes) -> bytes:
    """Kysyy käyttäjältä tiedot ja lisää uuden salasanamerkin.

    Merkintä tallennetaan heti, jotta levyllä oleva tietokanta pysyy
    yhtenäisenä. Jos käyttäjä peruuttaa antamalla tyhjän otsikon, suola
    palautetaan ennallaan.

    :param data: nykyinen salasanasanakirja
    :param master_pwd: käytössä oleva pääsalasana
    :param current_salt: käytetty suola
    :return: suola (päivitys jos uusi luotiin)
    """
    print("\n--- ADD NEW (LISÄÄ UUSI) ---")
    title = input("Title / Site: ").strip()
    if not title:
        return current_salt

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

def get_entry(data: dict) -> None:
    """Etsii merkintöjä ja näyttää vastaavat salasanat.

    Hakuehdot ovat kirjainkoon huomioimattomia alimerkkijonoja sivuston otsikosta. Ensimmäinen
    osuma kopioidaan myös leikepöydälle, jos ``pyperclip``-kirjasto löytyy.

    :param data: salasanasanakirja
    """
    print("\n--- GET PASSWORD (HAE) ---")
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
                print("(Password copied to clipboard! / Kopioitu leikepöydälle!)")
            except Exception:
                pass
            found = True

    if not found:
        print("No matches found (Ei tuloksia).")

def delete_entry(data: dict, master_pwd: str, current_salt: bytes) -> None:
    """Poistaa merkinnän, jonka otsikko täsmää tarkasti.

    Poiston jälkeen tietokanta salataan uudelleen ja tallennetaan heti.

    :param data: salasanasanakirja
    :param master_pwd: käytössä oleva pääsalasana
    :param current_salt: käytetty suola
    """
    print("\n--- DELETE (POISTA) ---")
    title = input("Exact site title to delete: ").strip()

    if title in data:
        del data[title]
        save_data(data, master_pwd, current_salt)
        print(f"Deleted {title}.")
    else:
        print("Site not found.")

def list_sites(data: dict) -> None:
    """Tulostaa numeroidun listan kaikista tallennetuista otsikoista.

    :param data: salasanasanakirja
    """
    print("\n--- SAVED SITES (TALLENNETUT) ---")
    if not data:
        print("(Empty / Tyhjä)")
        return

    for i, title in enumerate(sorted(data.keys()), 1):
        print(f"{i}. {title}")

# --- PÄÄOHJELMA ---

def main():
    print("="*30)
    print("  SECURE PASSWORD MANAGER")
    print("="*30)
    
    # 1. KIRJAUTUMINEN / ALUSTUS
    if os.path.exists(DATA_FILE):
        # Jos tiedosto on olemassa, kysy pääsalasanaa
        master_pwd = input("ENTER MASTER PASSWORD: ").strip()
        data, salt = load_data(master_pwd)
        
        # Jos data on None, salasana oli väärä
        if data is None:
            print("\n!!! ACCESS DENIED !!!")
            print("Wrong password or corrupt file.")
            input("Press Enter to exit...")
            return
    else:
        # Jos tiedostoa ei ole, luodaan uusi
        print("No database found. Creating new setup.")
        master_pwd = input("Create a MASTER PASSWORD: ").strip()
        if not master_pwd:
            print("Password cannot be empty.")
            return
        data = {}   # Tyhjä sanakirja
        salt = None # Suola luodaan ensimmäisessä tallennuksessa

    # 2. PÄÄVALIKKO (LOOP)
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
            # Pelkkä salasanan generointi ilman tallennusta
            p = generate_password()
            print(f"\nGenerated: {p}")
            pyperclip.copy(p)
            print("(Copied to clipboard)")
        elif choice in ('q', 'quit', 'exit'):
            break

if __name__ == "__main__":
    main()