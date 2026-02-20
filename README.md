TÄRKEÄÄ:
https://github.com/PUUKKO95/passwordmanager/tree/main
Tämä readme käsittelee tätä github linkkiä, jossa tehdyn työn tulos on.


# Salasananhallinta

Tämä yksinkertainen komentoriviohjelma salaa ja tallentaa
kirjautumistietoja paikalliseen JSON-tiedostoon. Se on tarkoitettu
henkilökohtaiseen käyttöön ja tarjoaa perustoiminnot kuten merkintöjen
lisäyksen, haun, listauksen ja poistamisen. Tietokanta salataan
pääsalasanalla, jotta tallennetut tunnukset pysyvät suojattuina.

## Järjestelmävaatimukset

* Python 3.11.3 tai uudempi
* Seuraavat Python-paketit pitää asentaa:
  * `cryptography`
  * `pyperclip` (vapaaehtoinen, mutta käytetään leikepöydän kopiointiin)

Asenna riippuvuudet komennolla:

```sh
pip install cryptography pyperclip
```

Windowsilla itsenäisen suoritettavan tiedoston luomiseen tarvitset myös
[PyInstallerin](https://pyinstaller.org/).

## Siirrettävyys

Skripti on siirrettävissä, kunhan vaadittu Python-versio ja paketit ovat
saatavilla. Ohjelma tallentaa tietonsa (`my_passwords.json`) samaan
hakemistoon skriptin tai suoritettavan tiedoston kanssa.

- **Python-skriptinä ajaminen:** kopioi `.py`-tiedosto toiselle koneelle,
  jossa Python ja riippuvuudet on asennettu, ja suorita `python
  password_manager.py`.
- **Suoritettavana tiedostona:** rakenna PyInstallerilla kohdekoneella
  tai kopioi valmis `PassManager.exe` ja JSON-tiedosto; se toimii ilman
  erillistä Python-asennusta.

Koodissa ei ole alustakohtaista logiikkaa, joten se toimii Windowsissa,
macOS:ssä ja Linuxissa. Leikepöydän käyttö (`pyperclip`) saattaa edellyttää
lisäpaketteja riippuen käyttöjärjestelmästä. Asennus on erilainen varmasti myös eri käyttöjärjestelmissä,
johon en ole perehtynyt Windowsia pidemmälle vielä.

## Rajoitteet

* Tämä ei ole täysimittainen salasananhallintaohjelma; se ei tarjoa
  esimerkiksi kategoriaa, muistutusta salasanan vanhenemisesta tai
  käyttöliittymää.
* Pääsalasanan suojaus on vain niin vahva kuin itse valittu salasana ja
  `Fernet`-salaus; käytä vahvaa salasanaa ja säilytä JSON-tiedosto
  turvallisesti.
* Ohjelma ei synkronoi tietoja koneiden välillä; jokaisella kopioilla
  on oma tietokantatiedosto.
* Tietokantaa voi käyttää vain yhdellä pääsalasanalla. Pääsalasanan
  unohtaminen tarkoittaa pääsyn menettämistä.

## Kehitysehdotuksia

* Lisää komentorivivalinnat ei-interaktiivista käyttöä varten (esim.
  `--add` ja `--get`).
* Toteuta vaihtoehtoinen GUI tai web‑käyttöliittymä helpompaan käyttöön.
* Lisää tuettu tuonti/vienti tai synkronointi pilvipalveluiden kautta
  (Dropbox, Nextcloud jne.).
* Salli useiden tietokantojen käyttö ja niiden vaihto.
* Paranna virheenkäsittelyä ja lisää lokitus.
* Kirjoita yksikkötestejä ja ota käyttöön jatkuva integraatio luotettavuuden
  parantamiseksi.