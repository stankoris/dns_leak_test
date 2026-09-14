# DNS Leak Test — hardened, security-conscious verzija

Self-hosted DNS leak test alat. Autoritativni DNS servis (NE recursive
resolver) + Express HTTP API/frontend. Bez baze podataka - sve efemerno,
u memoriji, sa striktnim TTL-om.

**Status ove isporuke:** Ovaj kod je napisan i logicki proveren, ali NIJE
izvrsen niti testiran u okruzenju sa mreznim pristupom (sandbox u kom je
pisan nema pristup internetu - nije bilo moguce `npm install`, pokrenuti
`dig` protiv zive instance, niti preuzeti DB-IP baze). Pre bilo kakvog
javnog izlaganja MORAS sam da prodjes kroz sekciju "Pre otvaranja porta
53" ispod. Vidi i finalnu klasifikaciju na kraju ovog dokumenta.

---

## Arhitektura

```
Internet
   |
   +-- 80/443 (HTTP/HTTPS) --> nginx --> 127.0.0.1:3000 (Express, privatan)
   |
   +-- 53/udp, 53/tcp (DNS) --> direktno Node.js DNS listener (javna IP)
```

DNS i HTTP servis dele isti Node.js proces (jedna in-memory sesijska
memorija) - namerni kompromis radi jednostavnosti, dokumentovan u
`src/index.js` i `docs/THREAT-MODEL.md` (tacka 9) sa preporukom za dalju
izolaciju u vecoj instalaciji.

## Kako DNS leak test radi (koncept)

VPN treba da enkriptuje sav saobracaj, ukljucujuci DNS upite. Ako DNS
upiti "procure" mimo VPN tunela direktno ka ISP-u korisnika, to ISP-u
otkriva koje sajtove korisnik posecuje uprkos VPN-u.

Test: browser generise CSPRNG testId, pravi niz jedinstvenih nasumicnih
poddomena (`<probe>.<testId>.dnstest.tvojdomen.com`) i "gadja" ih (preko
`<img>` taga, sto forsira DNS lookup bez potrebe za uspesnom HTTP
konekcijom). Nas autoritativni DNS server beleze koje IP adrese (DNS
resolveri) su ga direktno pitale za ta imena. Te IP adrese se lokalno
geolociraju (DB-IP Lite) i prikazuju korisniku - ako se medju njima nadje
ISP korisnika umesto VPN provajdera, DNS cura.

## Zasto autoritativni, ne recursive resolver

Autoritativni server odgovara SAMO za imena u sopstvenoj, delegiranoj
zoni (`DNS_TEST_DOMAIN`) i NIKAD ne "resava" proizvoljna imena treceg
lica niti prosledjuje upite dalje. Recursive resolver (kakav bi npr. bio
javni 8.8.8.8) resava BILO KOJE ime na internetu - upravo ta razlika je
uzrok prethodnog BSI/CERT-Bund incidenta: server se spolja ponasao kao da
je (zloupotrebljiv) recursive resolver, iako to nije bila namera.

## Root cause prethodnog incidenta (za istoriju/kontekst)

Prijava je navela da je server (`116.202.27.25`) na UDP portu 53
detektovan kao potencijalno zloupotrebljiv otvoren DNS servis. Uzrok u
kodu: DNS handler je vracao A odgovor za SVAKI upit, bez provere da li
upit pripada `DNS_TEST_DOMAIN`. Ova cinjenica je uzeta kao data (relejovana
od strane korisnika) - nije nezavisno verifikovana od strane ovog alata,
ali osnovni bug koji opisuje je stvaran i vidljiv u starom kodu, i
ispravljen je u ovoj verziji (vidi `docs/THREAT-MODEL.md`, tacka 1).

---

## 1. DNS delegacija (obavezno pre bilo cega drugog)

Kod svog DNS provajdera:

```
dnstest.tvojdomen.com.   IN  NS   ns1.dnstest.tvojdomen.com.
ns1.dnstest.tvojdomen.com. IN A   <JAVNA_IP_HETZNER_SERVERA>
```

Proveri propagaciju sa druge masine:

```bash
dig NS dnstest.tvojdomen.com
```

## 2. Environment varijable

Kopiraj `.env.example` u `.env` i popuni SVE vrednosti - pogledaj
komentare u fajlu. U produkciji (`NODE_ENV=production`), aplikacija se
NECE pokrenuti ako `DNS_BIND_ADDRESS` nije eksplicitno postavljen na
javnu IP adresu (namerno, fail-closed - vidi `src/config.js`).

## 3. DB-IP baze (opciono, ali preporuceno)

Ova verzija NE koristi ip-api.com niti bilo koji eksterni geolokacioni
API. Za ISP/lokacija obogacivanje rezultata:

1. Preuzmi DB-IP City Lite i DB-IP ASN Lite u MMDB formatu sa
   https://db-ip.com/db/lite.php (besplatne, mesecno azurirane, zahtevaju
   atribuciju - vec ukljucena u `public/index.html` footer i
   `public/terms.html`).
2. Postavi fajlove na server, npr. `/opt/dns-leak-test/data/`.
3. Podesi `DBIP_CITY_DB` i `DBIP_ASN_DB` u `.env`.
4. Ako ostavis ova polja prazna, aplikacija radi normalno, samo bez
   ISP/lokacija podataka (prikazuju se samo IP adrese).

Azuriranje: DB-IP Lite baze se mesecno osvezavaju od strane DB-IP. Rucno
preuzmi novu verziju i zameni fajl - ne postoji automatski downloader u
ovoj isporuci (namerno - izbegava se oslanjanje na nedokumentovane URL-ove
koji se mogu promeniti).

## 4. Instalacija

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

sudo useradd --system --no-create-home --shell /usr/sbin/nologin dnsleak
sudo mkdir -p /opt/dns-leak-test/data
sudo chown -R dnsleak:dnsleak /opt/dns-leak-test

cd /opt/dns-leak-test
# prebaci fajlove ovog projekta ovde (git clone ili scp)
npm install          # generisace package-lock.json - PROVERI npm audit posle ovoga
npm audit
cp .env.example .env
nano .env
```

## 5. Dozvola za port 53 bez root-a

```bash
sudo setcap 'cap_net_bind_service=+ep' $(which node)
```

Napomena: `systemd/dns-leak-test.service` vec koristi
`AmbientCapabilities=CAP_NET_BIND_SERVICE`, sto postize isto na nivou
servisa bez potrebe za globalnim `setcap` - biraj jedan pristup, ne oba
nepotrebno.

## 6. systemd

```bash
sudo cp systemd/dns-leak-test.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now dns-leak-test
sudo systemctl status dns-leak-test
sudo journalctl -u dns-leak-test -f
```

Ako servis ne starta sa svim `systemd` hardening direktivama ukljucenim,
iskljucuj ih jednu po jednu (pocevsi od `RestrictAddressFamilies`,
`ProtectKernelModules`) dok ne nadjes koja pravi problem na tvojoj
distribuciji, umesto da ih sve iskljucis odjednom.

## 7. Nginx + HTTPS

```bash
sudo cp nginx/dns-leak-test.conf /etc/nginx/sites-available/dns-leak-test
sudo ln -s /etc/nginx/sites-available/dns-leak-test /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d test.tvojdomen.com
```

Nakon potvrde da HTTPS radi, otkomentarisi HSTS red u
`nginx/dns-leak-test.conf` i ponovo `nginx -t && systemctl reload nginx`.

## 8. UFW / firewall — port 53 ostaje ZATVOREN dok se ne zavrse testovi

```bash
sudo ufw allow 22/tcp     # ili tvoj custom SSH port
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw deny 53/udp
sudo ufw deny 53/tcp
sudo ufw enable
```

## 9. Pre otvaranja porta 53 (OBAVEZNO, redosled je bitan)

```bash
# 1) Lokalne provere DOK je port 53 jos uvek zatvoren spolja:
bash scripts/security-check.sh

# Sve mora da pise OK / PASS pre nego sto nastavis.
```

Tek nakon sto `security-check.sh` prodje u potpunosti:

```bash
sudo ufw allow 53/udp
sudo ufw allow 53/tcp
```

I dodaj isto pravilo u Hetzner Cloud Firewall (odvojen sistem od ufw-a na
samoj masini - oba moraju da propuste saobracaj).

```bash
# 2) SA DRUGE MASINE (ne sa Hetzner servera samog), pokreni:
bash scripts/external-dns-check.sh <JAVNA_IP_SERVERA>

# Mora da ispise PASS. Ako bilo koji test ne prodje, ODMAH ponovo
# zatvori port 53 (ufw deny) i ne nastavljaj dok se problem ne resi.
```

## 10. Rollback

```bash
sudo ufw deny 53/udp
sudo ufw deny 53/tcp
sudo systemctl stop dns-leak-test
```

---

## Poznata ogranicenja

- Ako korisnikov sistem koristi DNS-over-HTTPS (DoH) ili DNS-over-TLS
  (DoT), ti upiti idu enkriptovano direktno ka provajderu i nikad ne
  prolaze kroz klasican UDP/TCP port 53 lanac - ovaj test ih nece uhvatiti
  na isti nacin. Poznato ogranicenje i kod uporedivih javnih alata.
- Nema mreznog nivoa rate-limitinga za DNS port (vidi
  `docs/THREAT-MODEL.md`, tacka 2) - preporucen dodatak pre vece javne
  upotrebe.
- Fuzz testiranje DNS parsera NIJE izvrseno u ovoj isporuci (nema
  mreznog pristupa u okruzenju u kom je kod pisan).
- `package-lock.json` NIJE isporucen - generisi ga sa `npm install` pri
  prvoj instalaciji i komituj ga.
- DNS i HTTP dele isti proces (vidi `docs/THREAT-MODEL.md`, tacka 9).
- Automatizovan test suite (unit/integration) NIJE ukljucen u ovu
  isporuku - `scripts/security-check.sh` i
  `scripts/external-dns-check.sh` pokrivaju najkriticnije slucajeve
  rucno/skriptovano, ali ne zamenjuju pravi CI test suite.

## Pravni disclaimer

Ovo je softverska isporuka, ne pravni savet niti potvrda uskladjenosti.
Tehnicke privatnosne kontrole su implementirane (minimalna retencija,
lokalni geo lookup, server-side enforcement pristanka, itd.), ali
organizacija koja ovo pokrece MORA da sprovede sopstveni pravni/DPO
pregled i popuni `public/privacy.html` i `public/terms.html` pre
komercijalne produkcijske upotrebe. Ovaj alat ne tvrdi "GDPR
compliant" niti eliminise pravnu odgovornost.

---

## Finalni self-audit (druga, adversarijalna provera sopstvene implementacije)

| # | Ozbiljnost | Fajl/funkcija | Scenario | Uticaj | Preporuka | Blokira produkciju? |
|---|---|---|---|---|---|---|
| 1 | Visoka | cela isporuka | Nikakav test nije stvarno izvrsen (nema mreznog pristupa u okruzenju pisanja koda) - moguce su sintaksne/API greske u `dns2`/`maxmind` pozivima koje bi se otkrile tek pri stvarnom pokretanju | Servis moze da ne startuje ili radi pogresno dok se prvi put ne pokrene | Pokreni `npm install && npm start` lokalno/staging, prodji `security-check.sh`, PA TEK ONDA razmatraj produkciju | DA |
| 2 | Visoka | DNS parser (`dns2` zavisnost) | Fuzz testiranje nije izvrseno | Nepoznato ponasanje na malformisan/neocekivan binarni ulaz | Pokrenuti namenski DNS fuzzer pre javnog izlaganja (vidi THREAT-MODEL tacka 3) | DA |
| 3 | Srednja | mrezni sloj (van aplikacije) | Nema RRL/mreznog rate-limita za UDP 53 | Reflection/amplification rizik ostaje delimicno neublazen na mreznom nivou | Dodati nftables/firewall rate limit za UDP 53 (THREAT-MODEL tacka 2) | DA (za javnu produkciju veceg obima) |
| 4 | Srednja | `package.json` | Nema `package-lock.json`, verzije zavisnosti nisu pin-ovane na tacan poznat bezbedan build | Nedeterministicki build, potencijalno neproveren supply-chain | `npm install` + `npm audit` + commit lockfile pre deploy-a | DA |
| 5 | Niska-Srednja | `src/index.js` | DNS i HTTP dele proces - malformisan paket koji ipak izazove neuhvacen problem u `dns2` biblioteci (van naseg `try/catch`) mogao bi teorijski da obori i HTTP | Downtime celog servisa, ne samo DNS dela | Proceni odvajanje procesa za vecu instalaciju (THREAT-MODEL tacka 9) | NE (prihvatljivo za manju instalaciju uz monitoring/restart) |
| 6 | Niska | `src/dns/server.js`, apex odgovori | SOA/NS implementacija je minimalna (fiksne vrednosti refresh/retry/expire) - nije punopravna zone-transfer-capable implementacija | Vrlo ogranicen - ovo nije opsta DNS zona, samo dijagnosticki poddomen | Prihvatljivo za namenu; dokumentovano ogranicenje | NE |
| 7 | Niska | `public/privacy.html`, `public/terms.html` | Sadrze placeholder-e, nisu finalni pravni tekstovi | Nedovoljna pravna zastita/informisanost korisnika ako se objavi "kao sto jeste" | Pravni/DPO pregled i popunjavanje placeholder-a PRE produkcije | DA (za realnu komercijalnu produkciju) |
| 8 | Informativno | `docs/THREAT-MODEL.md` tacka 2, 3 | Vec dokumentovano gore | — | — | (vec pokriveno) |

### Klasifikacija

**SAFE FOR CONTROLLED TESTING ONLY**

Razlog: kod implementira ispravnu logiku (posebno kriticnu izmenu -
REFUSED za van-zonske upite, RA=0, minimalni odgovori, lokalni geo
lookup, server-side consent enforcement, odvojeni testId/resultToken), i
dizajn adresira sve glavne tacke iz specifikacije. MEDJUTIM, nista od
ovoga nije stvarno izvrseno niti eksterno testirano u okruzenju u kom je
pisano (nema mreznog pristupa), nema fuzz testiranja DNS parsera, nema
mreznog rate-limita za UDP amplification zastitu, i nema
`package-lock.json`/`npm audit` provere. Zbog toga se NE klasifikuje kao
"PRODUCTION CANDIDATE WITH CONDITIONS" niti "PRODUCTION READY" - to bi
bilo preterano samopouzdanje bez stvarnog testa.

Da bi presla u "PRODUCTION CANDIDATE WITH CONDITIONS", potrebno je
najmanje: (1) uspesno lokalno pokretanje i prolazak
`scripts/security-check.sh`, (2) prolazak
`scripts/external-dns-check.sh` sa druge masine, (3) generisan i
pregledan `package-lock.json` + `npm audit`, (4) osnovni DNS fuzz test
bez crash-a.

---

## GO / NO-GO checklist za otvaranje porta 53 javno

- [ ] `npm install` uspesno prosao, `npm audit` pregledan
- [ ] `.env` popunjen, `NODE_ENV=production`, `DNS_BIND_ADDRESS` = javna IP (ne 0.0.0.0)
- [ ] NS delegacija potvrdjena (`dig NS dnstest.tvojdomen.com` sa druge masine)
- [ ] systemd servis startuje i ostaje aktivan (`systemctl status`)
- [ ] `scripts/security-check.sh` u potpunosti PASS, lokalno, dok je port 53 JOS zatvoren spolja
- [ ] nginx + HTTPS potvrdjeno rade za HTTP/frontend deo
- [ ] Port 53 otvoren (ufw + Hetzner Cloud Firewall)
- [ ] `scripts/external-dns-check.sh <IP>` sa DRUGE masine u potpunosti PASS
- [ ] `public/privacy.html` i `public/terms.html` popunjeni od strane pravnog/DPO tima (za realnu komercijalnu upotrebu)
- [ ] Odluka o nginx access log retenciji doneta i Privacy Notice azuriran da je tacno odrazava
- [ ] Plan za DNS fuzz test i mrezni rate limit za UDP 53 (moze biti "posle lansiranja" za kontrolisano testiranje, ali MORA postojati pre sireg javnog objavljivanja)

Ako bilo koja stavka nije zaokruzena: **NO-GO** za javno otvaranje porta 53.
