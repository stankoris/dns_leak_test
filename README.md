# DNS Leak Test

Self-hosted DNS leak test aplikacija. Node.js/Express + custom DNS server (bez baze podataka).

## 1. Priprema domena (NS delegacija)

Kod svog DNS provajdera (tamo gde ti je domen registrovan) dodaj:

```
dnstest.tvojdomen.com.   IN  NS   ns1.tvojdomen.com.
ns1.tvojdomen.com.       IN  A    <JAVNA_IP_HETZNER_SERVERA>
```

Ovo govori celom internetu: "za sve sto zavrsava na dnstest.tvojdomen.com,
pitaj direktno moj Hetzner server, ne mene."

Propagacija DNS izmena moze potrajati od par minuta do par sati.

Proveri da li radi (sa bilo kog racunara, ne mora sa servera):

```bash
dig NS dnstest.tvojdomen.com
```

Treba da vidis svoj server kao autoritativni NS.

## 2. Firewall na Hetzner serveru

Otvori sledece portove (Hetzner Cloud Firewall + ufw na samom serveru):

```bash
sudo ufw allow 53/udp
sudo ufw allow 53/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 22/tcp
sudo ufw enable
```

I u Hetzner Cloud konzoli, u sekciji Firewalls, dodaj isto pravilo za port 53
(UDP i TCP) i 80/443 - Hetzner-ov firewall je odvojen od ufw-a na samoj
masini, oba moraju da propuste saobracaj.

## 3. Instalacija

```bash
# Node.js 18+ (ako vec nemas)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

cd /opt
sudo git clone <tvoj-repo> dns-leak-test   # ili prebaci fajlove preko scp
cd dns-leak-test
npm install
cp .env.example .env
nano .env   # upisi DNS_TEST_DOMAIN=dnstest.tvojdomen.com i ostalo
```

## 4. Dozvola za port 53 bez pokretanja kao root

Port 53 je "privilegovan" port (< 1024) - obican korisnik ne moze da ga
otvori. Dve opcije:

**Opcija A (preporuceno) - setcap na Node binary:**

```bash
sudo setcap 'cap_net_bind_service=+ep' $(which node)
```

Ovo dozvoljava Node.js procesu da otvori portove < 1024 bez punog root
pristupa - bezbednije od pokretanja celog procesa kao root.

**Opcija B - pokreni ceo proces kao root** (manje bezbedno, ne preporucujem
za produkciju).

## 5. systemd servis (da app radi trajno i restartuje se sama)

Napravi `/etc/systemd/system/dns-leak-test.service`:

```ini
[Unit]
Description=DNS Leak Test App
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/dns-leak-test
ExecStart=/usr/bin/node src/server.js
Restart=on-failure
EnvironmentFile=/opt/dns-leak-test/.env

[Install]
WantedBy=multi-user.target
```

Napomena: ako koristis Opciju A (setcap), korisnik `www-data` moze da ostane
- setcap dozvola vazi za sam node binary, ne za konkretnog korisnika.

```bash
sudo systemctl daemon-reload
sudo systemctl enable dns-leak-test
sudo systemctl start dns-leak-test
sudo systemctl status dns-leak-test
sudo journalctl -u dns-leak-test -f   # pracenje logova uzivo
```

## 6. nginx reverse proxy (za HTTPS na 443, HTTP API/frontend deo)

DNS server (port 53) ostaje direktan (nginx ne moze da proksira UDP DNS na
ovaj nacin) - samo HTTP deo (port 3000) ide iza nginx-a radi HTTPS-a.

```nginx
server {
    listen 80;
    server_name test.tvojdomen.com;   # obicna stranica za korisnike, RAZLICITA od dnstest poddomena

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Zatim HTTPS preko Certbot-a:

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d test.tvojdomen.com
```

**VAZNO:** `test.tvojdomen.com` (stranica koju korisnici otvaraju u browseru)
i `dnstest.tvojdomen.com` (poddomen delegiran za DNS server) su NAMERNO
razliciti poddomeni - jedan je normalna web stranica iza nginx-a, drugi je
sirovi DNS protokol na portu 53 direktno ka Node procesu.

## 7. Testiranje da DNS server radi

Sa bilo kog racunara:

```bash
dig @dnstest.tvojdomen.com test.abc123.dnstest.tvojdomen.com
```

Treba da dobijes odgovor sa IP adresom definisanom u `DNS_ANSWER_IP`.
Ako radi, otvori `https://test.tvojdomen.com` u browseru i pokreni test.

## Poznata ogranicenja

- Ako korisnikov sistem koristi DNS-over-HTTPS (DoH) ili DNS-over-TLS (DoT)
  (npr. Firefox sa ukljucenim "Secure DNS", ili Android/iOS sistemski DoH),
  ti upiti idu enkriptovano direktno ka provajderu (npr. Cloudflare
  1.1.1.1 preko HTTPS-a) i nikad ne prolaze kroz klasican UDP port 53 lanac
  - nas test ih nece "uhvatiti" na isti nacin. Ovo je poznato ogranicenje i
  kod dnsleaktest.com i browserleaks.com.
- Rezultati zavise od brzine DNS propagacije - probaj da povecas cekanje u
  `app.js` (trenutno 2 sekunde) ako primetis da ti fale spori resolveri.