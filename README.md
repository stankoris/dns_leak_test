# DNS Leak Test

A self-hosted DNS leak testing application built with Node.js and Express.

The project combines a web application with a custom authoritative DNS server
to detect which DNS resolvers are being used by a visitor.

No database is required. Test sessions and DNS queries are stored temporarily
in memory.

## Architecture

The application uses two separate subdomains:

```text
dnsleak.example.com
```

Web interface and HTTP API.

```text
dnstest.example.com
```

Delegated DNS zone used for generating unique DNS queries.

The basic request flow looks like this:

```text
User Browser
     |
     v
dnsleak.example.com
     |
     v
Nginx
     |
     v
Node.js / Express
127.0.0.1:3001


DNS Resolver
     |
     v
*.dnstest.example.com
     |
     v
ns1.example.com
     |
     v
Custom Node.js DNS Server
Public-IP:53/UDP
```

## Requirements

- Linux server
- Node.js 18+
- Nginx
- systemd
- Public IPv4 address
- Domain with DNS management access
- Ability to delegate a subdomain using an NS record

---

## 1. Configure DNS Delegation

Create an A record for the authoritative DNS server:

```text
ns1.example.com    A    SERVER_PUBLIC_IP
```

This record must point directly to the server.

If you are using Cloudflare, set this record to:

```text
DNS only
```

Do not proxy the nameserver through Cloudflare.

Then delegate the DNS test zone:

```text
dnstest.example.com    NS    ns1.example.com
```

The web application can use a separate record:

```text
dnsleak.example.com    A    SERVER_PUBLIC_IP
```

Verify the nameserver:

```bash
dig A ns1.example.com
```

Verify the delegation:

```bash
dig NS dnstest.example.com
```

You should see:

```text
dnstest.example.com.    IN    NS    ns1.example.com.
```

---

## 2. Configure the Firewall

Allow DNS traffic:

```bash
sudo ufw allow 53/udp
```

The web application should already be reachable through Nginx on:

```text
80/tcp
443/tcp
```

Check the firewall:

```bash
sudo ufw status
```

If your hosting provider has an additional network firewall, allow UDP port 53
there as well.

Do not expose the internal Node.js HTTP port publicly.

---

## 3. Create a Service User

Create a dedicated system user for the application:

```bash
sudo useradd \
  --system \
  --shell /usr/sbin/nologin \
  --home-dir /opt/dns-leak-test \
  dnsleak
```

Create the application directory:

```bash
sudo mkdir -p /opt/dns-leak-test
sudo chown dnsleak:dnsleak /opt/dns-leak-test
sudo chmod 750 /opt/dns-leak-test
```

---

## 4. Clone the Repository

Clone the project into `/opt`:

```bash
cd /opt
sudo git clone https://github.com/USERNAME/dns_leak_test.git dns-leak-test
```

Set ownership:

```bash
sudo chown -R dnsleak:dnsleak /opt/dns-leak-test
```

Install dependencies:

```bash
cd /opt/dns-leak-test
sudo -u dnsleak npm install
```

---

## 5. Configure Environment Variables

Create the environment file:

```bash
sudo -u dnsleak cp .env.example .env
```

Edit it:

```bash
sudo nano .env
```

Example:

```env
HTTP_PORT=3001

DNS_PORT=53
DNS_TEST_DOMAIN=dnstest.example.com
DNS_ANSWER_IP=SERVER_PUBLIC_IP

SESSION_TTL_SECONDS=180
```

Protect the file:

```bash
sudo chmod 600 /opt/dns-leak-test/.env
sudo chown dnsleak:dnsleak /opt/dns-leak-test/.env
```

---

## 6. Configure the DNS Bind Address

On systems using `systemd-resolved`, port 53 may already be used locally:

```bash
sudo ss -lntup | grep ':53'
```

You may see:

```text
127.0.0.53:53
```

This is normal.

Do not disable `systemd-resolved`.

Instead, configure the custom DNS server to listen only on the server's public
IP address.

Example:

```javascript
server.listen({
  udp: {
    port: DNS_PORT,
    address: 'SERVER_PUBLIC_IP',
    type: 'udp4',
  },
});
```

This allows both services to coexist:

```text
127.0.0.53:53       systemd-resolved
SERVER_PUBLIC_IP:53 Node.js DNS server
```

---

## 7. Create the systemd Service

Create:

```bash
sudo nano /etc/systemd/system/dns-leak-test.service
```

Add:

```ini
[Unit]
Description=DNS Leak Test
After=network-online.target
Wants=network-online.target

[Service]
Type=simple

User=dnsleak
Group=dnsleak

WorkingDirectory=/opt/dns-leak-test

EnvironmentFile=/opt/dns-leak-test/.env

ExecStart=/usr/bin/node /opt/dns-leak-test/src/server.js

AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

`CAP_NET_BIND_SERVICE` allows the application to bind to port 53 without
running the entire Node.js process as root.

Reload systemd:

```bash
sudo systemctl daemon-reload
```

Enable and start the application:

```bash
sudo systemctl enable --now dns-leak-test
```

Check status:

```bash
sudo systemctl status dns-leak-test
```

Follow logs:

```bash
sudo journalctl -u dns-leak-test -f
```

---

## 8. Verify the Application

Check listening ports:

```bash
sudo ss -lntup | grep -E ':3001|:53'
```

You should see something similar to:

```text
SERVER_PUBLIC_IP:53    Node.js
*:3001                 Node.js
127.0.0.53:53          systemd-resolved
```

Test the HTTP application locally:

```bash
curl http://127.0.0.1:3001
```

Test the DNS server directly:

```bash
dig @SERVER_PUBLIC_IP test123.dnstest.example.com
```

Then test it through the delegated nameserver:

```bash
dig @ns1.example.com test123.dnstest.example.com
```

---

## 9. Configure Nginx

Create:

```bash
sudo nano /etc/nginx/sites-available/dnsleak.example.com
```

Add:

```nginx
server {
    listen 80;
    listen [::]:80;

    server_name dnsleak.example.com;

    location / {
        proxy_pass http://127.0.0.1:3001;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable the site:

```bash
sudo ln -s \
  /etc/nginx/sites-available/dnsleak.example.com \
  /etc/nginx/sites-enabled/
```

Test the configuration:

```bash
sudo nginx -t
```

Reload Nginx:

```bash
sudo systemctl reload nginx
```

---

## 10. Enable HTTPS

Install Certbot if necessary:

```bash
sudo apt install certbot python3-certbot-nginx
```

Request a certificate:

```bash
sudo certbot --nginx -d dnsleak.example.com
```

Verify:

```bash
curl -I https://dnsleak.example.com
```

Then open:

```text
https://dnsleak.example.com
```

and run the test.

---

## Troubleshooting

### Port 3000 is already in use

If the application reports:

```text
EADDRINUSE: address already in use :::3000
```

verify that `.env` contains:

```env
HTTP_PORT=3001
```

The application expects `HTTP_PORT`, not `PORT`.

Restart the service:

```bash
sudo systemctl restart dns-leak-test
```

### DNS queries are not reaching the server

Check that the authoritative nameserver resolves directly to your server:

```bash
dig A ns1.example.com
```

Then verify delegation:

```bash
dig NS dnstest.example.com
```

Test the DNS server directly:

```bash
dig @SERVER_PUBLIC_IP test123.dnstest.example.com
```

Check that UDP port 53 is listening:

```bash
sudo ss -lnup | grep ':53'
```

Watch application logs while running a test:

```bash
sudo journalctl -u dns-leak-test -f
```

---

## Known Limitations

DNS leak detection is more complex when clients use technologies such as
DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), browser-specific DNS resolvers,
VPN-provided DNS infrastructure, or resolver anycast networks.

The IP address observed by the authoritative DNS server represents the
recursive resolver that contacted it, which may not always correspond directly
to the user's ISP.

Results should therefore be interpreted as an indication of which DNS
infrastructure handled the queries, rather than absolute proof of a DNS leak.

DNS query timing can also vary between resolvers. If some results are missing,
the wait interval used by the frontend may need to be increased.

---

## Tech Stack

- Node.js
- Express
- Custom UDP DNS server
- Nginx
- systemd
- Linux
- DNS delegation