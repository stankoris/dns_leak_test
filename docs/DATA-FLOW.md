# Data Flow — DNS Leak Test

```
Browser korisnika
   |
   | HTTPS (preko nginx, 443)
   v
Express API (127.0.0.1:3000, NIJE javno izlozen)
   |
   +-- proverava privacyAcknowledged && termsAccepted (server-side, obavezno)
   +-- kreira sesiju: { testId, resultToken, createdAt } u memoriji procesa
   |

Recursive DNS resolver (VPN-ov, ISP-ov, ili bilo koji drugi u lancu)
   |
   | DNS upit (UDP/TCP port 53), IZVAN nginx-a, direktno
   v
Autoritativni DNS servis (isti Node proces, poseban listener)
   |
   +-- van zone?              --> REFUSED (bez podataka)
   +-- u zoni, nepoznat testId --> NXDOMAIN
   +-- u zoni, validan testId --> upisuje resolverIp u IN-MEMORY sesiju
   |                              (deljena memorija sa HTTP delom - vidi
   |                               THREAT-MODEL.md tacka 9)
   +-- vraca mali A odgovor

Express API (kad browser pita GET /api/tests/:resultToken)
   |
   +-- cita resolverIp listu iz iste in-memory sesije
   |
   v
Lokalni MMDB lookup (DB-IP Lite, na disku servera)
   |
   +-- resolverIp NIKAD ne napusta server radi ovog lookup-a
   |
   v
JSON odgovor -> Browser (Cache-Control: no-store)
```

## Gde podaci mogu postojati (kompletna lista)

| Lokacija | Sta se cuva | Koliko dugo |
|---|---|---|
| Node.js memorija procesa (`sessions/store.js`) | testId, resultToken, resolverIp lista, brojaci upita, timestamp-ovi | Do `SESSION_TTL_SECONDS` (default 180s), proverava se pri SVAKOM citanju/pisanju, ne samo periodicnim cleanup-om |
| Node.js memorija (`security/rateLimiter.js`) | HMAC-pseudonimizovan otisak IP adrese HTTP posetioca, brojac zahteva | Do `RATE_LIMIT_WINDOW_MS` (default 10s) |
| Nginx access log | IP adresa HTTP posetioca (ne DNS resolvera), putanja, vreme | Zavisi od konfiguracije - podrazumevano ISKLJUCENO (`access_log off`) u isporucenoj konfiguraciji |
| journald / aplikacioni logovi | Generic poruke o startu/gasenju, broj aktivnih sesija, generic error poruke | Standardna systemd/journald retencija (podesava se odvojeno, van ove aplikacije) - NAMERNO ne sadrze resolverIp ni testId |
| Browser (klijent) | testId, resultToken, prikazani rezultati - u JS memoriji taba dok je stranica otvorena | Nestaje zatvaranjem/osvezavanjem stranice - nema localStorage/cookies |
| DB-IP MMDB fajlovi na disku | Staticke, unapred preuzete IP->lokacija/ASN baze - NE sadrze podatke o korisnicima ove aplikacije | Do sledeceg rucnog azuriranja baze (nezavisno od korisnickih testova) |

## Eksplicitno: sta se NE salje DB-IP servisu

Otkrivena IP adresa DNS resolvera se koristi ISKLJUCIVO za lokalni
`.mmdb` lookup na disku servera (`src/geo/lookup.js`, `maxmind.open()`).
Ne postoji nijedan network poziv ka db-ip.com ili bilo kom drugom
eksternom servisu u toku obrade pojedinacnog testa. DB-IP baze se
preuzimaju periodicno i rucno od strane administratora servera (vidi
README), potpuno odvojeno od bilo kog korisnickog testa.

## Eksplicitno: sta se NE salje ip-api.com ili bilo kom drugom eksternom API-ju

Prethodna verzija je slala otkrivene resolver IP adrese ka
`ip-api.com` (nesifrovano, HTTP, trece strani) samo da bi dobila
kozmeticki ISP naziv. Ovo je POTPUNO UKLONJENO iz ove verzije - u kodu
ne postoji nijedna referenca na ip-api.com niti bilo koji drugi eksterni
geolokacioni servis.
