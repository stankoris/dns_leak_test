# Threat Model — DNS Leak Test

Ovaj dokument je inzenjerska analiza pretnji, ne pravni ili formalni
bezbednosni sertifikat. Pisan je da bude iskren o poznatim ogranicenjima,
ne da uveri citaoca da je sve reseno.

---

## 1. DNS open-resolver regresija (istorijski incident)

**Pretnja:** Server odgovara autoritativno na upite van sopstvene zone,
ponasajuci se kao javno zloupotrebljiv DNS servis.

**Uzrok u prethodnoj verziji:** `response.answers.push(...)` se izvrsavao
bez provere da li upit pripada `DNS_TEST_DOMAIN`.

**Mitigacija u ovoj verziji:** `src/dns/server.js` eksplicitno proverava
`isInZone(name)` PRE bilo kakve obrade i vraca `REFUSED` (bez ANSWER
sekcije, bez RA bita) za sve sto nije u zoni. Ovo je prva i najvaznija
provera u `handleQuery()`.

**Rezidualni rizik:** Bug u samoj `isInZone`/`extractTestId` logici (npr.
greska u regex-u) mogao bi ponovo da otvori isti problem. Zato postoji
`scripts/external-dns-check.sh` kao obavezan regresioni test PRE svakog
otvaranja porta 53 javno, ukljucujuci posle bilo koje buduce izmene koda.

**Test:** `scripts/external-dns-check.sh <SERVER_IP>`

---

## 2. DNS reflection / amplification

**Pretnja:** Napadac salje UDP DNS upit sa lazno postavljenom (spoofovanom)
izvornom IP adresom zrtve. Server odgovara zrtvi, ne napadacu. Ako je
odgovor veci od upita, ovo pojacava kolicinu saobracaja ka zrtvi.

**Mitigacija:** Svi odgovori su namerno mali - jedan A rekord, bez
dodatnih sekcija, bez ANY podrske, bez velikih TXT odgovora. REFUSED
odgovori (najcesci slucaj za "random" upite sa strane) su minimalni.

**Rezidualni rizik:** Bilo koji autoritativni DNS server, koliko god mali
odgovori bili, teorijski moze da se koristi za reflection. Potpuna
eliminacija zahteva mrezne kontrole van ove aplikacije - Response Rate
Limiting (RRL) na DNS softverskom sloju NIJE implementiran (`dns2`
biblioteka nema ugradjenu RRL podrsku).

**Preporuka pre produkcije:** Dodati mrezni rate limit na UDP port 53
(npr. `nftables` pravilo koje ogranicava broj UDP paketa u sekundi po
izvornoj IP adresi). Ovo NIJE implementirano u ovoj isporuci.

---

## 3. Malformisan / fuzzovan DNS paket

**Pretnja:** Napadac salje namerno pokvaren binarni paket pokusavajuci da
izazove crash, beskonacnu petlju, ili neobradjen izuzetak.

**Mitigacija:** `safeHandle()` u `dns/server.js` hvata SVAKI izuzetak iz
`handleQuery()` i u tom slucaju NISTA ne odgovara.

**Rezidualni rizik:** Ovo stiti Node proces od direktnog crash-a, ali NE
garantuje da `dns2` biblioteka interno korektno parsira svaki mogus
malformisan ulaz bez sopstvenog problema. Ovo NIJE nezavisno
fuzz-testirano u ovoj isporuci zbog nedostatka mreznog pristupa u
okruzenju u kom je kod pisan - navedeno je kao blokirajuca stavka za
"production ready" klasifikaciju.

**Preporuka pre produkcije:** Pokrenuti namenski DNS fuzzer protiv lokalne
instance pre javnog izlaganja.

---

## 4. DoS / resource exhaustion

**Pretnja:** Napadac kreira veliki broj test sesija ili DNS "hit" zapisa
da napumpa memoriju procesa.

**Mitigacija:** `MAX_ACTIVE_SESSIONS`, `MAX_RESOLVERS_PER_SESSION`, HTTP
rate limiter sa gornjom granicom broja pracenih kljuceva
(`RATE_LIMIT_MAX_TRACKED_KEYS`).

**Rezidualni rizik:** DNS sloj nema sopstveni rate limiter - samo
indirektnu zastitu kroz `MAX_RESOLVERS_PER_SESSION` i cinjenicu da upit
mora sadrzati validan testId (128-bitni CSPRNG, prakticno neizvodljivo
pogoditi). Mrezni rate limit (tacka 2) adresira i ovo.

---

## 5. Enumeracija sesije

**Pretnja:** Napadac pokusava da pogodi tudji testId ili resultToken.

**Mitigacija:** `testId` i `resultToken` su nezavisno generisani,
128-bitni CSPRNG stringovi, namerno razliciti: `testId` je vidljiv DNS
infrastrukturi (moze zavrsiti u tudjim DNS logovima), `resultToken` se
nikad ne stavlja u DNS upit i koristi se iskljucivo za HTTP pristup.

---

## 6. XSS / DOM injection kroz geo/ISP podatke

**Pretnja:** Podaci iz IP baze (naziv organizacije, grad...) bi teorijski
mogli sadrzati karaktere opasne ako se naivno ubace preko `innerHTML`.

**Mitigacija:** `public/js/app.js` gradi DOM cvorove i koristi iskljucivo
`textContent`. CSP (`script-src 'self'`, bez `unsafe-inline`) je dodatni
sloj zastite.

---

## 7. Log leakage

**Pretnja:** Resolver IP adrese ili testId zavrse u trajnim logovima,
narusavajuci deklarisanu ~180s retenciju.

**Mitigacija:** `dns/server.js` i `sessions/store.js` NAMERNO ne loguju
resolver IP ili testId u normalnom toku izvrsavanja.

**Rezidualni rizik:** Nginx access log MOZE sadrzati IP adrese HTTP
posetilaca ako nije eksplicitno iskljucen - `access_log off` je
podrazumevana opcija u isporucenoj nginx konfiguraciji.

---

## 8. Supply-chain / zavisnosti

**Trenutno stanje:** `package-lock.json` NIJE isporucen zbog nedostatka
mreznog pristupa u okruzenju u kom je kod pisan. Ovo je eksplicitna
praznina navedena kao blokirajuca stavka za produkciju.

**Preporuka:** `npm install` (generise lockfile) -> `npm audit` -> `npm ci`
u deployment-u. Proveriti CVE liste za sve zavisnosti pre deploy-a.

---

## 9. Proces izolacija

**Trenutno stanje:** DNS i HTTP rade u istom Node.js procesu (deljena
in-memory sesija). `safeHandle()` hvata izuzetke da spreci direktan crash,
ali potpuna izolacija NIJE implementirana.

**Preporuka za vecu instalaciju:** Odvojiti DNS i HTTP u dva systemd
servisa sa deljenim stanjem preko lokalnog Redis-a (SAMO 127.0.0.1, bez
perzistencije, strog TTL) umesto in-process Map-e.

---

## 10. Deljenje infrastrukture sa kriticnim sistemima

**Preporuka:** Ovaj servis (narocito DNS deo) ne bi trebalo da deli host
sa produkcionom bazom, internim administrativnim sistemima ili drugim
poslovno-kriticnim servisima. Namenska, minimalna instanca je preporuceni
pristup za blast-radius redukciju.
