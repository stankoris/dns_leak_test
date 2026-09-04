/**
 * dns-server.js
 *
 * Ovo NIJE obican web server - ovo je nas sopstveni, minijaturni DNS server.
 * Sluša na UDP portu 53 (standardni DNS port) i ponaša se kao "autoritativni"
 * server za nas poddomen (DNS_TEST_DOMAIN iz .env).
 *
 * KAKO STIZE DO OVDE (ceo lanac):
 * Browser -> OS DNS resolver -> (opciono VPN DNS) -> (opciono ISP DNS)
 *   -> ... -> Root DNS serveri -> TLD (.com) serveri
 *   -> NASA MASINA (jer smo NS delegacijom rekli "pitaj mene za dnstest.tvojdomen.com")
 *
 * Svaka "stanica" u tom lancu koja NIJE bas krajnji browser jeste DNS
 * RESOLVER - i bas IP adresu poslednjeg resolvera u lancu (onog koji je
 * direktno pitao NAS) mi ovde hvatamo. To je upravo ono sto nas zanima:
 * da li je taj resolver "cist" (npr. VPN-ov DNS server) ili je to zapravo
 * DNS server tvog ISP-a (sto znaci leak).
 *
 * Koristimo biblioteku 'dns2' koja nam stedi posao rucnog parsiranja
 * binarnog DNS protokola (RFC 1035) - ali logika koju pisemo iznad nje je
 * nasa.
 */

require('dotenv').config();
const dns2 = require('dns2');
const { Packet } = dns2;
const sessionStore = require('./sessionStore');

const DNS_TEST_DOMAIN = (process.env.DNS_TEST_DOMAIN || 'dnstest.example.com').toLowerCase();
const DNS_PORT = parseInt(process.env.DNS_PORT || '53', 10);
const DNS_ANSWER_IP = process.env.DNS_ANSWER_IP || '203.0.113.1';

/**
 * Iz punog imena upita (npr. "a1b2c3.f29e7ab1.dnstest.tvojdomen.com")
 * izvlacimo testId. Format koji nas frontend generise je uvek:
 *
 *   <probeId>.<testId>.<DNS_TEST_DOMAIN>
 *
 * Zato: skinemo sufiks DNS_TEST_DOMAIN, ono sto ostane podelimo tackom -
 * prvi deo je probeId, drugi je testId.
 */
function extractTestId(queryName) {
  const name = queryName.toLowerCase().replace(/\.$/, ''); // skini trailing tacku ako postoji

  if (!name.endsWith(DNS_TEST_DOMAIN)) {
    return null; // upit koji ne pripada nasem test poddomenu - ignorisemo
  }

  const prefix = name.slice(0, name.length - DNS_TEST_DOMAIN.length).replace(/\.$/, '');
  const parts = prefix.split('.');

  if (parts.length < 2) return null; // ocekujemo bar probeId.testId

  const testId = parts[parts.length - 1];
  return testId;
}

const server = dns2.createServer({
  udp: true,
  handle: (request, send, rinfo) => {
    // rinfo.address = IP adresa masine koja nam je DIREKTNO poslala ovaj
    // UDP paket. To je nas "zadnji resolver u lancu" - upravo ono sto
    // zelimo da uhvatimo i pokazemo korisniku.
    const response = Packet.createResponseFromRequest(request);
    const [question] = request.questions;

    if (question) {
      const testId = extractTestId(question.name);

      if (testId) {
        const recorded = sessionStore.recordResolverHit(testId, rinfo.address);
        if (recorded) {
          console.log(`[DNS] test=${testId} resolver=${rinfo.address} query=${question.name}`);
        }
      }

      // Bez obzira da li prepoznajemo testId, MORAMO da odgovorimo necim -
      // inace ce resolver koji nas pita da ceka na timeout, sto usporava
      // ceo test i moze da izgleda kao da je "test zapeo".
      //
      // Vracamo namerno besmislenu (TEST-NET-3, RFC 5737) IP adresu sa
      // ttl=1 - klijentu ne treba prava IP adresa, samo nam treba da je
      // DNS upit stigao do nas. ttl=1 sprecava keširanje ovog odgovora.
      response.answers.push({
        name: question.name,
        type: Packet.TYPE.A,
        class: Packet.CLASS.IN,
        ttl: 1,
        address: DNS_ANSWER_IP,
      });
    }

    send(response);
  },
});

server.on('listening', () => {
  console.log(`[DNS] Server slusa na UDP portu ${DNS_PORT}, domen: *.${DNS_TEST_DOMAIN}`);
});

server.on('error', (err) => {
  console.error('[DNS] Greska:', err);
});

function startDnsServer() {
  server.listen({
    udp: {
      port: DNS_PORT,
      address: '0.0.0.0',
      type: 'udp4',
    },
  });
}

module.exports = { startDnsServer };