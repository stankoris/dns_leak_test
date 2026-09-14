'use strict';

const dns2 = require('dns2');
const { Packet } = dns2;
const config = require('../config');
const sessions = require('../sessions/store');

const TEST_DOMAIN = config.dns.testDomain; // vec normalizovan (lowercase, bez trailing tacke)

/**
 * dns/server.js
 *
 * GLAVNA ISPRAVKA U ODNOSU NA PRETHODNU VERZIJU:
 *
 * Prethodna implementacija je odgovarala A rekordom na SVAKI upit, bez
 * obzira da li pripada nasoj zoni. To je tacan uzrok "open resolver"
 * ponasanja - server se spolja ponasao kao da moze da "resi" bilo koje
 * ime (google.com, cert-bund.de, ...), sto CERT/BSI sistemi za detekciju
 * prepoznaju kao zloupotrebljiv javni DNS servis.
 *
 * Ova verzija implementira PRAVO autoritativno ponasanje:
 *
 *   ime van TEST_DOMAIN                    -> REFUSED, ANSWER=0, RA=0
 *   ime u TEST_DOMAIN, pogresan oblik       -> NXDOMAIN
 *   ime u TEST_DOMAIN, nepoznat/istekao ID  -> NXDOMAIN
 *   ime == TEST_DOMAIN (apex), SOA upit     -> SOA odgovor
 *   ime == TEST_DOMAIN (apex), NS upit      -> NS odgovor
 *   ime u TEST_DOMAIN, validna sesija, A    -> mali A odgovor + zapis IP-ja
 *
 * Server NIKAD:
 *   - ne postavlja RA (recursion available) bit
 *   - ne prosledjuje upit dalje (nema recursive resolucije)
 *   - ne izmislja odgovor za ime van sopstvene zone
 *   - ne vraca velike odgovore (amplification zastita - vidi docs/THREAT-MODEL.md)
 */

function normalizeName(name) {
  return name.toLowerCase().replace(/\.$/, '');
}

function isInZone(name) {
  return name === TEST_DOMAIN || name.endsWith(`.${TEST_DOMAIN}`);
}

/**
 * Ocekivani oblik probe imena: <probeId>.<testId>.<TEST_DOMAIN>
 * Vraca testId ili null ako oblik ne odgovara.
 */
function extractTestId(name) {
  if (name === TEST_DOMAIN) return null; // ovo je apex, ne probe

  const prefix = name.slice(0, name.length - TEST_DOMAIN.length - 1); // skini ".<TEST_DOMAIN>"
  const parts = prefix.split('.');

  if (parts.length !== 2) return null; // ocekujemo tacno probeId.testId

  const [probeId, testId] = parts;
  // testId je uvek 32 hex karaktera (16 bajtova crypto.randomBytes) -
  // stroga provera oblika odbacuje besmislene/napadacke upite rano.
  if (!/^[a-f0-9]{32}$/.test(testId)) return null;
  if (!/^[a-f0-9]{1,64}$/.test(probeId)) return null;

  return testId;
}

function refused(request) {
  const response = Packet.createResponseFromRequest(request);
  response.header.rcode = Packet.RCODE.REFUSED;
  response.header.aa = 0;
  response.header.ra = 0;
  return response;
}

function nxdomain(request) {
  const response = Packet.createResponseFromRequest(request);
  response.header.rcode = Packet.RCODE.NXDOMAIN;
  response.header.aa = 1; // mi SMO autoritativni za ovu zonu, samo ime ne postoji
  response.header.ra = 0;
  return response;
}

function formErr(request) {
  const response = Packet.createResponseFromRequest(request);
  response.header.rcode = Packet.RCODE.FORMERR;
  response.header.aa = 0;
  response.header.ra = 0;
  return response;
}

function buildApexResponse(request, question) {
  const response = Packet.createResponseFromRequest(request);
  response.header.aa = 1;
  response.header.ra = 0;

  if (question.type === Packet.TYPE.SOA) {
    response.answers.push({
      name: question.name,
      type: Packet.TYPE.SOA,
      class: Packet.CLASS.IN,
      ttl: 60,
      primary: config.dns.nsHostname,
      admin: config.dns.adminEmail.replace('@', '.'),
      serial: parseInt(config.dns.soaSerial, 10) || 1,
      refresh: 3600,
      retry: 600,
      expiration: 604800,
      minimum: 60,
    });
  } else if (question.type === Packet.TYPE.NS) {
    response.answers.push({
      name: question.name,
      type: Packet.TYPE.NS,
      class: Packet.CLASS.IN,
      ttl: 3600,
      ns: config.dns.nsHostname,
    });
  }
  // Za ostale tipove na apex-u: NOERROR sa praznim ANSWER (nema podataka za taj tip).
  // Namerno NE implementiramo ANY ili velike TXT odgovore - amplification zastita.

  return response;
}

function buildProbeResponse(request, question, resolverIp) {
  const testId = extractTestId(question.name);

  if (!testId) {
    return nxdomain(request); // ne odgovara ocekivanom obliku probe imena
  }

  if (question.type !== Packet.TYPE.A) {
    // Podrzavamo samo A upite za probe imena. Za sve ostalo (AAAA, TXT, ANY...)
    // vracamo NOERROR/prazan odgovor - NIKAD veliki odgovor. Ovo je namerno
    // konzervativno: manje povrsine za amplification zloupotrebu.
    const response = Packet.createResponseFromRequest(request);
    response.header.aa = 1;
    response.header.ra = 0;
    return response;
  }

  const recorded = sessions.recordResolverHit(testId, resolverIp);
  if (!recorded) {
    return nxdomain(request); // testId ne postoji, istekao je, ili je sesija puna
  }

  const response = Packet.createResponseFromRequest(request);
  response.header.aa = 1;
  response.header.ra = 0;
  response.answers.push({
    name: question.name,
    type: Packet.TYPE.A,
    class: Packet.CLASS.IN,
    ttl: 1, // namerno minimalan TTL - sprecava keširanje ovog "probe" odgovora
    address: config.dns.answerIp,
  });
  return response;
}

function handleQuery(request, rinfo) {
  // Fail-closed: ako paket ima 0 ili vise od 1 pitanja, odbijamo. Standardni
  // DNS klijenti salju tacno jedno pitanje po upitu; visestruka pitanja su
  // ili malformisan paket ili pokusaj zloupotrebe.
  if (!request.questions || request.questions.length !== 1) {
    return formErr(request);
  }

  const question = request.questions[0];

  // Podrzavamo samo IN klasu (standardna internet klasa). Sve ostalo REFUSED.
  if (question.class !== undefined && question.class !== Packet.CLASS.IN) {
    return refused(request);
  }

  const name = normalizeName(question.name);

  if (!isInZone(name)) {
    // OVO JE KLJUCNA LINIJA KOJA SPRECAVA PONAVLJANJE INCIDENTA:
    // za bilo koje ime van nase zone, NIKAD ne gradimo odgovor sa podacima -
    // samo REFUSED, bez ANSWER sekcije, bez RA bita.
    return refused(request);
  }

  if (name === TEST_DOMAIN) {
    return buildApexResponse(request, question);
  }

  return buildProbeResponse(request, question, rinfo.address);
}

function safeHandle(request, send, rinfo) {
  try {
    const response = handleQuery(request, rinfo);
    send(response);
  } catch (err) {
    // Namerno NE logujemo ceo paket (mogao bi da sadrzi testId/IP podatke).
    // Namerno NE odgovaramo nista na paket koji je izazvao izuzetak pri
    // parsiranju/obradi - ne saljemo odgovor uopste je bezbednije od
    // slanja bilo cega kad ne znamo sta se tacno desilo (izbegava se
    // potencijalni amplification vektor kroz neocekivan/veliki fallback odgovor).
    console.error('[DNS] Doslo je do greske pri obradi upita - paket odbacen (bez odgovora).');
  }
}

let server = null;

function startDnsServer() {
  server = dns2.createServer({
    udp: true,
    tcp: true, // autoritativni DNS mora da podrzi i TCP (RFC 7766)
    handle: safeHandle,
  });

  server.on('listening', () => {
    console.log(
      `[DNS] Server slusa na ${config.dns.bindAddress}:${config.dns.port} (UDP+TCP), zona: ${TEST_DOMAIN}`
    );
  });

  server.on('error', (err) => {
    console.error('[DNS] Greska servera:', err.message);
  });

  server.listen({
    udp: { port: config.dns.port, address: config.dns.bindAddress, type: 'udp4' },
    tcp: { port: config.dns.port, address: config.dns.bindAddress },
  });
}

module.exports = { startDnsServer };
