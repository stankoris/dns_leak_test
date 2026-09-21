/**
 * dns-server.js
 *
 * Autoritativni DNS server za DNS leak test.
 *
 * Ovaj server:
 *   - slusa UDP i TCP port 53
 *   - odgovara samo za DNS_TEST_DOMAIN zonu
 *   - NE radi DNS rekurziju
 *   - belezi IP resolvera koji direktno kontaktira server
 *   - prihvata samo hostname formata:
 *
 *       <probeId>.<testId>.<DNS_TEST_DOMAIN>
 *
 * Primer:
 *
 *   7d8a...e21.91bc...a44.dnsleaktest.firewallmindset.site
 *
 * probeId i testId su 128-bitni ID-jevi generisani sa crypto.randomBytes(16),
 * odnosno 32 hex karaktera.
 */

require('dotenv').config();

const net = require('net');
const dns2 = require('dns2');

const { Packet } = dns2;

const sessionStore = require('./sessionStore');


/* -------------------------------------------------------------------------- */
/* Configuration                                                              */
/* -------------------------------------------------------------------------- */

const DNS_NAMESERVER = 'ns1.firewallmindset.site';

const SOA = {
  primary: DNS_NAMESERVER,
  admin: 'hostmaster.firewallmindset.site',
  serial: 2026092101,
  refresh: 3600,
  retry: 600,
  expiration: 604800,
  minimum: 60,
};

const DNS_TEST_DOMAIN = (
  process.env.DNS_TEST_DOMAIN ||
  'dnstest.example.com'
)
  .toLowerCase()
  .replace(/\.$/, '');


const DNS_PORT = Number.parseInt(
  process.env.DNS_PORT || '53',
  10
);


const DNS_ANSWER_IP =
  process.env.DNS_ANSWER_IP || '203.0.113.1';


/* -------------------------------------------------------------------------- */
/* Configuration validation                                                   */
/* -------------------------------------------------------------------------- */

if (
  !Number.isInteger(DNS_PORT) ||
  DNS_PORT < 1 ||
  DNS_PORT > 65535
) {
  throw new Error('DNS_PORT mora biti validan TCP/UDP port.');
}


if (!net.isIPv4(DNS_ANSWER_IP)) {
  throw new Error(
    'DNS_ANSWER_IP mora biti validna IPv4 adresa.'
  );
}


if (
  !DNS_TEST_DOMAIN ||
  DNS_TEST_DOMAIN.length > 253
) {
  throw new Error(
    'DNS_TEST_DOMAIN nije validan DNS domen.'
  );
}


/* -------------------------------------------------------------------------- */
/* Constants                                                                  */
/* -------------------------------------------------------------------------- */

/*
 * generateId(16) daje:
 *
 * 16 bytes = 128 bits
 * hex       = 32 karaktera
 */
const ID_REGEX = /^[a-f0-9]{32}$/;


/* -------------------------------------------------------------------------- */
/* Hostname parsing                                                           */
/* -------------------------------------------------------------------------- */

/**
 * Proverava da li query pripada nasoj DNS zoni.
 */
function isInsideTestDomain(queryName) {
  const name = normalizeName(queryName);

  return (
    name === DNS_TEST_DOMAIN ||
    name.endsWith(`.${DNS_TEST_DOMAIN}`)
  );
}


/**
 * Uklanja trailing "." i pretvara hostname u lowercase.
 */
function normalizeName(queryName) {
  if (typeof queryName !== 'string') {
    return '';
  }

  return queryName
    .toLowerCase()
    .replace(/\.$/, '');
}


/**
 * Ocekujemo TACNO:
 *
 *   <probeId>.<testId>.<DNS_TEST_DOMAIN>
 *
 * Ne prihvatamo:
 *
 *   foo.<probe>.<test>.<domain>
 *   <test>.<domain>
 *   random.<domain>
 *
 * @returns {{ probeId: string, testId: string } | null}
 */
function extractProbeInfo(queryName) {
  const name = normalizeName(queryName);

  const suffix = `.${DNS_TEST_DOMAIN}`;

  if (!name.endsWith(suffix)) {
    return null;
  }

  const prefix = name.slice(
    0,
    name.length - suffix.length
  );

  const parts = prefix.split('.');

  /*
   * Mora biti TACNO:
   *
   * probeId.testId
   */
  if (parts.length !== 2) {
    return null;
  }

  const [probeId, testId] = parts;

  /*
   * Oba ID-ja moraju biti 128-bitni hex stringovi.
   */
  if (
    !ID_REGEX.test(probeId) ||
    !ID_REGEX.test(testId)
  ) {
    return null;
  }

  return {
    probeId,
    testId,
  };
}


/* -------------------------------------------------------------------------- */
/* DNS server                                                                 */
/* -------------------------------------------------------------------------- */

const server = dns2.createServer({

  /*
   * DNS mora da podrzava oba transporta.
   */
  udp: true,
  tcp: true,


  handle: (request, send, rinfo) => {

    /*
     * dns2 je uspeo da parsira paket, ali je tokom parsiranja
     * pronasao problem.
     *
     * Vracamo minimalni FORMERR odgovor.
     */
    if (request.errors?.length) {
      const response =
        Packet.createResponseFromRequest(request);

      response.header.rcode =
        Packet.RCODE.FORMERR;

      response.header.ra = 0;

      return send(response);
    }


    /*
     * Nas servis ocekuje tacno jedno DNS pitanje.
     *
     * Ovo dodatno pojednostavljuje server i sprecava neobicne
     * multi-question pakete.
     */
    if (
      !Array.isArray(request.questions) ||
      request.questions.length !== 1
    ) {
      const response =
        Packet.createResponseFromRequest(request);

      response.header.rcode =
        Packet.RCODE.FORMERR;

      response.header.ra = 0;

      return send(response);
    }


    const question = request.questions[0];

    const response =
      Packet.createResponseFromRequest(request);


    /*
     * Ovaj server NIKADA ne radi rekurziju.
     *
     * RA = Recursion Available
     *
     * 0 znaci:
     *
     * "Nemoj od mene traziti da resolve-ujem druge domene."
     */
    response.header.ra = 0;


    const queryName =
      normalizeName(question.name);


    /* ---------------------------------------------------------------------- */
    /* Query van nase zone                                                    */
    /* ---------------------------------------------------------------------- */

    /*
     * Primer:
     *
     *   google.com
     *   example.org
     *
     * Mi nismo autoritativni za njih i ne pokusavamo da ih resolve-ujemo.
     */
    if (!isInsideTestDomain(queryName)) {

      response.header.aa = 0;

      response.header.rcode =
        Packet.RCODE.REFUSED;

      return send(response);
    }


    /*
     * Od ovog trenutka znamo da je query unutar nase zone.
     */
    response.header.aa = 1;


    /* ---------------------------------------------------------------------- */
    /* Validacija klase                                                       */
    /* ---------------------------------------------------------------------- */

    /*
     * Nas servis radi samo sa Internet klasom (IN).
     */
    if (question.class !== Packet.CLASS.IN) {

      response.header.rcode =
        Packet.RCODE.REFUSED;

      return send(response);
    }

    
 /*
 * Apex zone records:
 *
 * dnsleaktest.firewallmindset.site NS
 * dnsleaktest.firewallmindset.site SOA
 */
if (queryName === DNS_TEST_DOMAIN) {

  if (question.type === Packet.TYPE.NS) {
    response.answers.push({
      name: DNS_TEST_DOMAIN,
      type: Packet.TYPE.NS,
      class: Packet.CLASS.IN,
      ttl: 300,
      data: DNS_NAMESERVER,
    });

    return send(response);
  }


  if (question.type === Packet.TYPE.SOA) {
    response.answers.push({
      name: DNS_TEST_DOMAIN,
      type: Packet.TYPE.SOA,
      class: Packet.CLASS.IN,
      ttl: 300,

      primary: SOA.primary,
      admin: SOA.admin,
      serial: SOA.serial,
      refresh: SOA.refresh,
      retry: SOA.retry,
      expiration: SOA.expiration,
      minimum: SOA.minimum,
    });

    return send(response);
  }


  /*
   * Zona postoji, ali nema record trazenog tipa.
   */
  return send(response);
}

    /* ---------------------------------------------------------------------- */
    /* Validacija probe hostname-a                                            */
    /* ---------------------------------------------------------------------- */

    const probe =
      extractProbeInfo(queryName);


    /*
     * Query pripada nasoj zoni ali hostname nije validna probe adresa.
     *
     * Primer:
     *
     *   random.dnsleaktest.firewallmindset.site
     *
     * Za nas takvo ime ne postoji.
     */
    if (!probe) {

      response.header.rcode =
        Packet.RCODE.NXDOMAIN;

      return send(response);
    }


    const { testId } = probe;


    /* ---------------------------------------------------------------------- */
    /* Provera sesije                                                         */
    /* ---------------------------------------------------------------------- */

    /*
     * Ne odgovaramo A zapisom ako testId vise ne postoji.
     *
     * Ovo sprecava da stari/random probe domeni zauvek budu validni.
     */
    if (!sessionStore.sessionExists(testId)) {

      response.header.rcode =
        Packet.RCODE.NXDOMAIN;

      return send(response);
    }


    /* ---------------------------------------------------------------------- */
    /* Belezenje resolvera                                                    */
    /* ---------------------------------------------------------------------- */

    /*
     * rinfo.address je IP masine koja je DIREKTNO kontaktirala
     * nas autoritativni DNS server.
     *
     * Najcesce je to recursive DNS resolver:
     *
     *   Cloudflare
     *   Google
     *   ISP DNS
     *   VPN DNS
     *   itd.
     */
    if (
      rinfo &&
      typeof rinfo.address === 'string'
    ) {
      sessionStore.recordResolverHit(
        testId,
        rinfo.address
      );
    }


    /*
     * NAMERNO nema console.log() za svaki DNS query.
     *
     * Javni UDP servis moze dobiti veliki broj paketa.
     * Logovanje svakog paketa bi omogucilo napadacu da puni:
     *
     *   journald
     *   disk
     *   stdout
     *
     * i nepotrebno trosi CPU.
     */


    /* ---------------------------------------------------------------------- */
    /* A query                                                                */
    /* ---------------------------------------------------------------------- */

    if (question.type === Packet.TYPE.A) {

      response.answers.push({
        name: question.name,

        type: Packet.TYPE.A,

        class: Packet.CLASS.IN,

        /*
         * Vrlo kratak TTL jer svaka probe koristi jedinstveni hostname.
         */
        ttl: 1,

        address: DNS_ANSWER_IP,
      });

      return send(response);
    }


    /* ---------------------------------------------------------------------- */
    /* Ostali record tipovi                                                   */
    /* ---------------------------------------------------------------------- */

    /*
     * Na primer:
     *
     *   AAAA
     *   TXT
     *   MX
     *   ANY
     *
     * Hostname postoji, ali mi nemamo record tog tipa.
     *
     * Zato vracamo:
     *
     *   NOERROR
     *   0 answers
     *
     * umesto da izmisljamo A record.
     *
     * Resolver hit smo ipak zabelezili jer je sam DNS upit validan
     * signal za leak test.
     */

    return send(response);
  },
});


/* -------------------------------------------------------------------------- */
/* Server events                                                              */
/* -------------------------------------------------------------------------- */

server.on('listening', () => {
  console.log(
    `[DNS] Authoritative DNS server aktivan: *.${DNS_TEST_DOMAIN} port=${DNS_PORT}`
  );
});


/*
 * Paket nije mogao ni da bude normalno dekodiran.
 *
 * Ovde ne logujemo raw paket ili korisnicki input.
 */
server.on('requestError', (err) => {
  console.warn(
    `[DNS] Nevalidan DNS paket: ${err.message}`
  );
});


server.on('error', (err) => {
  console.error(
    '[DNS] Server greska:',
    err
  );
});


/* -------------------------------------------------------------------------- */
/* Start                                                                      */
/* -------------------------------------------------------------------------- */

function startDnsServer() {

  server.listen({

    udp: {
      port: DNS_PORT,
      address: '0.0.0.0',
    },

    tcp: {
      port: DNS_PORT,
      address: '0.0.0.0',
    },

  });
}

/* -------------------------------------------------------------------------- */
/* Stop                                                                   */
/* -------------------------------------------------------------------------- */


function stopDnsServer() {
  return new Promise((resolve, reject) => {
    server.close((err) => {
      if (err) {
        reject(err);
        return;
      }

      resolve();
    });
  });
}

module.exports = {
  startDnsServer,
  stopDnsServer,
};