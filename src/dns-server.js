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
 *   - prihvata probe hostname formata:
 *
 *       <probeId>.<testId>.<DNS_TEST_DOMAIN>
 *
 * Primer:
 *
 *   7d8a...e21.91bc...a44.dnsleaktest.firewallmindset.site
 *
 * probeId i testId su 128-bitni ID-jevi,
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

const DNS_TEST_DOMAIN = (
  process.env.DNS_TEST_DOMAIN ||
  'dnstest.example.com'
)
  .toLowerCase()
  .replace(/\.$/, '');


const DNS_NAMESERVER = (
  process.env.DNS_NAMESERVER ||
  'ns1.firewallmindset.site'
)
  .toLowerCase()
  .replace(/\.$/, '');


const DNS_PORT = Number.parseInt(
  process.env.DNS_PORT || '53',
  10
);


const DNS_ANSWER_IP =
  process.env.DNS_ANSWER_IP || '203.0.113.1';


/*
 * SOA = Start of Authority.
 *
 * primary:
 *   glavni autoritativni nameserver za ovu zonu
 *
 * admin:
 *   DNS format email adrese:
 *
 *   hostmaster.firewallmindset.site
 *
 * predstavlja:
 *
 *   hostmaster@firewallmindset.site
 */
const SOA = {
  primary: DNS_NAMESERVER,

  admin: 'hostmaster.firewallmindset.site',

  /*
   * Format:
   *
   * YYYYMMDDNN
   *
   * Ako kasnije menjas zone podatke, povecaj serial.
   */
  serial: 2026092101,

  refresh: 3600,

  retry: 600,

  expiration: 604800,

  minimum: 60,
};


/* -------------------------------------------------------------------------- */
/* Configuration validation                                                   */
/* -------------------------------------------------------------------------- */

if (
  !Number.isInteger(DNS_PORT) ||
  DNS_PORT < 1 ||
  DNS_PORT > 65535
) {
  throw new Error(
    'DNS_PORT mora biti validan TCP/UDP port.'
  );
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


if (
  !DNS_NAMESERVER ||
  DNS_NAMESERVER.length > 253
) {
  throw new Error(
    'DNS_NAMESERVER nije validan DNS hostname.'
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
/* DNS record helpers                                                         */
/* -------------------------------------------------------------------------- */

/**
 * Kreira SOA record.
 *
 * Koristimo ga:
 *
 *   - kada neko direktno pita za SOA
 *   - u authority sekciji kod NXDOMAIN/NODATA odgovora
 */
function createSoaRecord() {
  return {
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
  };
}


/**
 * Dodaje SOA u authority sekciju.
 */
function addSoaAuthority(response) {
  response.authorities.push(
    createSoaRecord()
  );
}


/* -------------------------------------------------------------------------- */
/* Hostname parsing                                                           */
/* -------------------------------------------------------------------------- */

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
 * Proverava da li query pripada nasoj DNS zoni.
 *
 * Validno:
 *
 * dnsleaktest.firewallmindset.site
 *
 * ili:
 *
 * anything.dnsleaktest.firewallmindset.site
 */
function isInsideTestDomain(queryName) {
  const name =
    normalizeName(queryName);

  return (
    name === DNS_TEST_DOMAIN ||
    name.endsWith(`.${DNS_TEST_DOMAIN}`)
  );
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
  const name =
    normalizeName(queryName);

  const suffix =
    `.${DNS_TEST_DOMAIN}`;


  if (!name.endsWith(suffix)) {
    return null;
  }


  const prefix =
    name.slice(
      0,
      name.length - suffix.length
    );


  const parts =
    prefix.split('.');


  /*
   * Mora biti TACNO:
   *
   * probeId.testId
   */
  if (parts.length !== 2) {
    return null;
  }


  const [
    probeId,
    testId,
  ] = parts;


  /*
   * Oba ID-ja moraju biti:
   *
   * 32 hex karaktera
   * = 128 bita
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
   * Autoritativni DNS server podrzava:
   *
   * UDP :53
   * TCP :53
   */
  udp: true,

  tcp: true,


  handle: (request, send, rinfo) => {

    /* ---------------------------------------------------------------------- */
    /* Malformed request                                                      */
    /* ---------------------------------------------------------------------- */

    /*
     * Paket je mogao da bude parsiran, ali sadrzi greske.
     */
    if (request.errors?.length) {

      const response =
        Packet.createResponseFromRequest(
          request
        );


      response.header.rcode =
        Packet.RCODE.FORMERR;


      /*
       * Rekurzija nije dostupna.
       */
      response.header.ra = 0;


      return send(response);
    }


    /* ---------------------------------------------------------------------- */
    /* Question validation                                                    */
    /* ---------------------------------------------------------------------- */

    /*
     * Nas servis ocekuje TACNO jedno DNS pitanje.
     */
    if (
      !Array.isArray(request.questions) ||
      request.questions.length !== 1
    ) {

      const response =
        Packet.createResponseFromRequest(
          request
        );


      response.header.rcode =
        Packet.RCODE.FORMERR;


      response.header.ra = 0;


      return send(response);
    }


    const question =
      request.questions[0];


    const response =
      Packet.createResponseFromRequest(
        request
      );


    /*
     * RA = Recursion Available
     *
     * 0:
     *
     * Ovaj server nikada ne radi rekurziju.
     */
    response.header.ra = 0;


    const queryName =
      normalizeName(
        question.name
      );


    /* ---------------------------------------------------------------------- */
    /* Query van nase zone                                                    */
    /* ---------------------------------------------------------------------- */

    /*
     * Primer:
     *
     * google.com
     *
     * example.org
     *
     * Mi nismo autoritativni za te zone.
     */
    if (
      !isInsideTestDomain(
        queryName
      )
    ) {

      response.header.aa = 0;


      response.header.rcode =
        Packet.RCODE.REFUSED;


      return send(response);
    }


    /*
     * Od ovog trenutka znamo da query pripada nasoj zoni.
     *
     * AA = Authoritative Answer
     */
    response.header.aa = 1;


    /* ---------------------------------------------------------------------- */
    /* DNS class validation                                                   */
    /* ---------------------------------------------------------------------- */

    /*
     * Podrzavamo samo standardnu:
     *
     * IN = Internet
     */
    if (
      question.class !==
      Packet.CLASS.IN
    ) {

      response.header.rcode =
        Packet.RCODE.REFUSED;


      return send(response);
    }


    /* ---------------------------------------------------------------------- */
    /* Zone apex                                                              */
    /* ---------------------------------------------------------------------- */

    /*
     * Apex zone:
     *
     * dnsleaktest.firewallmindset.site
     *
     * Ovo je potrebno da se server ponasa kao pravi autoritativni
     * DNS server nakon NS delegacije.
     */
    if (
      queryName ===
      DNS_TEST_DOMAIN
    ) {

      /* -------------------------------------------------------------------- */
      /* NS                                                                   */
      /* -------------------------------------------------------------------- */

      if (
        question.type ===
        Packet.TYPE.NS
      ) {

        response.answers.push({
          name: DNS_TEST_DOMAIN,

          type: Packet.TYPE.NS,

          class: Packet.CLASS.IN,

          ttl: 300,

          data: DNS_NAMESERVER,
        });


        return send(response);
      }


      /* -------------------------------------------------------------------- */
      /* SOA                                                                  */
      /* -------------------------------------------------------------------- */

      if (
        question.type ===
        Packet.TYPE.SOA
      ) {

        response.answers.push(
          createSoaRecord()
        );


        return send(response);
      }


      /*
       * Zona postoji, ali nema trazeni record.
       *
       * Primer:
       *
       * dnsleaktest.firewallmindset.site AAAA
       *
       * To je NOERROR sa praznim answerom + SOA authority.
       */
      addSoaAuthority(
        response
      );


      return send(response);
    }


    /* ---------------------------------------------------------------------- */
    /* Probe hostname validation                                              */
    /* ---------------------------------------------------------------------- */

    const probe =
      extractProbeInfo(
        queryName
      );


    /*
     * Query jeste unutar nase zone,
     * ali nije validna probe adresa.
     *
     * Primer:
     *
     * random.dnsleaktest.firewallmindset.site
     */
    if (!probe) {

      response.header.rcode =
        Packet.RCODE.NXDOMAIN;


      addSoaAuthority(
        response
      );


      return send(response);
    }


    const {
      testId,
    } = probe;


    /* ---------------------------------------------------------------------- */
    /* Session validation                                                     */
    /* ---------------------------------------------------------------------- */

    /*
     * Test mora trenutno postojati u sessionStore-u.
     *
     * Ako je session istekao ili je testId nasumican,
     * hostname ne postoji.
     */
    if (
      !sessionStore.sessionExists(
        testId
      )
    ) {

      response.header.rcode =
        Packet.RCODE.NXDOMAIN;


      addSoaAuthority(
        response
      );


      return send(response);
    }


    /* ---------------------------------------------------------------------- */
    /* Resolver recording                                                     */
    /* ---------------------------------------------------------------------- */

    /*
     * rinfo.address je IP masine koja je DIREKTNO kontaktirala
     * nas autoritativni DNS server.
     *
     * To moze biti:
     *
     * Cloudflare DNS
     * Google DNS
     * VPN DNS
     * ISP DNS
     * itd.
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
     * NAMERNO ne logujemo svaki DNS query.
     *
     * Na javnom UDP servisu bi napadac mogao da generise
     * ogroman broj logova i puni journald/disk.
     */


    /* ---------------------------------------------------------------------- */
    /* A record                                                               */
    /* ---------------------------------------------------------------------- */

    if (
      question.type ===
      Packet.TYPE.A
    ) {

      response.answers.push({
        name: question.name,

        type: Packet.TYPE.A,

        class: Packet.CLASS.IN,

        /*
         * Svaka probe koristi jedinstven hostname.
         *
         * Kratak TTL dodatno smanjuje kesiranje.
         */
        ttl: 1,

        address: DNS_ANSWER_IP,
      });


      return send(response);
    }


    /* ---------------------------------------------------------------------- */
    /* Other record types                                                     */
    /* ---------------------------------------------------------------------- */

    /*
     * Primer:
     *
     * AAAA
     * TXT
     * MX
     * ANY
     *
     * Hostname postoji, ali nemamo taj record type.
     *
     * Zato vracamo:
     *
     * NOERROR
     * 0 answers
     * SOA u authority sekciji
     *
     * Resolver smo ipak zabelezili jer je DNS upit
     * stigao do naseg autoritativnog servera.
     */
    addSoaAuthority(
      response
    );


    return send(response);
  },
});


/* -------------------------------------------------------------------------- */
/* Server events                                                              */
/* -------------------------------------------------------------------------- */

server.on(
  'listening',
  () => {

    console.log(
      `[DNS] Authoritative DNS server aktivan: *.${DNS_TEST_DOMAIN} port=${DNS_PORT}`
    );
  }
);


/*
 * Ne logujemo svaki malformed paket.
 *
 * Public DNS server moze biti floodovan namerno losim paketima,
 * pa bi unlimited logovanje moglo da puni disk.
 *
 * Maksimalno jedan warning u 60 sekundi.
 */
let lastRequestErrorLog = 0;


server.on(
  'requestError',
  () => {

    const now =
      Date.now();


    if (
      now - lastRequestErrorLog <
      60_000
    ) {
      return;
    }


    lastRequestErrorLog =
      now;


    console.warn(
      '[DNS] Odbijen nevalidan DNS paket.'
    );
  }
);


server.on(
  'error',
  (err) => {

    console.error(
      '[DNS] Server greska:',
      err
    );
  }
);


server.on(
  'close',
  () => {

    console.log(
      '[DNS] Server ugasen.'
    );
  }
);


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
/* Stop                                                                       */
/* -------------------------------------------------------------------------- */

/**
 * Graceful shutdown DNS servera.
 *
 * server.close() zaustavlja UDP/TCP listenere.
 *
 * Promise se zavrsava tek kada dns2 emituje "close".
 */
function stopDnsServer() {

  return new Promise(
    (resolve, reject) => {

      const handleClose = () => {
        cleanup();

        resolve();
      };


      const handleError = (err) => {
        cleanup();

        reject(err);
      };


      const cleanup = () => {
        server.off(
          'close',
          handleClose
        );

        server.off(
          'error',
          handleError
        );
      };


      server.once(
        'close',
        handleClose
      );


      server.once(
        'error',
        handleError
      );


      try {

        server.close();

      } catch (err) {

        cleanup();

        reject(err);
      }
    }
  );
}


/* -------------------------------------------------------------------------- */
/* Exports                                                                    */
/* -------------------------------------------------------------------------- */

module.exports = {
  startDnsServer,
  stopDnsServer,
};