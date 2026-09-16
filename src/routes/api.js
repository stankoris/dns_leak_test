const express = require('express');

const sessionStore = require('../sessionStore');
const { generateId } = require('../utils/idGenerator');
const { lookupMany } = require('../services/geoLookup');

const router = express.Router();


/* -------------------------------------------------------------------------- */
/* Configuration                                                              */
/* -------------------------------------------------------------------------- */

const DNS_TEST_DOMAIN = (
  process.env.DNS_TEST_DOMAIN || 'dnstest.example.com'
)
  .toLowerCase()
  .replace(/\.$/, '');


const parsedProbeCount = Number.parseInt(
  process.env.PROBE_COUNT || '8',
  10
);

/*
 * DNS leak test nema potrebe da generise ogroman broj probe upita.
 *
 * Ako je .env vrednost nevalidna ili van dozvoljenog opsega,
 * vracamo se na default = 8.
 */
const PROBE_COUNT =
  Number.isInteger(parsedProbeCount) &&
  parsedProbeCount >= 1 &&
  parsedProbeCount <= 20
    ? parsedProbeCount
    : 8;


/*
 * generateId(16) daje 32 hex karaktera.
 *
 * Mora biti uskladjeno sa dns-server.js.
 */
const TEST_ID_REGEX = /^[a-f0-9]{32}$/;


/* -------------------------------------------------------------------------- */
/* Rate limiting                                                              */
/* -------------------------------------------------------------------------- */

/*
 * Ne koristimo neogranicen Map.
 *
 * Svaki limiter ima:
 *
 *   key       = client IP
 *   value     = { count, windowStartedAt }
 *
 * Kada prozor istekne, entry se resetuje.
 *
 * Ako Map dostigne MAX_RATE_LIMIT_ENTRIES, novi nepoznati IP-evi se
 * privremeno odbijaju umesto da dozvolimo neogranicen rast memorije.
 */
const MAX_RATE_LIMIT_ENTRIES = 10_000;


/*
 * /test/start
 *
 * Maksimalno 20 kreiranja testa u jednom minutu po IP adresi.
 *
 * To je u proseku jedno kreiranje na ~3 sekunde.
 */
const START_RATE_LIMIT = {
  windowMs: 60 * 1000,
  maxRequests: 20,
};


/*
 * /results frontend moze pozvati vise puta dok ceka DNS odgovore,
 * pa mu dozvoljavamo vise zahteva nego /start.
 */
const RESULTS_RATE_LIMIT = {
  windowMs: 60 * 1000,
  maxRequests: 120,
};


const startRequestsByIp = new Map();
const resultRequestsByIp = new Map();


/**
 * Brise istekle rate-limit zapise.
 *
 * Ovo radimo "lazy" tokom zahteva umesto setInterval(), tako da limiter
 * ne zahteva dodatni background timer.
 */
function cleanupRateLimitMap(map, windowMs) {
  const now = Date.now();

  for (const [key, entry] of map.entries()) {
    if (now - entry.windowStartedAt >= windowMs) {
      map.delete(key);
    }
  }
}


/**
 * Jednostavan fixed-window rate limiter.
 *
 * @param {Map} map
 * @param {string} key
 * @param {{windowMs: number, maxRequests: number}} config
 * @returns {boolean}
 */
function isRateLimited(map, key, config) {
  const now = Date.now();

  let entry = map.get(key);


  /*
   * Postojeci prozor je istekao.
   */
  if (
    entry &&
    now - entry.windowStartedAt >= config.windowMs
  ) {
    map.delete(key);
    entry = undefined;
  }


  /*
   * Novi IP.
   */
  if (!entry) {

    /*
     * Pre nego sto odbijemo novi IP, probamo da ocistimo
     * stare zapise.
     */
    if (map.size >= MAX_RATE_LIMIT_ENTRIES) {
      cleanupRateLimitMap(
        map,
        config.windowMs
      );
    }


    /*
     * Ako je limiter i dalje pun, ne dozvoljavamo dalje
     * povecavanje memorije.
     */
    if (map.size >= MAX_RATE_LIMIT_ENTRIES) {
      return true;
    }


    map.set(key, {
      count: 1,
      windowStartedAt: now,
    });

    return false;
  }


  /*
   * Postojeci IP.
   */
  if (entry.count >= config.maxRequests) {
    return true;
  }


  entry.count += 1;

  return false;
}


/* -------------------------------------------------------------------------- */
/* Helper functions                                                           */
/* -------------------------------------------------------------------------- */

function getClientIp(req) {
  /*
   * Koristimo iskljucivo req.ip.
   *
   * Kada aplikacija bude iza Nginx-a, Express "trust proxy" MORA biti
   * pravilno podesen u server.js.
   *
   * Ne citamo rucno X-Forwarded-For header jer bi klijent mogao da ga
   * falsifikuje ako proxy konfiguracija nije strogo kontrolisana.
   */
  return req.ip || 'unknown';
}


/* -------------------------------------------------------------------------- */
/* POST /api/test/start                                                       */
/* -------------------------------------------------------------------------- */

/**
 * Kreira novu DNS leak test sesiju.
 *
 * Browser dobija:
 *
 *   testId
 *   dnsTestDomain
 *   probeCount
 */
router.post('/test/start', (req, res) => {

  const clientIp = getClientIp(req);


  if (
    isRateLimited(
      startRequestsByIp,
      clientIp,
      START_RATE_LIMIT
    )
  ) {
    return res.status(429).json({
      error: 'Previse zahteva. Pokusaj ponovo malo kasnije.',
    });
  }


  /*
   * 16 bytes = 128 bits = 32 hex karaktera.
   *
   * Ovo mora biti isto sto ocekuje dns-server.js.
   */
  const testId = generateId();


  /*
   * createSession() moze vratiti false ako:
   *
   *   - testId vec postoji
   *   - dostignut je globalni session limit
   *
   * Kolizija ID-ja je prakticno nemoguca sa 128-bitnim ID-em,
   * tako da false najverovatnije znaci da je server dostigao limit.
   */
  const created =
    sessionStore.createSession(testId);


  if (!created) {
    return res.status(503).json({
      error: 'Server trenutno ne moze da kreira novu test sesiju.',
    });
  }


  /*
   * Rezultati testa su kratkotrajni i ne zelimo proxy/browser cache.
   */
  res.set('Cache-Control', 'no-store');


  return res.json({
    testId,
    dnsTestDomain: DNS_TEST_DOMAIN,
    probeCount: PROBE_COUNT,
  });
});


/* -------------------------------------------------------------------------- */
/* GET /api/test/:testId/results                                              */
/* -------------------------------------------------------------------------- */

/**
 * Vraca DNS resolvere koji su kontaktirali nas autoritativni DNS server.
 */
router.get('/test/:testId/results', async (req, res) => {

  const clientIp = getClientIp(req);


  /*
   * Rate limit radimo PRE geo lookup-a.
   *
   * Time sprecavamo da neko koristi ovaj endpoint za generisanje
   * velikog broja outbound zahteva.
   */
  if (
    isRateLimited(
      resultRequestsByIp,
      clientIp,
      RESULTS_RATE_LIMIT
    )
  ) {
    return res.status(429).json({
      error: 'Previse zahteva za rezultate. Pokusaj ponovo malo kasnije.',
    });
  }


  const { testId } = req.params;


  /* ---------------------------------------------------------------------- */
  /* testId validation                                                       */
  /* ---------------------------------------------------------------------- */

  if (
    typeof testId !== 'string' ||
    !TEST_ID_REGEX.test(testId)
  ) {
    return res.status(400).json({
      error: 'Nevalidan test ID.',
    });
  }


  /* ---------------------------------------------------------------------- */
  /* Session validation                                                      */
  /* ---------------------------------------------------------------------- */

  if (!sessionStore.sessionExists(testId)) {
    return res.status(404).json({
      error: 'Sesija ne postoji ili je istekla.',
    });
  }


  const resolvers =
    sessionStore.getResolvers(testId);


  /*
   * Teoretski session moze nestati izmedju sessionExists()
   * i getResolvers() ako kasnije promenimo nacin cleanup-a.
   *
   * Zato ipak proveravamo rezultat.
   */
  if (!Array.isArray(resolvers)) {
    return res.status(404).json({
      error: 'Sesija ne postoji ili je istekla.',
    });
  }


  /* ---------------------------------------------------------------------- */
  /* Geo / ISP lookup                                                        */
  /* ---------------------------------------------------------------------- */

  const ips =
    resolvers.map((resolver) => resolver.ip);


  const enriched =
    await lookupMany(ips);


  /*
   * Napravimo Map umesto da za svaki geo rezultat koristimo Array.find().
   */
  const hitCounts = new Map(
    resolvers.map((resolver) => [
      resolver.ip,
      resolver.count,
    ])
  );


  const merged = enriched.map((geo) => ({
    ...geo,

    hitCount:
      hitCounts.get(geo.ip) || 0,
  }));


  /* ---------------------------------------------------------------------- */
  /* Response                                                                */
  /* ---------------------------------------------------------------------- */

  res.set('Cache-Control', 'no-store');


  return res.json({
    testId,

    resolverCount:
      merged.length,

    resolvers:
      merged,
  });
});


module.exports = router;