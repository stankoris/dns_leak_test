/**
 * sessionStore.js
 *
 * Ovo je "srce" komunikacije izmedju dva potpuno odvojena servera koja ova
 * aplikacija pokrece u istom Node.js procesu:
 *
 *   1) DNS server (dns-server.js) -> UPISUJE koji resolveri su ga pogodili
 *   2) HTTP API (routes/api.js)   -> CITA te podatke da bi ih vratio browseru
 *
 * Zasto obican JavaScript Map, a ne baza podataka?
 * Podaci su izuzetno kratkotrajni (test traje par sekundi, rezultat se gleda
 * jednom i vise nije potreban) i zive samo unutar jednog procesa.
 *
 * Nema potrebe da prezive restart servera niti da budu deljeni izmedju vise
 * servera. Baza bi ovde bila nepotreban overhead.
 *
 * VAZNO:
 * DNS server i HTTP server MORAJU da rade u istom Node.js procesu da bi
 * delili ovaj Map iz memorije.
 */

const sessions = new Map();

let ttlSeconds = 180;

/**
 * Zastita od nekontrolisanog rasta memorije.
 *
 * Jedna DNS leak sesija realno ne bi trebalo da vidi veliki broj resolvera.
 * Limit od 50 ostavlja dosta prostora za neobicne konfiguracije, a sprecava
 * napadaca da jednu sesiju koristi za neograniceno punjenje memorije.
 */
const MAX_RESOLVERS_PER_SESSION = 50;

/**
 * Dodatna zastita za ukupan broj aktivnih sesija.
 *
 * Prava zastita od abuse-a treba da postoji i u HTTP API sloju kroz
 * rate limiting, ali ovaj limit predstavlja poslednju liniju odbrane.
 */
const MAX_ACTIVE_SESSIONS = 10_000;

/**
 * Postavlja koliko dugo sesija ostaje u memoriji.
 *
 * @param {number} seconds
 */
function setTtl(seconds) {
  if (!Number.isFinite(seconds) || seconds <= 0) {
    throw new Error("SESSION_TTL_SECONDS mora biti pozitivan broj.");
  }

  ttlSeconds = seconds;
}

/**
 * Kreira novu praznu sesiju testa.
 *
 * @param {string} testId
 * @returns {boolean}
 */
function createSession(testId) {
  if (typeof testId !== "string" || testId.length === 0) {
    return false;
  }

  /*
   * Nemoj dozvoliti da jedan testId pregazi vec postojecu sesiju.
   */
  if (sessions.has(testId)) {
    return false;
  }

  /*
   * Poslednja zastita od memory exhaustion napada.
   *
   * Rate limiting za kreiranje sesija cemo dodatno raditi u routes/api.js.
   */
  if (sessions.size >= MAX_ACTIVE_SESSIONS) {
    return false;
  }

  sessions.set(testId, {
    createdAt: Date.now(),

    /*
     * key:   IP resolvera
     * value: {
     *   firstSeen: timestamp,
     *   count: broj DNS upita
     * }
     */
    resolvers: new Map(),
  });

  return true;
}

/**
 * Poziva DNS server svaki put kada primi DNS upit koji pripada testId-u.
 *
 * Resolver moze poslati vise upita za razlicite probe subdomene.
 * Map automatski deduplicira resolver na osnovu njegove IP adrese.
 *
 * @param {string} testId
 * @param {string} resolverIp
 * @returns {boolean}
 */
function recordResolverHit(testId, resolverIp) {
  const session = sessions.get(testId);

  if (!session) {
    return false;
  }

  if (typeof resolverIp !== "string" || resolverIp.length === 0) {
    return false;
  }

  const existing = session.resolvers.get(resolverIp);

  if (existing) {
    /*
     * Ogranicavamo brojac da teoretski ne moze da raste zauvek.
     */
    if (existing.count < Number.MAX_SAFE_INTEGER) {
      existing.count += 1;
    }

    return true;
  }

  /*
   * Sprečava da napadac ubacuje neogranicen broj razlicitih resolver IP
   * adresa u jednu sesiju i time trosi RAM.
   */
  if (session.resolvers.size >= MAX_RESOLVERS_PER_SESSION) {
    return false;
  }

  session.resolvers.set(resolverIp, {
    firstSeen: Date.now(),
    count: 1,
  });

  return true;
}

/**
 * Poziva HTTP API kada browser trazi rezultate testa.
 *
 * Vraca samo podatke potrebne API sloju.
 * Geo/ISP lookup radi services/geoLookup.js.
 *
 * @param {string} testId
 * @returns {Array|null}
 */
function getResolvers(testId) {
  const session = sessions.get(testId);

  if (!session) {
    return null;
  }

  return Array.from(session.resolvers.entries()).map(([ip, meta]) => ({
    ip,
    count: meta.count,
  }));
}

/**
 * Proverava da li sesija postoji.
 *
 * @param {string} testId
 * @returns {boolean}
 */
function sessionExists(testId) {
  return sessions.has(testId);
}

/**
 * Brise jednu sesiju.
 *
 * Moze biti korisno ako kasnije odlucimo da obrisemo rezultat odmah nakon
 * sto ga browser preuzme.
 *
 * @param {string} testId
 * @returns {boolean}
 */
function deleteSession(testId) {
  return sessions.delete(testId);
}

/**
 * Cisti sesije kojima je istekao TTL.
 *
 * Poziva se periodicno iz server.js preko setInterval().
 */
function cleanupExpired() {
  const now = Date.now();
  const ttlMilliseconds = ttlSeconds * 1000;

  for (const [testId, session] of sessions.entries()) {
    if (now - session.createdAt >= ttlMilliseconds) {
      sessions.delete(testId);
    }
  }
}

/**
 * Korisno za monitoring/debugging.
 *
 * @returns {number}
 */
function getActiveSessionCount() {
  return sessions.size;
}

module.exports = {
  setTtl,
  createSession,
  recordResolverHit,
  getResolvers,
  sessionExists,
  deleteSession,
  cleanupExpired,
  getActiveSessionCount,
};