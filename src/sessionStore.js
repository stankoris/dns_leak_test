/**
 * sessionStore.js
 *
 * Ovo je "srce" komunikacije izmedju dva potpuno odvojena servera koja ova
 * aplikacija pokrece u istom Node.js procesu:
 *
 *   1) DNS server (dns-server.js)  -> UPISUJE koji resolveri su ga pogodili
 *   2) HTTP API (routes/api.js)    -> CITA te podatke da bi ih vratio browseru
 *
 * Zasto obican JavaScript Map, a ne baza podataka?
 * Podaci su izuzetno kratkotrajni (test traje par sekundi, rezultat se gleda
 * jednom i vise nije potreban) i zive samo unutar jednog procesa - nema
 * potrebe da prezive restart servera niti da budu deljeni izmedju vise
 * servera. Baza bi ovde bila nepotreban overhead.
 *
 * VAZNO: DNS server i HTTP server MORAJU da rade u istom Node.js procesu da
 * bi delili ovaj Map iz memorije. Zato ih pokrecemo iz istog server.js
 * (pogledaj server.js - tamo se pozivaju oba startNotifier-a).
 */

const sessions = new Map();

let ttlSeconds = 180; // default, prepisuje se iz .env u server.js

function setTtl(seconds) {
  ttlSeconds = seconds;
}

/**
 * Kreira novu praznu sesiju testa.
 * @param {string} testId
 */
function createSession(testId) {
  sessions.set(testId, {
    createdAt: Date.now(),
    resolvers: new Map(), // key: IP resolvera, value: { firstSeen, count }
  });
}

/**
 * Poziva DNS server svaki put kad primi upit koji pripada nekom testId-u.
 * Koristimo Map za resolvers da automatski dedupliciramo isti IP (jedan
 * resolver ume da posalje vise upita za razlicite probe poddomene).
 */
function recordResolverHit(testId, resolverIp) {
  const session = sessions.get(testId);
  if (!session) return false;

  const existing = session.resolvers.get(resolverIp);
  if (existing) {
    existing.count += 1;
  } else {
    session.resolvers.set(resolverIp, { firstSeen: Date.now(), count: 1 });
  }
  return true;
}

/**
 * Poziva HTTP API kad browser trazi rezultate.
 * Vraca listu IP adresa (bez dodatnih detalja - geo lookup radi API sloj).
 */
function getResolvers(testId) {
  const session = sessions.get(testId);
  if (!session) return null;
  return Array.from(session.resolvers.entries()).map(([ip, meta]) => ({
    ip,
    count: meta.count,
  }));
}

function sessionExists(testId) {
  return sessions.has(testId);
}

/**
 * Ciscenje starih sesija da memorija ne raste u nedogled.
 * Pozivamo periodicno iz server.js (setInterval).
 */
function cleanupExpired() {
  const now = Date.now();
  for (const [testId, session] of sessions.entries()) {
    if (now - session.createdAt > ttlSeconds * 1000) {
      sessions.delete(testId);
    }
  }
}

module.exports = {
  setTtl,
  createSession,
  recordResolverHit,
  getResolvers,
  sessionExists,
  cleanupExpired,
};