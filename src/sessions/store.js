'use strict';

const crypto = require('crypto');
const config = require('../config');

/**
 * sessions/store.js
 *
 * Bezbednosno bitna dizajnerska odluka: DNS testId (koji se vidi u DNS
 * upitima - a DNS upiti mogu da prolaze kroz tudje resolvere, koji ih mogu
 * logovati) NIJE isti identifikator koji se koristi za preuzimanje
 * rezultata preko HTTP-a. Umesto toga:
 *
 *   testId      -> koristi se SAMO kao DNS labela (vidljivo trecim stranama)
 *   resultToken -> koristi se SAMO za HTTP GET/DELETE rezultata (drzi ga
 *                  samo browser klijenta, nikad se ne stavlja u DNS upit)
 *
 * Oba su nezavisno generisana CSPRNG (crypto.randomBytes) sa 128 bita
 * entropije - poznavanje jednog ne pomaze u pogadjanju drugog.
 *
 * Isteklost sesije se NE oslanja iskljucivo na periodicni cleanup interval:
 * svaka read/write operacija sama proverava da li je TTL istekao, i ako
 * jeste, tretira sesiju kao da ne postoji (i uklanja je odmah).
 */

const sessionsByTestId = new Map();
const testIdByResultToken = new Map();

function generateId(byteLength = 16) {
  return crypto.randomBytes(byteLength).toString('hex'); // 128 bita entropije
}

function isExpired(session) {
  return Date.now() - session.createdAt > config.session.ttlSeconds * 1000;
}

function destroySession(testId) {
  const session = sessionsByTestId.get(testId);
  if (session) {
    testIdByResultToken.delete(session.resultToken);
    sessionsByTestId.delete(testId);
  }
}

/**
 * Vraca sesiju SAMO ako postoji i nije istekla. Ako je istekla, brise je
 * odmah (lazy expiration) i vraca null - tako da nijedan citalac nikad ne
 * vidi podatke stariji od deklarisanog TTL-a, bez obzira na to kada je
 * poslednji put istekao background cleanup interval.
 */
function getActiveSessionByTestId(testId) {
  const session = sessionsByTestId.get(testId);
  if (!session) return null;
  if (isExpired(session)) {
    destroySession(testId);
    return null;
  }
  return session;
}

function getActiveSessionByResultToken(resultToken) {
  const testId = testIdByResultToken.get(resultToken);
  if (!testId) return null;
  return getActiveSessionByTestId(testId);
}

/**
 * Kreira novu sesiju. Vraca null ako je dostignut MAX_ACTIVE_SESSIONS
 * limit (zastita od unbounded memory growth pri masovnom kreiranju
 * sesija - vidi rate limiter za dodatnu zastitu na HTTP sloju).
 */
function createSession({ privacyAcknowledged, termsAccepted }) {
  cleanupExpired(); // osvezi brojac pre provere limita

  if (sessionsByTestId.size >= config.session.maxActiveSessions) {
    return null;
  }

  const testId = generateId(16);
  const resultToken = generateId(16);

  const session = {
    testId,
    resultToken,
    createdAt: Date.now(),
    privacyAcknowledged: Boolean(privacyAcknowledged),
    termsAccepted: Boolean(termsAccepted),
    resolvers: new Map(), // ip -> { firstSeen, lastSeen, count }
  };

  sessionsByTestId.set(testId, session);
  testIdByResultToken.set(resultToken, testId);

  return session;
}

/**
 * Poziva DNS server kad primi validan probe upit za AKTIVNU sesiju.
 * NAMERNO ne loguje resolverIp nigde - samo ga upisuje u in-memory session
 * objekat, koji ce automatski nestati kad sesija istekne.
 */
function recordResolverHit(testId, resolverIp) {
  const session = getActiveSessionByTestId(testId);
  if (!session) return false;

  if (session.resolvers.size >= config.session.maxResolversPerSession) {
    // vec smo dostigli limit za ovu sesiju - odbacujemo dalje zapise da
    // spreci ovaj mehanizam da se koristi za pumpanje memorije jedne sesije
    if (!session.resolvers.has(resolverIp)) return false;
  }

  const now = Date.now();
  const existing = session.resolvers.get(resolverIp);
  if (existing) {
    existing.count += 1;
    existing.lastSeen = now;
  } else {
    session.resolvers.set(resolverIp, { firstSeen: now, lastSeen: now, count: 1 });
  }
  return true;
}

function getResolvers(resultToken) {
  const session = getActiveSessionByResultToken(resultToken);
  if (!session) return null;
  return Array.from(session.resolvers.entries()).map(([ip, meta]) => ({
    ip,
    count: meta.count,
  }));
}

function deleteByResultToken(resultToken) {
  const testId = testIdByResultToken.get(resultToken);
  if (!testId) return false;
  destroySession(testId);
  return true;
}

/**
 * Background "metla" - dodatno, ne umesto, provere pri svakom pristupu.
 * Postoji da oslobodi memoriju za sesije koje niko vise ne cita (pa se
 * lazy-expiration provera nikad ne bi ni pozvala za njih).
 */
function cleanupExpired() {
  const now = Date.now();
  for (const [testId, session] of sessionsByTestId.entries()) {
    if (now - session.createdAt > config.session.ttlSeconds * 1000) {
      destroySession(testId);
    }
  }
}

function activeSessionCount() {
  return sessionsByTestId.size;
}

module.exports = {
  createSession,
  getActiveSessionByTestId,
  getActiveSessionByResultToken,
  recordResolverHit,
  getResolvers,
  deleteByResultToken,
  cleanupExpired,
  activeSessionCount,
};
