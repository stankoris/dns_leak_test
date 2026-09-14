'use strict';

const config = require('./config');
const sessions = require('./sessions/store');
const rateLimiter = require('./security/rateLimiter');
const geo = require('./geo/lookup');
const { startHttpServer } = require('./http/server');
const { startDnsServer } = require('./dns/server');

/**
 * index.js
 *
 * ARHITEKTONSKA NAPOMENA (namerno dokumentovano, ne skriveno):
 *
 * DNS i HTTP servis rade u ISTOM Node.js procesu, jer dele in-memory
 * sessionStore (potrebno da bi DNS upiti mogli da upisu resolver IP, a
 * HTTP API da ga procita, bez dodatne infrastrukture poput Redis-a).
 *
 * Ovo je namerni kompromis radi jednostavnosti za pocetnu produkciju
 * jednog servisa. Da bi se DNS i HTTP potpuno izolovali (preporuceno za
 * vecu komercijalnu instalaciju - vidi docs/THREAT-MODEL.md, "Process
 * isolation"), potreban je deljeni store van procesa (npr. Redis vezan
 * SAMO na loopback, bez perzistencije, sa strogim TTL-om) i dva odvojena
 * systemd servisa. To NIJE implementirano u ovoj verziji - ostavljeno je
 * kao eksplicitno dokumentovano ogranicenje, ne kao tiha pretpostavka.
 *
 * Zbog toga: safeHandle() u dns/server.js hvata SVE izuzetke iz obrade
 * paketa, tako da malformisan DNS paket ne moze da obori ceo proces
 * (ukljucujuci HTTP deo) - ovo je delimicna ublazujuca mera dok se ne
 * uvede puna procesna izolacija.
 */

async function main() {
  await geo.init();

  startHttpServer();
  startDnsServer();

  setInterval(() => {
    sessions.cleanupExpired();
    rateLimiter.cleanupExpired();
  }, 30_000);

  console.log(`[APP] Pokrenuto (NODE_ENV=${config.nodeEnv}). Aktivnih sesija: ${sessions.activeSessionCount()}`);
}

main().catch((err) => {
  console.error('[APP] Fatalna greska pri pokretanju:', err.message);
  process.exit(1);
});
