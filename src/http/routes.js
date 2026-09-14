'use strict';

const express = require('express');
const config = require('../config');
const sessions = require('../sessions/store');
const rateLimiter = require('../security/rateLimiter');
const geo = require('../geo/lookup');
const { noStore } = require('./security-headers');

const router = express.Router();

/**
 * POST /api/tests
 *
 * Server-side enforcement (ZAHTEV #18 iz specifikacije): ne verujemo
 * frontend JavaScript-u da je disable-ovao dugme dok checkboxovi nisu
 * cekirani. Bez oba flaga eksplicitno true u telu zahteva, sesija se NE
 * kreira - bez obzira sta klijent (ili neko ko direktno pogadja API bez
 * koriscenja nase stranice) posalje kao ostatak zahteva.
 */
router.post('/tests', express.json({ limit: '1kb' }), (req, res) => {
  if (rateLimiter.isRateLimited(req.ip)) {
    return res.status(429).json({ error: 'Previse zahteva. Sacekaj i pokusaj ponovo.' });
  }

  const { privacyAcknowledged, termsAccepted } = req.body || {};

  if (privacyAcknowledged !== true || termsAccepted !== true) {
    return res.status(400).json({
      error: 'Potrebno je eksplicitno prihvatiti Privacy Notice i Terms of Use pre pokretanja testa.',
    });
  }

  const session = sessions.createSession({ privacyAcknowledged, termsAccepted });

  if (!session) {
    return res.status(503).json({ error: 'Servis je trenutno pod velikim opterecenjem. Pokusaj kasnije.' });
  }

  res.json({
    testId: session.testId,
    resultToken: session.resultToken,
    dnsTestDomain: config.dns.testDomain,
    ttlSeconds: config.session.ttlSeconds,
  });
});

/**
 * GET /api/tests/:resultToken
 *
 * Namerno koristi resultToken, NE testId - testId je vidljiv DNS
 * infrastrukturi (resolveri ga vide u query imenu), pa ne zelimo da isti
 * string bude i "kljuc" za citanje rezultata testa. Vidi docs/THREAT-MODEL.md.
 */
router.get('/tests/:resultToken', noStore, async (req, res) => {
  if (rateLimiter.isRateLimited(req.ip)) {
    return res.status(429).json({ error: 'Previse zahteva. Sacekaj i pokusaj ponovo.' });
  }

  const { resultToken } = req.params;

  if (!/^[a-f0-9]{32}$/.test(resultToken)) {
    return res.status(400).json({ error: 'Neispravan format identifikatora.' });
  }

  const resolvers = sessions.getResolvers(resultToken);

  if (resolvers === null) {
    return res.status(404).json({ error: 'Sesija ne postoji ili je istekla.' });
  }

  const enriched = geo.isEnabled() ? geo.lookupMany(resolvers.map((r) => r.ip)) : resolvers.map((r) => ({ ip: r.ip }));

  const merged = enriched.map((g) => {
    const match = resolvers.find((r) => r.ip === g.ip);
    return { ...g, hitCount: match ? match.count : 0 };
  });

  res.json({
    resolverCount: merged.length,
    resolvers: merged,
    geoLookupEnabled: geo.isEnabled(),
  });
});

/**
 * DELETE /api/tests/:resultToken
 * Frontend poziva kad korisnik zavrsi/napusti stranicu ili klikne "Testiraj
 * ponovo" - dodatna, eksplicitna minimizacija podataka pre isteka TTL-a.
 */
router.delete('/tests/:resultToken', (req, res) => {
  const { resultToken } = req.params;

  if (!/^[a-f0-9]{32}$/.test(resultToken)) {
    return res.status(400).json({ error: 'Neispravan format identifikatora.' });
  }

  const deleted = sessions.deleteByResultToken(resultToken);
  res.status(deleted ? 204 : 404).end();
});

/**
 * GET /healthz
 * Namerno minimalan - ne otkriva internu konfiguraciju, verzije zavisnosti,
 * ni broj aktivnih sesija sa preciznoscu koja bi pomogla napadacu da
 * proceni kapacitet/opterecenje servisa.
 */
router.get('/healthz', (req, res) => {
  res.json({ status: 'ok' });
});

module.exports = router;
