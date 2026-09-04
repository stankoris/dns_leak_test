const express = require('express');
const sessionStore = require('../sessionStore');
const { generateId } = require('../utils/idGenerator');
const { lookupMany } = require('../services/geoLookup');

const router = express.Router();

const DNS_TEST_DOMAIN = process.env.DNS_TEST_DOMAIN || 'dnstest.example.com';
const PROBE_COUNT = parseInt(process.env.PROBE_COUNT || '8', 10);

/**
 * Vrlo jednostavan rate limiter po IP adresi da neko ne moze da spamuje
 * kreiranje sesija (svaka sesija zauzima memoriju dok ne istekne TTL).
 * Za ozbiljniju produkciju bi ovo islo kroz nginx/reverse-proxy rate
 * limiting, ali ova osnovna zastita je dovoljna za start.
 */
const lastRequestByIp = new Map();
const MIN_INTERVAL_MS = 3000;

function isRateLimited(ip) {
  const last = lastRequestByIp.get(ip);
  const now = Date.now();
  if (last && now - last < MIN_INTERVAL_MS) return true;
  lastRequestByIp.set(ip, now);
  return false;
}

/**
 * POST /api/test/start
 * Kreira novu test sesiju i vraca frontend-u sve sto mu treba da sam
 * generise probne poddomene (testId, domen, broj probe-ova).
 */
router.post('/test/start', (req, res) => {
  const clientIp = req.ip;

  if (isRateLimited(clientIp)) {
    return res.status(429).json({ error: 'Previse zahteva, sacekaj par sekundi.' });
  }

  const testId = generateId(6); // 12 hex karaktera
  sessionStore.createSession(testId);

  res.json({
    testId,
    dnsTestDomain: DNS_TEST_DOMAIN,
    probeCount: PROBE_COUNT,
  });
});

/**
 * GET /api/test/:testId/results
 * Vraca listu DNS resolvera koji su do sad pogodili nas DNS server za dati
 * testId, obogacenu geolokacijom/ISP podacima.
 */
router.get('/test/:testId/results', async (req, res) => {
  const { testId } = req.params;

  if (!sessionStore.sessionExists(testId)) {
    return res.status(404).json({ error: 'Sesija ne postoji ili je istekla.' });
  }

  const resolvers = sessionStore.getResolvers(testId);
  const enriched = await lookupMany(resolvers.map((r) => r.ip));

  const merged = enriched.map((geo) => {
    const match = resolvers.find((r) => r.ip === geo.ip);
    return { ...geo, hitCount: match ? match.count : 0 };
  });

  res.json({
    testId,
    resolverCount: merged.length,
    resolvers: merged,
  });
});

module.exports = router;