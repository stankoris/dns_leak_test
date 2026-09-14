'use strict';

const express = require('express');
const config = require('../config');
const sessions = require('../sessions/store');
const geo = require('../geo/lookup');
const { rateLimit } = require('../security/rateLimiter');

const router = express.Router();
const HEX_128 = /^[a-f0-9]{32}$/;

function noStore(res) {
  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');
}

router.get('/healthz', (req, res) => {
  noStore(res);
  res.json({ status: 'ok' });
});

router.post('/tests', rateLimit, (req, res) => {
  noStore(res);

  const privacyAcknowledged = req.body?.privacyAcknowledged === true;
  const termsAccepted = req.body?.termsAccepted === true;

  if (!privacyAcknowledged || !termsAccepted) {
    return res.status(400).json({
      error: 'Please acknowledge the Privacy Notice and accept the Terms of Use before starting the test.',
    });
  }

  const session = sessions.createSession({ privacyAcknowledged, termsAccepted });
  if (!session) {
    return res.status(503).json({ error: 'The test service is temporarily busy. Please try again shortly.' });
  }

  res.status(201).json({
    testId: session.testId,
    resultToken: session.resultToken,
    dnsTestDomain: config.dns.testDomain,
    probeCount: config.session.probeCount,
    ttlSeconds: config.session.ttlSeconds,
  });
});

router.get('/tests/:resultToken', rateLimit, async (req, res) => {
  noStore(res);

  const { resultToken } = req.params;
  if (!HEX_128.test(resultToken)) {
    return res.status(404).json({ error: 'Test session not found or expired.' });
  }

  const resolvers = sessions.getResolvers(resultToken);
  if (!resolvers) {
    return res.status(404).json({ error: 'Test session not found or expired.' });
  }

  const enrichment = await geo.lookupMany(resolvers.map((item) => item.ip));
  const detailsByIp = new Map(enrichment.map((item) => [item.ip, item]));

  res.json({
    resolverCount: resolvers.length,
    resolvers: resolvers.map((resolver) => ({
      ...resolver,
      ...(detailsByIp.get(resolver.ip) || {}),
    })),
    geoLookupEnabled: geo.enabled(),
  });
});

router.delete('/tests/:resultToken', rateLimit, (req, res) => {
  noStore(res);
  const { resultToken } = req.params;
  if (HEX_128.test(resultToken)) sessions.deleteByResultToken(resultToken);
  res.status(204).end();
});

module.exports = router;
