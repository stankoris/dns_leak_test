'use strict';

const config = require('../config');

const buckets = new Map();

function cleanup(now) {
  for (const [key, bucket] of buckets) {
    if (now - bucket.windowStartedAt >= config.rateLimit.windowMs) {
      buckets.delete(key);
    }
  }
}

function allow(key) {
  const now = Date.now();
  if (buckets.size >= config.rateLimit.maxTrackedKeys) cleanup(now);

  let bucket = buckets.get(key);
  if (!bucket || now - bucket.windowStartedAt >= config.rateLimit.windowMs) {
    bucket = { windowStartedAt: now, count: 0 };
    buckets.set(key, bucket);
  }

  bucket.count += 1;
  return bucket.count <= config.rateLimit.max;
}

function rateLimit(req, res, next) {
  const key = req.ip || req.socket.remoteAddress || 'unknown';
  if (!allow(key)) {
    res.set('Retry-After', String(Math.ceil(config.rateLimit.windowMs / 1000)));
    return res.status(429).json({ error: 'Too many requests. Please wait a moment and try again.' });
  }
  next();
}

module.exports = { rateLimit };
