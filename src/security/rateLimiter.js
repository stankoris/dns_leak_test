'use strict';

const crypto = require('crypto');
const config = require('../config');

/**
 * security/rateLimiter.js
 *
 * Prethodna verzija je cuvala sirove IP adrese posetilaca u Map-i bez
 * eksplicitne ekspiracije. Ova verzija:
 *
 *  1) NIKAD ne cuva sirovu IP adresu - umesto toga racuna HMAC(IP) sa
 *     tajnim kljucem generisanim SAMO u memoriji pri startu procesa
 *     (nikad ne perzistira na disk, nikad se ne loguje). Kljuc se menja
 *     na svaki restart procesa, sto dodatno smanjuje mogucnost
 *     dugorocnog povezivanja zapisa sa konkretnom IP adresom.
 *  2) Automatski ciscenje isteklih unosa.
 *  3) Gornju granicu broja pracenih kljuceva (maxTrackedKeys) - da napadac
 *     koji salje zahteve sa hiljada razlicitih IP adresa ne moze da
 *     neograniceno napumpa memoriju rate limiter-a.
 */

const hmacSecret = crypto.randomBytes(32); // samo u memoriji, po restartu procesa

function pseudonymize(ip) {
  return crypto.createHmac('sha256', hmacSecret).update(ip).digest('hex');
}

const buckets = new Map(); // pseudonym -> { count, windowStart }

function isRateLimited(ip) {
  const key = pseudonymize(ip);
  const now = Date.now();
  const bucket = buckets.get(key);

  if (!bucket || now - bucket.windowStart > config.rateLimit.windowMs) {
    if (buckets.size >= config.rateLimit.maxTrackedKeys) {
      // gornja granica dostignuta - umesto neograničenog rasta memorije,
      // odbijamo nove/nepoznate klijente dok se stari zapisi ne oslobode
      // prirodnim ciscenjem ispod.
      return true;
    }
    buckets.set(key, { count: 1, windowStart: now });
    return false;
  }

  bucket.count += 1;
  return bucket.count > config.rateLimit.maxPerWindow;
}

function cleanupExpired() {
  const now = Date.now();
  for (const [key, bucket] of buckets.entries()) {
    if (now - bucket.windowStart > config.rateLimit.windowMs) {
      buckets.delete(key);
    }
  }
}

module.exports = { isRateLimited, cleanupExpired };
