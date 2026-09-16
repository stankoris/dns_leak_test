const net = require('net');

/**
 * geoLookup.js
 *
 * IP adrese DNS resolvera obogacujemo informacijama kao sto su:
 * drzava, grad, ISP, organizacija i AS broj.
 *
 * Koristimo ip-api.com batch endpoint kako ne bismo pravili jedan HTTP
 * zahtev za svaki resolver posebno.
 */

const CACHE_TTL_MS = 60 * 60 * 1000; // 1 sat
const MAX_CACHE_ENTRIES = 1000;
const MAX_IPS_PER_LOOKUP = 50;

const cache = new Map();

/*
 * Ako ip-api vrati da smo potrosili rate limit, ovde cuvamo trenutak
 * do kog ne smemo ponovo da ga kontaktiramo.
 */
let blockedUntil = 0;

function unknownResult(ip, message = 'Nepoznato') {
  return {
    ip,
    country: null,
    city: null,
    isp: message,
    org: null,
    as: null,
  };
}

function getCached(ip) {
  const entry = cache.get(ip);

  if (!entry) {
    return null;
  }

  if (Date.now() - entry.createdAt >= CACHE_TTL_MS) {
    cache.delete(ip);
    return null;
  }

  return entry.data;
}

function setCached(ip, data) {
  /*
   * Jednostavna zastita da cache ne raste neograniceno.
   */
  if (cache.size >= MAX_CACHE_ENTRIES) {
    const oldestKey = cache.keys().next().value;

    if (oldestKey !== undefined) {
      cache.delete(oldestKey);
    }
  }

  cache.set(ip, {
    createdAt: Date.now(),
    data,
  });
}

/**
 * Radi lookup za listu IP adresa.
 *
 * @param {string[]} ips
 * @returns {Promise<Array>}
 */
async function lookupMany(ips) {
  if (!Array.isArray(ips)) {
    return [];
  }

  /*
   * Prihvatamo samo validne IPv4/IPv6 adrese.
   * Takodje dedupliciramo IP adrese.
   */
  const validIps = [
    ...new Set(
      ips
        .filter((ip) => typeof ip === 'string')
        .filter((ip) => net.isIP(ip) !== 0)
    ),
  ].slice(0, MAX_IPS_PER_LOOKUP);

  if (validIps.length === 0) {
    return [];
  }

  const results = [];
  const uncachedIps = [];

  for (const ip of validIps) {
    const cached = getCached(ip);

    if (cached) {
      results.push(cached);
    } else {
      uncachedIps.push(ip);
    }
  }

  /*
   * Ako su svi IP-evi vec u cache-u, nema potrebe da zovemo eksterni API.
   */
  if (uncachedIps.length === 0) {
    return results;
  }

  /*
   * Postujemo prethodno dobijeni rate-limit.
   */
  if (Date.now() < blockedUntil) {
    for (const ip of uncachedIps) {
      results.push(unknownResult(ip, 'Lookup privremeno nedostupan'));
    }

    return results;
  }

  try {
    const url =
      'http://ip-api.com/batch?fields=status,message,country,city,isp,org,as,query';

    const response = await fetch(url, {
      method: 'POST',

      headers: {
        'Content-Type': 'application/json',
      },

      body: JSON.stringify(uncachedIps),

      signal: AbortSignal.timeout(4000),
    });

    /*
     * X-Rl = koliko zahteva je ostalo.
     * X-Ttl = koliko sekundi do resetovanja rate limita.
     */
    const remaining = Number(response.headers.get('x-rl'));
    const resetSeconds = Number(response.headers.get('x-ttl'));

    if (
      Number.isFinite(remaining) &&
      remaining === 0 &&
      Number.isFinite(resetSeconds)
    ) {
      blockedUntil = Date.now() + resetSeconds * 1000;
    }

    if (response.status === 429) {
      if (Number.isFinite(resetSeconds)) {
        blockedUntil = Date.now() + resetSeconds * 1000;
      }

      for (const ip of uncachedIps) {
        results.push(unknownResult(ip, 'Lookup rate limit'));
      }

      return results;
    }

    if (!response.ok) {
      for (const ip of uncachedIps) {
        results.push(unknownResult(ip, 'Lookup neuspesan'));
      }

      return results;
    }

    const data = await response.json();

    if (!Array.isArray(data)) {
      for (const ip of uncachedIps) {
        results.push(unknownResult(ip, 'Lookup neuspesan'));
      }

      return results;
    }

    for (const item of data) {
      const ip = item.query;

      if (!ip || !uncachedIps.includes(ip)) {
        continue;
      }

      let result;

      if (item.status !== 'success') {
        result = unknownResult(ip);
      } else {
        result = {
          ip,
          country: item.country ?? null,
          city: item.city ?? null,
          isp: item.isp ?? 'Nepoznato',
          org: item.org ?? null,
          as: item.as ?? null,
        };
      }

      setCached(ip, result);
      results.push(result);
    }

    return results;
  } catch (err) {
    for (const ip of uncachedIps) {
      results.push(unknownResult(ip, 'Lookup neuspesan'));
    }

    return results;
  }
}

module.exports = {
  lookupMany,
};