'use strict';

require('dotenv').config();

function intEnv(name, fallback, min, max) {
  const raw = process.env[name];
  const value = raw === undefined || raw === '' ? fallback : Number.parseInt(raw, 10);
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}.`);
  }
  return value;
}

function required(name) {
  const value = String(process.env[name] || '').trim();
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

function normalizeDomain(value) {
  return value.trim().toLowerCase().replace(/\.$/, '');
}

const nodeEnv = process.env.NODE_ENV || 'development';
const production = nodeEnv === 'production';

const dnsBindAddress = production
  ? required('DNS_BIND_ADDRESS')
  : String(process.env.DNS_BIND_ADDRESS || '127.0.0.1').trim();

if (production && ['0.0.0.0', '::', '127.0.0.1'].includes(dnsBindAddress)) {
  throw new Error('DNS_BIND_ADDRESS must be the public server IP in production.');
}

const httpBindAddress = String(process.env.HTTP_BIND_ADDRESS || '127.0.0.1').trim();
if (production && !['127.0.0.1', 'localhost', '::1'].includes(httpBindAddress)) {
  throw new Error('HTTP_BIND_ADDRESS must remain loopback-only in production.');
}

const config = {
  nodeEnv,
  production,
  http: {
    bindAddress: httpBindAddress,
    port: intEnv('HTTP_PORT', 3001, 1, 65535),
    trustProxy: process.env.TRUST_PROXY || 'loopback',
  },
  dns: {
    bindAddress: dnsBindAddress,
    port: intEnv('DNS_PORT', 53, 1, 65535),
    testDomain: normalizeDomain(required('DNS_TEST_DOMAIN')),
    answerIp: required('DNS_ANSWER_IP'),
    nsHostname: normalizeDomain(required('DNS_NS_HOSTNAME')),
    adminEmail: normalizeDomain(process.env.DNS_ADMIN_EMAIL || 'hostmaster.example.com'),
    soaSerial: intEnv('DNS_SOA_SERIAL', Math.floor(Date.now() / 1000), 1, 4294967295),
  },
  session: {
    ttlSeconds: intEnv('SESSION_TTL_SECONDS', 180, 30, 3600),
    maxActiveSessions: intEnv('MAX_ACTIVE_SESSIONS', 2000, 1, 100000),
    maxResolversPerSession: intEnv('MAX_RESOLVERS_PER_SESSION', 50, 1, 1000),
    probeCount: intEnv('PROBE_COUNT', 8, 1, 20),
  },
  rateLimit: {
    windowMs: intEnv('RATE_LIMIT_WINDOW_MS', 10000, 1000, 3600000),
    max: intEnv('RATE_LIMIT_MAX', 5, 1, 10000),
    maxTrackedKeys: intEnv('RATE_LIMIT_MAX_TRACKED_KEYS', 50000, 100, 1000000),
  },
  geo: {
    cityDb: String(process.env.DBIP_CITY_DB || '').trim() || null,
    asnDb: String(process.env.DBIP_ASN_DB || '').trim() || null,
  },
};

module.exports = config;
