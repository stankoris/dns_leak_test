'use strict';

require('dotenv').config({ quiet: true });

/**
 * Central configuration module.
 *
 * Design principle: there are NO silent dangerous defaults for
 * security-critical settings in production. If NODE_ENV=production and a
 * required variable is missing or invalid, the process exits immediately
 * (fail closed) rather than starting with a value nobody chose.
 *
 * This directly addresses the root cause class of the prior incident: a
 * silent bind-to-0.0.0.0 (or similar "helpful" default) is exactly the
 * kind of implicit behavior that turns an internal tool into a
 * publicly-reachable, unintentionally-open service.
 */

const NODE_ENV = process.env.NODE_ENV || 'development';
const isProduction = NODE_ENV === 'production';

const errors = [];

function required(name) {
  const value = process.env[name];
  if (value === undefined || value.trim() === '') {
    errors.push(`Missing required environment variable: ${name}`);
    return undefined;
  }
  return value.trim();
}

function optional(name, fallback) {
  const value = process.env[name];
  return value && value.trim() !== '' ? value.trim() : fallback;
}

function requiredInProdOr(name, devFallback) {
  return isProduction ? required(name) : optional(name, devFallback);
}

function toInt(value, fallback) {
  const n = parseInt(value, 10);
  return Number.isFinite(n) ? n : fallback;
}

function isValidIpv4(value) {
  if (typeof value !== 'string') return false;
  const parts = value.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
}

// --- DNS bind address: NEVER silently defaults to 0.0.0.0 -----------------
// In production this MUST be set explicitly to the server's public IP.
// In development it defaults to 127.0.0.1 (loopback-only, safe default).
const DNS_BIND_ADDRESS = requiredInProdOr('DNS_BIND_ADDRESS', '127.0.0.1');
if (isProduction && DNS_BIND_ADDRESS && !isValidIpv4(DNS_BIND_ADDRESS)) {
  errors.push(
    `DNS_BIND_ADDRESS="${DNS_BIND_ADDRESS}" does not look like a valid IPv4 address. ` +
      'Refusing to start rather than guess.'
  );
}
if (DNS_BIND_ADDRESS === '0.0.0.0') {
  errors.push(
    'DNS_BIND_ADDRESS=0.0.0.0 is not permitted. Bind explicitly to the intended ' +
      'public interface address so exposure is always an explicit choice, never a default.'
  );
}

// --- HTTP bind address: must stay on loopback; Nginx is the public edge ---
const HTTP_BIND_ADDRESS = optional('HTTP_BIND_ADDRESS', '127.0.0.1');
if (HTTP_BIND_ADDRESS !== '127.0.0.1' && HTTP_BIND_ADDRESS !== 'localhost' && HTTP_BIND_ADDRESS !== '::1') {
  errors.push(
    `HTTP_BIND_ADDRESS="${HTTP_BIND_ADDRESS}" is not a loopback address. The Express ` +
      'application must never be exposed directly to the Internet; Nginx terminates TLS ' +
      'and reverse-proxies to loopback only.'
  );
}

const DNS_TEST_DOMAIN = required('DNS_TEST_DOMAIN');
const DNS_ANSWER_IP = required('DNS_ANSWER_IP');
if (DNS_ANSWER_IP && !isValidIpv4(DNS_ANSWER_IP)) {
  errors.push(`DNS_ANSWER_IP="${DNS_ANSWER_IP}" does not look like a valid IPv4 address.`);
}
const DNS_NS_HOSTNAME = requiredInProdOr('DNS_NS_HOSTNAME', `ns1.${optional('DNS_TEST_DOMAIN', 'test.invalid')}`);

// --- Local geolocation databases -------------------------------------------
const DBIP_CITY_DB = optional('DBIP_CITY_DB', null);
const DBIP_ASN_DB = optional('DBIP_ASN_DB', null);

// --- IPC session-store socket -----------------------------------------------
const IPC_SOCKET_PATH = optional('IPC_SOCKET_PATH', '/run/dns-leak-test/session-store.sock');

const config = {
  nodeEnv: NODE_ENV,
  isProduction,

  dns: {
    bindAddress: DNS_BIND_ADDRESS,
    port: toInt(optional('DNS_PORT', '53'), 53),
    testDomain: (DNS_TEST_DOMAIN || '').toLowerCase().replace(/\.$/, ''),
    answerIp: DNS_ANSWER_IP,
    nsHostname: (DNS_NS_HOSTNAME || '').toLowerCase().replace(/\.$/, ''),
    adminEmail: optional('DNS_ADMIN_EMAIL', 'hostmaster.invalid'),
    soaSerial: optional('DNS_SOA_SERIAL', String(Math.floor(Date.now() / 1000))),
    maxQuestionsPerMessage: 1,
  },

  http: {
    bindAddress: HTTP_BIND_ADDRESS,
    port: toInt(optional('HTTP_PORT', '3000'), 3000),
    jsonBodyLimitBytes: toInt(optional('HTTP_JSON_BODY_LIMIT_BYTES', '2048'), 2048),
  },

  session: {
    ttlSeconds: toInt(optional('SESSION_TTL_SECONDS', '180'), 180),
    maxActiveSessions: toInt(optional('MAX_ACTIVE_SESSIONS', '2000'), 2000),
    maxResolversPerSession: toInt(optional('MAX_RESOLVERS_PER_SESSION', '50'), 50),
  },

  geo: {
    cityDbPath: DBIP_CITY_DB,
    asnDbPath: DBIP_ASN_DB,
  },

  rateLimit: {
    windowMs: toInt(optional('RATE_LIMIT_WINDOW_MS', '10000'), 10000),
    maxPerWindow: toInt(optional('RATE_LIMIT_MAX', '5'), 5),
    maxTrackedKeys: toInt(optional('RATE_LIMIT_MAX_TRACKED_KEYS', '50000'), 50000),
  },

  ipc: {
    socketPath: IPC_SOCKET_PATH,
  },
};

if (errors.length > 0) {
  for (const message of errors) {
    // eslint-disable-next-line no-console
    console.error(`[CONFIG] FATAL: ${message}`);
  }
  // eslint-disable-next-line no-console
  console.error('[CONFIG] Refusing to start due to invalid/missing configuration.');
  process.exit(1);
}

if (!isProduction) {
  // eslint-disable-next-line no-console
  console.warn(
    `[CONFIG] NODE_ENV=${NODE_ENV} (not "production") - development defaults are in use. ` +
      'This must never be exposed to the Internet.'
  );
}

module.exports = config;