'use strict';

const dns2 = require('dns2');
const { Packet } = dns2;
const config = require('../config');
const sessions = require('../sessions/store');

const TEST_DOMAIN = config.dns.testDomain;

function normalizeName(name) {
  return String(name || '').trim().toLowerCase().replace(/\.$/, '');
}

function isInZone(name) {
  return name === TEST_DOMAIN || name.endsWith(`.${TEST_DOMAIN}`);
}

function extractProbe(name) {
  const normalized = normalizeName(name);
  const suffix = `.${TEST_DOMAIN}`;
  if (!normalized.endsWith(suffix)) return null;

  const prefix = normalized.slice(0, -suffix.length);
  const labels = prefix.split('.');
  if (labels.length !== 2) return null;

  const [probeId, testId] = labels;
  if (!/^[a-f0-9]{1,64}$/.test(probeId)) return null;
  if (!/^[a-f0-9]{32}$/.test(testId)) return null;
  return { probeId, testId };
}

function baseResponse(request) {
  const response = Packet.createResponseFromRequest(request);
  response.header.ra = 0;
  return response;
}

function refused(request) {
  const response = baseResponse(request);
  response.header.rcode = Packet.RCODE.REFUSED;
  response.header.aa = 0;
  response.answers = [];
  return response;
}

function nxdomain(request) {
  const response = baseResponse(request);
  response.header.rcode = Packet.RCODE.NXDOMAIN;
  response.header.aa = 1;
  response.answers = [];
  return response;
}

function formErr(request) {
  const response = baseResponse(request);
  response.header.rcode = Packet.RCODE.FORMERR;
  response.header.aa = 0;
  response.answers = [];
  return response;
}

function buildApexResponse(request, question) {
  const response = baseResponse(request);
  response.header.aa = 1;

  if (question.type === Packet.TYPE.SOA) {
    response.answers.push({
      name: TEST_DOMAIN,
      type: Packet.TYPE.SOA,
      class: Packet.CLASS.IN,
      ttl: 60,
      primary: config.dns.nsHostname,
      admin: config.dns.adminEmail,
      serial: config.dns.soaSerial,
      refresh: 300,
      retry: 60,
      expiration: 3600,
      minimum: 60,
    });
  } else if (question.type === Packet.TYPE.NS) {
    response.answers.push({
      name: TEST_DOMAIN,
      type: Packet.TYPE.NS,
      class: Packet.CLASS.IN,
      ttl: 60,
      ns: config.dns.nsHostname,
    });
  }

  return response;
}

function buildProbeResponse(request, question, resolverIp) {
  const probe = extractProbe(question.name);
  if (!probe) return nxdomain(request);

  if (!sessions.sessionExistsByTestId(probe.testId)) {
    return nxdomain(request);
  }

  if (question.type !== Packet.TYPE.A) {
    const response = baseResponse(request);
    response.header.aa = 1;
    return response;
  }

  if (!sessions.recordResolverHit(probe.testId, resolverIp)) {
    return nxdomain(request);
  }

  const response = baseResponse(request);
  response.header.aa = 1;
  response.answers.push({
    name: question.name,
    type: Packet.TYPE.A,
    class: Packet.CLASS.IN,
    ttl: 1,
    address: config.dns.answerIp,
  });
  return response;
}

function handleQuery(request, rinfo) {
  if (request.errors?.length) {
    return formErr(request);
  }

  if (!request.questions || request.questions.length !== 1) {
    return formErr(request);
  }

  const question = request.questions[0];
  if (question.class !== undefined && question.class !== Packet.CLASS.IN) {
    return refused(request);
  }

  const name = normalizeName(question.name);

  // Never answer names outside our delegated test zone.
  // This is the critical protection that prevents open-resolver behavior.
  if (!isInZone(name)) {
    return refused(request);
  }

  if (name === TEST_DOMAIN) {
    return buildApexResponse(request, question);
  }

  const resolverIp =
    (rinfo && typeof rinfo.address === 'string' && rinfo.address) ||
    (request.source && typeof request.source.address === 'string' && request.source.address) ||
    null;

  return buildProbeResponse(request, question, resolverIp);
}

function safeHandle(request, send, rinfo) {
  try {
    send(handleQuery(request, rinfo));
  } catch (error) {
    console.error('[DNS] Query processing failed; packet dropped.');
  }
}

let server;

function startDnsServer() {
  server = dns2.createServer({
    udp: true,
    tcp: true,
    handle: safeHandle,
  });

  server.on('listening', () => {
    console.log(
      `[DNS] Listening on ${config.dns.bindAddress}:${config.dns.port} (UDP+TCP), zone ${TEST_DOMAIN}`
    );
  });

  server.on('error', (error) => {
    console.error(`[DNS] Server error: ${error.message}`);
    process.exit(1);
  });

  server.listen({
    udp: {
      port: config.dns.port,
      address: config.dns.bindAddress,
      type: 'udp4',
    },
    tcp: {
      port: config.dns.port,
      address: config.dns.bindAddress,
    },
  });
}

module.exports = { startDnsServer };
