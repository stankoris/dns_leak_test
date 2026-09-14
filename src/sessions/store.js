'use strict';

const crypto = require('crypto');
const net = require('net');
const config = require('../config');

const sessionsByTestId = new Map();
const testIdByResultToken = new Map();

function generateId(bytes = 16) {
  return crypto.randomBytes(bytes).toString('hex');
}

function isExpired(session) {
  return Date.now() - session.createdAt > config.session.ttlSeconds * 1000;
}

function destroySession(testId) {
  const session = sessionsByTestId.get(testId);
  if (!session) return false;
  testIdByResultToken.delete(session.resultToken);
  sessionsByTestId.delete(testId);
  return true;
}

function getActiveSessionByTestId(testId) {
  const session = sessionsByTestId.get(testId);
  if (!session) return null;
  if (isExpired(session)) {
    destroySession(testId);
    return null;
  }
  return session;
}

function getActiveSessionByResultToken(resultToken) {
  const testId = testIdByResultToken.get(resultToken);
  if (!testId) return null;
  return getActiveSessionByTestId(testId);
}

function createSession({ privacyAcknowledged, termsAccepted }) {
  cleanupExpired();
  if (sessionsByTestId.size >= config.session.maxActiveSessions) return null;

  const testId = generateId(16);
  const resultToken = generateId(16);
  const session = {
    testId,
    resultToken,
    createdAt: Date.now(),
    privacyAcknowledged: Boolean(privacyAcknowledged),
    termsAccepted: Boolean(termsAccepted),
    resolvers: new Map(),
  };

  sessionsByTestId.set(testId, session);
  testIdByResultToken.set(resultToken, testId);
  return session;
}

function sessionExistsByTestId(testId) {
  return Boolean(getActiveSessionByTestId(testId));
}

function recordResolverHit(testId, resolverIp) {
  const session = getActiveSessionByTestId(testId);
  if (!session) return false;

  // dns2 does not consistently expose peer details for TCP requests.
  // A missing peer address must never create an "undefined" resolver entry.
  if (typeof resolverIp !== 'string' || net.isIP(resolverIp) === 0) return true;

  if (
    session.resolvers.size >= config.session.maxResolversPerSession &&
    !session.resolvers.has(resolverIp)
  ) {
    return false;
  }

  const now = Date.now();
  const existing = session.resolvers.get(resolverIp);
  if (existing) {
    existing.count += 1;
    existing.lastSeen = now;
  } else {
    session.resolvers.set(resolverIp, {
      firstSeen: now,
      lastSeen: now,
      count: 1,
    });
  }

  return true;
}

function getResolvers(resultToken) {
  const session = getActiveSessionByResultToken(resultToken);
  if (!session) return null;
  return Array.from(session.resolvers.entries()).map(([ip, meta]) => ({
    ip,
    count: meta.count,
  }));
}

function deleteByResultToken(resultToken) {
  const testId = testIdByResultToken.get(resultToken);
  if (!testId) return false;
  return destroySession(testId);
}

function cleanupExpired() {
  const now = Date.now();
  for (const [testId, session] of sessionsByTestId.entries()) {
    if (now - session.createdAt > config.session.ttlSeconds * 1000) {
      destroySession(testId);
    }
  }
}

function activeSessionCount() {
  cleanupExpired();
  return sessionsByTestId.size;
}

module.exports = {
  createSession,
  sessionExistsByTestId,
  recordResolverHit,
  getResolvers,
  deleteByResultToken,
  cleanupExpired,
  activeSessionCount,
};
