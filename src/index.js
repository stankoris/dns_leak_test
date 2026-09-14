'use strict';

const config = require('./config');
const sessions = require('./sessions/store');
const geo = require('./geo/lookup');
const { startHttpServer } = require('./http/server');
const { startDnsServer } = require('./dns/server');

async function main() {
  await geo.init();
  startHttpServer();
  startDnsServer();

  setInterval(() => sessions.cleanupExpired(), 30_000).unref();

  console.log(
    `[APP] Started in ${config.nodeEnv} mode. Active sessions: ${sessions.activeSessionCount()}`
  );
}

main().catch((error) => {
  console.error(`[APP] Startup failed: ${error.message}`);
  process.exit(1);
});
