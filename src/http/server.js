'use strict';

const path = require('path');
const express = require('express');
const config = require('../config');
const routes = require('./routes');
const securityHeaders = require('./security-headers');

function startHttpServer() {
  const app = express();

  app.disable('x-powered-by');
  app.set('trust proxy', config.http.trustProxy);
  app.use(securityHeaders);
  app.use(express.json({ limit: '2kb' }));
  app.use('/api', routes);
  app.use(express.static(path.join(__dirname, '..', '..', 'public'), {
    etag: true,
    maxAge: config.production ? '5m' : 0,
  }));

  const server = app.listen(config.http.port, config.http.bindAddress, () => {
    console.log(`[HTTP] Listening on ${config.http.bindAddress}:${config.http.port}`);
  });

  return server;
}

module.exports = { startHttpServer };
