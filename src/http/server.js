'use strict';

const path = require('path');
const express = require('express');
const config = require('../config');
const routes = require('./routes');
const { securityHeaders } = require('./security-headers');

function createHttpApp() {
  const app = express();

  // 'loopback' znaci: veruj X-Forwarded-For SAMO ako zahtev dolazi sa
  // localhost-a (gde nginx zaista i radi). Ovo je bezbednije od 'true'
  // (koje bi verovalo bilo kom posredniku) - vidi config.trustProxy.
  app.set('trust proxy', config.trustProxy);
  app.disable('x-powered-by');

  app.use(securityHeaders);
  app.use(express.json({ limit: '1kb' })); // globalni limit velicine tela

  app.use('/api', routes);

  app.use(express.static(path.join(__dirname, '..', '..', 'public'), {
    maxAge: '1h',
    index: 'index.html',
  }));

  // Generic error handler - NIKAD ne vraca stack trace ili interne detalje
  // klijentu; detalji idu samo u server-side log (bez osetljivih podataka).
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    console.error('[HTTP] Neuhvacena greska u obradi zahteva.');
    res.status(500).json({ error: 'Doslo je do interne greske.' });
  });

  return app;
}

function startHttpServer() {
  const app = createHttpApp();
  app.listen(config.http.port, config.http.bindAddress, () => {
    console.log(`[HTTP] Server slusa na ${config.http.bindAddress}:${config.http.port}`);
  });
}

module.exports = { startHttpServer, createHttpApp };
