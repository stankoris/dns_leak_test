/**
 * server.js
 *
 * Glavni entry point aplikacije.
 *
 * U ISTOM Node.js procesu pokrecemo:
 *
 *   1) Express HTTP server
 *   2) Autoritativni DNS server
 *
 * Razlog je sto oba koriste isti in-memory sessionStore.
 *
 * Production arhitektura:
 *
 * Internet
 *    |
 *    v
 * Nginx :80/:443
 *    |
 *    v
 * Express 127.0.0.1:3001
 *
 *
 * DNS saobracaj ide direktno:
 *
 * Internet
 *    |
 *    +---- UDP :53 ---> Node DNS server
 *    |
 *    +---- TCP :53 ---> Node DNS server
 */

require('dotenv').config();

const path = require('path');
const express = require('express');

const apiRoutes = require('./routes/api');
const sessionStore = require('./sessionStore');
// const { startDnsServer } = require('./dns-server');
const {
  startDnsServer,
  stopDnsServer,
} = require('./dns-server');


/* -------------------------------------------------------------------------- */
/* Configuration                                                              */
/* -------------------------------------------------------------------------- */

function parsePositiveInteger(value, name) {
  /*
   * Ne koristimo samo parseInt("123abc") jer bi on vratio 123.
   *
   * Zelimo da cela vrednost bude validan pozitivan integer.
   */
  if (!/^\d+$/.test(String(value))) {
    throw new Error(`${name} mora biti pozitivan ceo broj.`);
  }

  const parsed = Number(value);

  if (
    !Number.isSafeInteger(parsed) ||
    parsed <= 0
  ) {
    throw new Error(`${name} mora biti pozitivan ceo broj.`);
  }

  return parsed;
}


const HTTP_PORT = parsePositiveInteger(
  process.env.HTTP_PORT || '3001',
  'HTTP_PORT'
);


if (HTTP_PORT > 65535) {
  throw new Error(
    'HTTP_PORT mora biti izmedju 1 i 65535.'
  );
}


const SESSION_TTL_SECONDS = parsePositiveInteger(
  process.env.SESSION_TTL_SECONDS || '180',
  'SESSION_TTL_SECONDS'
);


/*
 * Za ovaj servis nema smisla da sesije ostaju satima u memoriji.
 *
 * Ovo je dodatna konfiguraciona zastita.
 */
if (SESSION_TTL_SECONDS > 3600) {
  throw new Error(
    'SESSION_TTL_SECONDS ne sme biti veci od 3600.'
  );
}


/* -------------------------------------------------------------------------- */
/* Session store                                                              */
/* -------------------------------------------------------------------------- */

sessionStore.setTtl(
  SESSION_TTL_SECONDS
);


/* -------------------------------------------------------------------------- */
/* Express                                                                    */
/* -------------------------------------------------------------------------- */

const app = express();


/*
 * Ne otkrivamo nepotrebno da backend koristi Express.
 *
 * Bez ovoga Express standardno moze poslati:
 *
 *   X-Powered-By: Express
 *
 * Nije velika security zastita sama po sebi, ali nema razloga da
 * nepotrebno otkrivamo implementacione detalje.
 */
app.disable('x-powered-by');


/*
 * Express je dostupan ISKLJUCIVO preko Nginx-a koji se nalazi
 * na istoj masini.
 *
 * Zato verujemo proxy informacijama samo ako je direktni peer
 * loopback adresa.
 *
 * NEMOJ menjati ovo u:
 *
 *   app.set('trust proxy', true)
 *
 * jer rate limiting u routes/api.js zavisi od pouzdanog req.ip.
 */
app.set(
  'trust proxy',
  'loopback'
);


/* -------------------------------------------------------------------------- */
/* Request parsing                                                            */
/* -------------------------------------------------------------------------- */

/*
 * Ova aplikacija nema potrebu za velikim JSON request body-jima.
 *
 * Mali limit smanjuje mogucnost nepotrebnog trosenja memorije.
 */
app.use(
  express.json({
    limit: '8kb',
  })
);


/* -------------------------------------------------------------------------- */
/* Static frontend                                                            */
/* -------------------------------------------------------------------------- */

const publicDirectory = path.join(
  __dirname,
  '..',
  'public'
);


app.use(
  express.static(
    publicDirectory,
    {
      /*
       * index.html i frontend mogu kasnije dobiti zasebnu cache politiku
       * preko Nginx-a.
       *
       * Za sada drzimo Express konfiguraciju jednostavnom.
       */
      fallthrough: true,
    }
  )
);


/* -------------------------------------------------------------------------- */
/* API                                                                        */
/* -------------------------------------------------------------------------- */

app.use(
  '/api',
  apiRoutes
);


/* -------------------------------------------------------------------------- */
/* 404                                                                        */
/* -------------------------------------------------------------------------- */

/*
 * Ako request nije pogodio ni static fajl ni API rutu,
 * vracamo mali odgovor.
 */
app.use((req, res) => {
  res.status(404).json({
    error: 'Not found.',
  });
});


/* -------------------------------------------------------------------------- */
/* Error handler                                                              */
/* -------------------------------------------------------------------------- */

/*
 * Centralni Express error handler.
 *
 * Ne vracamo stack trace browseru.
 */
app.use((err, req, res, next) => {
  console.error(
    '[HTTP] Request error:',
    err.message
  );


  if (res.headersSent) {
    return next(err);
  }


  /*
   * express.json() koristi status 413 kada body predje limit.
   */
  if (err.status === 413) {
    return res.status(413).json({
      error: 'Request body je prevelik.',
    });
  }


  /*
   * Nevalidan JSON.
   */
  if (
    err instanceof SyntaxError &&
    err.status === 400
  ) {
    return res.status(400).json({
      error: 'Nevalidan JSON.',
    });
  }


  return res.status(500).json({
    error: 'Internal server error.',
  });
});


/* -------------------------------------------------------------------------- */
/* HTTP server                                                                */
/* -------------------------------------------------------------------------- */

/*
 * VEOMA BITNO:
 *
 * Express ne slusa na:
 *
 *   0.0.0.0:3001
 *
 * nego samo:
 *
 *   127.0.0.1:3001
 *
 * Zato mu se sa Interneta ne moze direktno pristupiti.
 * Nginx je jedina javna HTTP/HTTPS ulazna tacka.
 */
const httpServer = app.listen(
  HTTP_PORT,
  '127.0.0.1',
  () => {
    console.log(
      `[HTTP] Server slusa na 127.0.0.1:${HTTP_PORT}`
    );
  }
);


httpServer.on('error', (err) => {
  console.error(
    '[HTTP] Server greska:',
    err
  );

  process.exit(1);
});


/* -------------------------------------------------------------------------- */
/* HTTP timeout protection                                                    */
/* -------------------------------------------------------------------------- */

/*
 * Node podrazumevano ima relativno liberalne timeout vrednosti.
 *
 * Nginx ce biti glavna zastita od sporih HTTP klijenata, ali ove vrednosti
 * daju dodatnu defense-in-depth zastitu na Node sloju.
 */

/*
 * Maksimalno vreme za primanje kompletnih HTTP headera.
 */
httpServer.headersTimeout = 15_000;


/*
 * Maksimalno vreme za kompletan request.
 */
httpServer.requestTimeout = 30_000;


/*
 * Koliko dugo idle keep-alive konekcija ostaje otvorena.
 */
httpServer.keepAliveTimeout = 5_000;


/* -------------------------------------------------------------------------- */
/* DNS server                                                                 */
/* -------------------------------------------------------------------------- */

/*
 * DNS server radi u ISTOM procesu jer zajedno sa HTTP API-em koristi
 * sessionStore.js.
 */
startDnsServer();


/* -------------------------------------------------------------------------- */
/* Session cleanup                                                            */
/* -------------------------------------------------------------------------- */

/*
 * Periodicno uklanjamo istekle DNS leak test sesije.
 */
const cleanupInterval = setInterval(() => {
  sessionStore.cleanupExpired();
}, 30_000);


/*
 * Timer sam po sebi ne treba da drzi Node proces zivim tokom shutdown-a.
 */
cleanupInterval.unref();


/* -------------------------------------------------------------------------- */
/* Shutdown                                                                   */
/* -------------------------------------------------------------------------- */

/*
 * Za sada uredno zatvaramo HTTP server i cleanup timer.
 *
 * dns-server.js trenutno nema exportovan stop/close metod.
 * Kada budemo dodavali potpuno graceful gasenje DNS servera,
 * dopunicemo i dns-server.js.
 */
let shuttingDown = false;


async function shutdown(signal) {
  if (shuttingDown) {
    return;
  }

  shuttingDown = true;

  console.log(`[APP] Primljen ${signal}. Gasim server...`);

  clearInterval(cleanupInterval);

  /*
   * Ako graceful shutdown iz nekog razloga zaglavi,
   * prisilno ugasi proces posle 10 sekundi.
   */
  const forceShutdownTimer = setTimeout(() => {
    console.error('[APP] Forced shutdown.');
    process.exit(1);
  }, 10_000);

  forceShutdownTimer.unref();

  try {
    await stopDnsServer();

    httpServer.close((err) => {
      if (err) {
        console.error(
          '[HTTP] Greska tokom shutdown-a:',
          err
        );

        process.exit(1);
      }

      clearTimeout(forceShutdownTimer);

      console.log(
        '[APP] HTTP i DNS serveri uredno ugaseni.'
      );

      process.exit(0);
    });
  } catch (err) {
    console.error(
      '[DNS] Greska tokom shutdown-a:',
      err
    );

    process.exit(1);
  }
}


process.on(
  'SIGTERM',
  () => shutdown('SIGTERM')
);


process.on(
  'SIGINT',
  () => shutdown('SIGINT')
);