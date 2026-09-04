require('dotenv').config();
const path = require('path');
const express = require('express');
const apiRoutes = require('./routes/api');
const sessionStore = require('./sessionStore');
const { startDnsServer } = require('./dns-server');

const HTTP_PORT = parseInt(process.env.HTTP_PORT || '3000', 10);
const SESSION_TTL_SECONDS = parseInt(process.env.SESSION_TTL_SECONDS || '180', 10);

sessionStore.setTtl(SESSION_TTL_SECONDS);

const app = express();

// Ako je Express iza nginx reverse proxy-a (sto ce biti slucaj na Hetzneru),
// mora da zna da veruje X-Forwarded-For headeru da bi req.ip bio STVARNA
// IP adresa posetioca, a ne IP nginx-a.
app.set('trust proxy', true);

app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));
app.use('/api', apiRoutes);

app.listen(HTTP_PORT, () => {
  console.log(`[HTTP] Server slusa na portu ${HTTP_PORT}`);
});

// Pokrecemo DNS server u ISTOM procesu (deli sessionStore in-memory Map
// sa HTTP serverom - to je razlog zasto ovo NIJE odvojen npm start skript
// u produkciji, vec se sve pokrece odavde).
startDnsServer();

// Periodicno ciscenje isteklih sesija da memorija ne raste u nedogled.
setInterval(() => {
  sessionStore.cleanupExpired();
}, 30_000);