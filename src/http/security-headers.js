'use strict';

/**
 * http/security-headers.js
 *
 * CSP je namerno strog: app.js je jedini skript, ucitan iz spoljasnjeg
 * fajla (nema inline <script> u HTML-u), pa mozemo da zabranimo
 * 'unsafe-inline' bez lomljenja funkcionalnosti.
 */
function securityHeaders(req, res, next) {
  res.removeHeader('X-Powered-By');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; " +
      "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
  );
  // HSTS se namerno NE postavlja ovde - treba da se ukljuci na nginx sloju
  // TEK nakon sto je HTTPS potvrdjeno ispravno podesen (vidi README).
  next();
}

/**
 * Odgovori koji sadrze podatke o resolverima NIKAD ne smeju da se
 * kesiraju - ni u browseru, ni na bilo kom posrednickom proxy-ju.
 */
function noStore(req, res, next) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  next();
}

module.exports = { securityHeaders, noStore };
