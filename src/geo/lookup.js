'use strict';

const config = require('../config');

/**
 * geo/lookup.js
 *
 * NAMERNO ne postoji nijedan network zahtev u ovom fajlu. Resolver IP
 * adrese se NIKAD ne salju trecoj strani samo da bi se dobio ISP/lokacija
 * - to je bio problem sa prethodnom ip-api.com integracijom (HTTP, bez
 * enkripcije, i uslovi koriscenja koji ne dozvoljavaju komercijalnu
 * upotrebu besplatnog nivoa).
 *
 * Umesto toga koristimo lokalno preuzete DB-IP Lite baze (MMDB format,
 * kompatibilne sa 'maxmind' Node.js citacem) koje administrator servera
 * sam preuzme i postavi na disk (vidi README, sekcija "DB-IP baze").
 *
 * Ako baze nisu prisutne, aplikacija se NE gasi - geo podaci su "nice to
 * have" kozmeticka informacija, ne kriticna funkcionalnost testa. Umesto
 * toga, upozoravamo na startu i vracamo prazne/null geo podatke.
 */

let cityReader = null;
let asnReader = null;
let initAttempted = false;
let maxmind = null;

async function init() {
  if (initAttempted) return;
  initAttempted = true;

  if (!config.geo.cityDbPath && !config.geo.asnDbPath) {
    console.warn(
      '[GEO] DBIP_CITY_DB / DBIP_ASN_DB nisu podeseni - geo/ISP obogacivanje rezultata bice iskljuceno.'
    );
    return;
  }

  try {
    // Lenjo ucitavanje da aplikacija ne pukne na startu ako paket nije
    // instaliran u okruzenjima gde geo lookup namerno nije potreban.
    // eslint-disable-next-line global-require
    maxmind = require('maxmind');
  } catch (err) {
    console.error(
      "[GEO] Paket 'maxmind' nije instaliran. Pokreni 'npm install maxmind' ili ostavi " +
        'DBIP_* promenljive prazne da iskljucis geo obogacivanje.'
    );
    return;
  }

  try {
    if (config.geo.cityDbPath) {
      cityReader = await maxmind.open(config.geo.cityDbPath);
    }
  } catch (err) {
    console.error(`[GEO] Nije moguce ucitati City bazu (${config.geo.cityDbPath}): ${err.message}`);
  }

  try {
    if (config.geo.asnDbPath) {
      asnReader = await maxmind.open(config.geo.asnDbPath);
    }
  } catch (err) {
    console.error(`[GEO] Nije moguce ucitati ASN bazu (${config.geo.asnDbPath}): ${err.message}`);
  }
}

/**
 * Vraca strukturu istog oblika bez obzira da li su baze dostupne, kako
 * pozivalac (routes.js) ne bi morao da razlikuje slucajeve.
 */
function lookup(ip) {
  const result = {
    ip,
    country: null,
    countryCode: null,
    region: null,
    city: null,
    asn: null,
    asnOrg: null,
  };

  if (cityReader) {
    try {
      const cityData = cityReader.get(ip);
      if (cityData) {
        result.country = cityData.country?.names?.en || null;
        result.countryCode = cityData.country?.iso_code || null;
        result.region = cityData.subdivisions?.[0]?.names?.en || null;
        result.city = cityData.city?.names?.en || null;
      }
    } catch (err) {
      // neispravna IP adresa ili slicno - ignorisi, vrati prazno
    }
  }

  if (asnReader) {
    try {
      const asnData = asnReader.get(ip);
      if (asnData) {
        result.asn = asnData.autonomous_system_number || null;
        result.asnOrg = asnData.autonomous_system_organization || null;
      }
    } catch (err) {
      // ignorisi
    }
  }

  return result;
}

function lookupMany(ips) {
  return ips.map(lookup);
}

function isEnabled() {
  return Boolean(cityReader || asnReader);
}

module.exports = { init, lookup, lookupMany, isEnabled };
