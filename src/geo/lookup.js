'use strict';

const maxmind = require('maxmind');
const config = require('../config');

let cityReader = null;
let asnReader = null;
let initPromise = null;

async function init() {
  if (initPromise) return initPromise;

  initPromise = (async () => {
    try {
      if (config.geo.cityDb) cityReader = await maxmind.open(config.geo.cityDb);
      if (config.geo.asnDb) asnReader = await maxmind.open(config.geo.asnDb);
    } catch (error) {
      console.error(`[GEO] Local database could not be opened: ${error.message}`);
      cityReader = null;
      asnReader = null;
    }

    if (!cityReader && !asnReader) {
      console.log('[GEO] Local ISP/location enrichment is disabled.');
    }
  })();

  return initPromise;
}

function enabled() {
  return Boolean(cityReader || asnReader);
}

async function lookup(ip) {
  await init();

  const city = cityReader ? cityReader.get(ip) : null;
  const asn = asnReader ? asnReader.get(ip) : null;

  return {
    ip,
    organization: asn?.autonomous_system_organization || null,
    asn: asn?.autonomous_system_number ? `AS${asn.autonomous_system_number}` : null,
    city: city?.city?.names?.en || null,
    country: city?.country?.names?.en || null,
  };
}

async function lookupMany(ips) {
  await init();
  return Promise.all(ips.map(lookup));
}

module.exports = { init, enabled, lookupMany };
