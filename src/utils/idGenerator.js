const crypto = require('crypto');

/**
 * Generise nasumicni hex string koji koristimo kao:
 *  - testId (identifikuje jednu test sesiju)
 *  - probeId (identifikuje jedan pojedinacni "leak" zahtev unutar sesije)
 *
 * Svaki ID mora biti jedinstven jer DNS resolveri, browser i OS mogu
 * kesirati DNS odgovore. Novi hostname forsira novi DNS lookup.
 *
 * crypto.randomBytes() koristi kriptografski bezbedan izvor nasumicnosti,
 * za razliku od Math.random().
 *
 * 16 bajtova = 128 bita entropije.
 */
function generateId(byteLength = 16) {
  return crypto.randomBytes(byteLength).toString('hex');
}

module.exports = { generateId };