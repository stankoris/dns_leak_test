const crypto = require('crypto');

/**
 * Generise nasumicni hex string koji koristimo kao:
 *  - testId (identifikuje jednu test sesiju)
 *  - probeId (identifikuje jedan pojedinacni "leak" zahtev unutar sesije)
 *
 * Zasto MORA da bude nasumicno i jedinstveno svaki put?
 * DNS resolveri (i browser, i OS, i sam ISP) agresivno kesiraju odgovore.
 * Ako bismo koristili isto ime dva puta, drugi put bi odgovor mogao doci iz
 * kesa negde usput, umesto da stvarno otputuje sve do naseg servera - a to bi
 * nam pokvarilo test (izgledalo bi kao da nema leaka, iako ga ima, samo je
 * odgovor bio kesiran).
 *
 * crypto.randomBytes je bezbedniji izvor nasumicnosti od Math.random() -
 * bitno je da testId ne moze niko da pogodi/predvidi.
 */
function generateId(byteLength = 6) {
  return crypto.randomBytes(byteLength).toString('hex');
}

module.exports = { generateId };