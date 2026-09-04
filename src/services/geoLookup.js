/**
 * geoLookup.js
 *
 * Kad dobijemo listu IP adresa DNS resolvera koji su nas pogodili, same IP
 * adrese (npr. "195.14.50.3") nista ne znace obicnom korisniku. Zato ih
 * "obogacujemo" podacima: koja zemlja, grad i - najvaznije - koji ISP/
 * organizacija stoji iza te IP adrese (npr. "Deutsche Telekom AG" ili
 * "Google LLC"). Upravo ISP naziv je ono sto korisniku otkriva leak: ako
 * vidi ime svog kucnog internet provajdera umesto imena VPN kompanije,
 * DNS mu cementirano cura.
 *
 * Koristimo ip-api.com (besplatan, bez API kljuca, ali ograničen na ~45
 * zahteva/minut i samo HTTP, ne HTTPS na free planu). Za produkciju sa
 * ozbiljnim saobracajem razmisli o placenom planu ili ipinfo.io.
 */

async function lookupIp(ip) {
  try {
    const url = `http://ip-api.com/json/${ip}?fields=status,message,country,city,isp,org,as,query`;
    const res = await fetch(url, { signal: AbortSignal.timeout(4000) });
    const data = await res.json();

    if (data.status !== 'success') {
      return { ip, country: null, city: null, isp: 'Nepoznato', org: null, as: null };
    }

    return {
      ip,
      country: data.country,
      city: data.city,
      isp: data.isp,
      org: data.org,
      as: data.as,
    };
  } catch (err) {
    return { ip, country: null, city: null, isp: 'Lookup neuspesan', org: null, as: null };
  }
}

/**
 * Radimo lookup za vise IP adresa paralelno (Promise.all), jer je test
 * po prirodi kratkotrajan i ne zelimo da korisnik ceka sekvencijalno
 * po nekoliko stotina milisekundi za svaki IP.
 */
async function lookupMany(ips) {
  return Promise.all(ips.map(lookupIp));
}

module.exports = { lookupIp, lookupMany };