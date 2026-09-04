const startBtn = document.getElementById('start-btn');
const retryBtn = document.getElementById('retry-btn');
const startCard = document.getElementById('start-card');
const progressCard = document.getElementById('progress-card');
const progressText = document.getElementById('progress-text');
const resultsCard = document.getElementById('results-card');
const resultsBody = document.getElementById('results-body');
const verdictEl = document.getElementById('verdict');

/**
 * Nasumicni hex string za probeId - mora biti jedinstven svaki put da bi
 * zaobisao DNS kesiranje (objasnjeno detaljnije u src/utils/idGenerator.js
 * na backendu - ista logika, samo ovde u browseru).
 */
function randomHex(length = 8) {
  const chars = 'abcdef0123456789';
  let out = '';
  for (let i = 0; i < length; i++) {
    out += chars[Math.floor(Math.random() * chars.length)];
  }
  return out;
}

/**
 * Salje jedan "probe" DNS upit.
 *
 * Zasto koristimo Image() umesto fetch()?
 * - <img> tag ne pravi CORS preflight (za razliku od fetch-a ka drugom
 *   domenu), pa nema konzolnih gresaka ni komplikacija oko CORS headera.
 * - Bitan nam je SAMO DNS lookup koji se desava PRE nego sto browser
 *   pokusa da uspostavi TCP konekciju. Sama slika ne mora (i nece) uspesno
 *   da se ucita - nas server ne servira slike na tim nasumicnim
 *   poddomenima, samo odgovara na DNS upite. To je ocekivano i potpuno OK.
 */
function sendProbe(hostname) {
  return new Promise((resolve) => {
    const img = new Image();
    const done = () => resolve();
    img.onload = done;
    img.onerror = done; // ocekujemo gresku (nema pravog HTTP servera na tom imenu) - to je OK
    img.src = `http://${hostname}/probe.png?_=${Date.now()}`;

    // Sigurnosni tajmaut - ne cekamo unedogled ako browser "visi" na upitu
    setTimeout(done, 3000);
  });
}

async function runTest() {
  startCard.classList.add('hidden');
  resultsCard.classList.add('hidden');
  progressCard.classList.remove('hidden');
  progressText.textContent = 'Pokrecem test...';

  // 1. Zatrazi novu test sesiju od backend-a
  const startRes = await fetch('/api/test/start', { method: 'POST' });
  if (!startRes.ok) {
    progressText.textContent = 'Greska pri pokretanju testa. Pokusaj ponovo.';
    return;
  }
  const { testId, dnsTestDomain, probeCount } = await startRes.json();

  // 2. Generisi N nasumicnih poddomena i posalji "probe" zahteve
  progressText.textContent = `Saljem ${probeCount} DNS upita...`;
  const probes = [];
  for (let i = 0; i < probeCount; i++) {
    const hostname = `${randomHex(8)}.${testId}.${dnsTestDomain}`;
    probes.push(sendProbe(hostname));
  }
  await Promise.all(probes);

  // 3. Malo sacekaj da spori resolveri stignu do naseg DNS servera
  progressText.textContent = 'Prikupljam rezultate...';
  await new Promise((r) => setTimeout(r, 2000));

  // 4. Preuzmi rezultate
  const resultsRes = await fetch(`/api/test/${testId}/results`);
  if (!resultsRes.ok) {
    progressText.textContent = 'Nije bilo moguce preuzeti rezultate.';
    return;
  }
  const data = await resultsRes.json();

  renderResults(data);
}

function renderResults(data) {
  progressCard.classList.add('hidden');
  resultsCard.classList.remove('hidden');
  resultsBody.innerHTML = '';

  if (!data.resolvers || data.resolvers.length === 0) {
    verdictEl.className = 'verdict leak';
    verdictEl.textContent =
      'Nijedan DNS upit nije stigao do servera. Ovo moze znaciti da tvoj DNS ide preko sifrovanog kanala (DoH/DoT) koji ovaj test ne moze direktno da uhvati, ili da NS delegacija nije ispravno podesena.';
    return;
  }

  const distinctOrgs = new Set(data.resolvers.map((r) => r.org || r.isp));

  if (distinctOrgs.size > 1) {
    verdictEl.className = 'verdict leak';
    verdictEl.textContent = `Detektovano ${distinctOrgs.size} razlicita DNS provajdera. Ako se bilo koji od njih ne poklapa sa tvojim VPN provajderom, tvoj DNS curi.`;
  } else {
    verdictEl.className = 'verdict safe';
    verdictEl.textContent =
      'Svi DNS upiti dolaze od jednog provajdera. Proveri da li se ime organizacije ispod poklapa sa tvojim VPN provajderom.';
  }

  data.resolvers.forEach((r) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${r.ip}</td>
      <td>${r.isp || 'Nepoznato'}${r.org && r.org !== r.isp ? ` (${r.org})` : ''}</td>
      <td>${r.city ? `${r.city}, ${r.country}` : r.country || '-'}</td>
      <td>${r.hitCount}</td>
    `;
    resultsBody.appendChild(tr);
  });
}

startBtn.addEventListener('click', runTest);
retryBtn.addEventListener('click', () => {
  resultsCard.classList.add('hidden');
  startCard.classList.remove('hidden');
});