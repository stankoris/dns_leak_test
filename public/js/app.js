const privacyCheck = document.getElementById('privacy-check');
const termsCheck = document.getElementById('terms-check');
const startBtn = document.getElementById('start-btn');
const retryBtn = document.getElementById('retry-btn');
const startCard = document.getElementById('start-card');
const progressCard = document.getElementById('progress-card');
const progressText = document.getElementById('progress-text');
const resultsCard = document.getElementById('results-card');
const resultsBody = document.getElementById('results-body');
const verdictEl = document.getElementById('verdict');
const geoDisabledNote = document.getElementById('geo-disabled-note');

let currentResultToken = null;

function updateStartButton() {
  startBtn.disabled = !(privacyCheck.checked && termsCheck.checked);
}
privacyCheck.addEventListener('change', updateStartButton);
termsCheck.addEventListener('change', updateStartButton);

/**
 * Koristimo crypto.getRandomValues (CSPRNG) umesto Math.random() za
 * probeId - konzistentno sa zahtevom da svi identifikatori koji ucestvuju
 * u bezbednosno relevantnoj logici budu kriptografski nasumicni.
 */
function randomHex(byteLength = 8) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function sendProbe(hostname) {
  return new Promise((resolve) => {
    const img = new Image();
    const done = () => resolve();
    img.onload = done;
    img.onerror = done; // ocekivano - nema pravog HTTP servera na tim imenima
    img.src = `http://${hostname}/probe.png?_=${Date.now()}`;
    setTimeout(done, 3000);
  });
}

async function runTest() {
  if (!privacyCheck.checked || !termsCheck.checked) return; // odbrana i na frontendu, ali server je taj koji stvarno primorava

  startCard.classList.add('hidden');
  resultsCard.classList.add('hidden');
  progressCard.classList.remove('hidden');
  progressText.textContent = 'Pokrecem test...';

  const startRes = await fetch('/api/tests', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ privacyAcknowledged: true, termsAccepted: true }),
  });

  if (!startRes.ok) {
    const err = await startRes.json().catch(() => ({}));
    progressText.textContent = err.error || 'Greska pri pokretanju testa. Pokusaj ponovo.';
    return;
  }

  const { testId, resultToken, dnsTestDomain, probeCount } = await startRes.json();
  currentResultToken = resultToken;

  const count = probeCount || 8;
  progressText.textContent = `Saljem ${count} DNS upita...`;
  const probes = [];
  for (let i = 0; i < count; i++) {
    const hostname = `${randomHex(8)}.${testId}.${dnsTestDomain}`;
    probes.push(sendProbe(hostname));
  }
  await Promise.all(probes);

  progressText.textContent = 'Prikupljam rezultate...';
  await new Promise((r) => setTimeout(r, 2000));

  const resultsRes = await fetch(`/api/tests/${resultToken}`);
  if (!resultsRes.ok) {
    progressText.textContent = 'Nije bilo moguce preuzeti rezultate.';
    return;
  }
  const data = await resultsRes.json();
  renderResults(data);
}

/**
 * Podaci u tabeli (ISP naziv, grad, drzava) poticu iz spoljasnje IP baze i
 * tretiramo ih kao NEPOUZDAN ulaz - zato gradimo DOM cvorove i koristimo
 * textContent, NIKAD innerHTML, cak i ako danas ti podaci dolaze iz
 * lokalne baze koju sami kontrolisemo.
 */
function renderResults(data) {
  progressCard.classList.add('hidden');
  resultsCard.classList.remove('hidden');
  resultsBody.innerHTML = '';

  if (!data.geoLookupEnabled) {
    geoDisabledNote.textContent = 'Geo/ISP obogaćivanje rezultata je isključeno na ovom serveru - prikazane su samo IP adrese.';
  } else {
    geoDisabledNote.textContent = '';
  }

  if (!data.resolvers || data.resolvers.length === 0) {
    verdictEl.className = 'verdict leak';
    verdictEl.textContent =
      'Nijedan DNS upit nije stigao do servera. Ovo moze znaciti da tvoj DNS ide preko sifrovanog kanala (DoH/DoT), ili da nesto sa delegacijom/mrezom nije ispravno podeseno.';
    return;
  }

  const distinctOrgs = new Set(data.resolvers.map((r) => r.asnOrg || r.ip));

  if (distinctOrgs.size > 1) {
    verdictEl.className = 'verdict leak';
    verdictEl.textContent = `Detektovano ${distinctOrgs.size} razlicitih DNS provajdera. Proveri da li se svi poklapaju sa tvojim VPN provajderom.`;
  } else {
    verdictEl.className = 'verdict safe';
    verdictEl.textContent = 'Svi DNS upiti dolaze od jednog provajdera. Proveri da li se ime organizacije poklapa sa tvojim VPN provajderom.';
  }

  data.resolvers.forEach((r) => {
    const tr = document.createElement('tr');

    const ipTd = document.createElement('td');
    ipTd.textContent = r.ip;

    const orgTd = document.createElement('td');
    orgTd.textContent = r.asnOrg || 'Nepoznato';

    const locTd = document.createElement('td');
    locTd.textContent = r.city ? `${r.city}, ${r.country || ''}` : (r.country || '-');

    const countTd = document.createElement('td');
    countTd.textContent = String(r.hitCount);

    tr.append(ipTd, orgTd, locTd, countTd);
    resultsBody.appendChild(tr);
  });
}

startBtn.addEventListener('click', runTest);

retryBtn.addEventListener('click', async () => {
  if (currentResultToken) {
    fetch(`/api/tests/${currentResultToken}`, { method: 'DELETE' }).catch(() => {});
    currentResultToken = null;
  }
  resultsCard.classList.add('hidden');
  startCard.classList.remove('hidden');
});

// Namerno NEMA "cleanup on page leave" preko navigator.sendBeacon ovde -
// sendBeacon uvek salje POST, ne DELETE, pa ne bi stvarno pogodio DELETE
// rutu i bio bi varljiv kod koji izgleda kao da radi cisc enje a ne radi.
// Sesija ce prirodno isteci najkasnije nakon SESSION_TTL_SECONDS.
