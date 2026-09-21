/* -------------------------------------------------------------------------- */
/* DOM elements                                                               */
/* -------------------------------------------------------------------------- */

const startBtn = document.getElementById('start-btn');
const retryBtn = document.getElementById('retry-btn');

const startCard = document.getElementById('start-card');
const progressCard = document.getElementById('progress-card');
const progressText = document.getElementById('progress-text');

const resultsCard = document.getElementById('results-card');
const resultsBody = document.getElementById('results-body');
const verdictEl = document.getElementById('verdict');

const privacyDialog = document.getElementById('privacy-dialog');
const privacyContinueBtn = document.getElementById(
  'privacy-continue-btn'
);


/* -------------------------------------------------------------------------- */
/* Privacy notice                                                             */
/* -------------------------------------------------------------------------- */

/*
 * Ovo NIJE consent mehanizam.
 *
 * Korisniku samo prikazujemo transparentno obavestenje o obradi podataka.
 * Sam DNS test pocinje tek kada korisnik zasebno klikne:
 *
 *   Start DNS Leak Test
 *
 * Za sada notice prikazujemo pri svakom ucitavanju stranice.
 * Ne koristimo cookie/localStorage samo da bismo zapamtili popup.
 */
function showPrivacyNotice() {
  if (!privacyDialog) {
    return;
  }

  /*
   * showModal() pretvara <dialog> u pravi modalni dialog.
   */
  if (typeof privacyDialog.showModal === 'function') {
    privacyDialog.showModal();
  }
}


if (privacyContinueBtn && privacyDialog) {
  privacyContinueBtn.addEventListener('click', () => {
    privacyDialog.close();
  });
}


/* -------------------------------------------------------------------------- */
/* Random probe ID                                                            */
/* -------------------------------------------------------------------------- */

/**
 * Generise kriptografski bezbedan 128-bitni probe ID.
 *
 * Backend koristi:
 *
 *   generateId(16)
 *
 * sto daje:
 *
 *   16 bytes
 *   128 bits
 *   32 hex karaktera
 *
 * DNS server zato ocekuje hostname:
 *
 *   <32 hex probeId>.<32 hex testId>.<domain>
 */
function generateProbeId() {
  const bytes = new Uint8Array(16);

  crypto.getRandomValues(bytes);

  return Array.from(
    bytes,
    (byte) => byte.toString(16).padStart(2, '0')
  ).join('');
}


/* -------------------------------------------------------------------------- */
/* Utility                                                                    */
/* -------------------------------------------------------------------------- */

function sleep(milliseconds) {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}


/**
 * Fetch sa timeout-om.
 *
 * Ne zelimo da UI zauvek ostane u "Loading" stanju ako backend
 * ili mreza prestanu da odgovaraju.
 */
async function fetchWithTimeout(
  url,
  options = {},
  timeoutMs = 8000
) {
  const controller = new AbortController();

  const timeout = setTimeout(() => {
    controller.abort();
  }, timeoutMs);

  try {
    return await fetch(url, {
      ...options,

      signal: controller.signal,

      cache: 'no-store',
    });
  } finally {
    clearTimeout(timeout);
  }
}


/* -------------------------------------------------------------------------- */
/* DNS probe                                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Pokrece browser network request prema jedinstvenom hostname-u.
 *
 * Nama sam HTTP odgovor nije bitan.
 *
 * Bitan je DNS lookup koji browser mora da uradi PRE pokusaja
 * uspostavljanja konekcije.
 *
 *
 * Zasto Image()?
 *
 * Jednostavan je nacin da browser pokuša da ucita resource sa drugog
 * hostname-a bez potrebe da citamo response ili podesavamo CORS.
 *
 *
 * Zasto HTTPS?
 *
 * Glavni production sajt ce biti:
 *
 *   https://...
 *
 * Browser moze blokirati HTTP subresource sa HTTPS stranice kao
 * mixed content PRE nego sto obavi network request.
 *
 * Zato probe koristimo preko HTTPS-a.
 */
/**
 * Pokrece DNS lookup za jedinstveni probe hostname.
 *
 * Koristimo <link rel="dns-prefetch"> jer nam nije potreban pravi
 * HTTP/HTTPS zahtev — potreban nam je samo DNS lookup.
 *
 * Browser pokusava da resolve-uje hostname, sto dovodi do toga da
 * korisnikov DNS resolver kontaktira nas autoritativni DNS server.
 *
 * Na taj nacin izbegavamo:
 *
 *   - TLS certificate mismatch
 *   - HTTPS konekciju ka probe hostname-u
 *   - CORS probleme
 *
 * Probe hostname je svaki put jedinstven kako DNS cache ne bi
 * uticao na rezultat testa.
 */
function sendProbe(hostname) {
  return new Promise((resolve) => {
    const link = document.createElement('link');

    link.rel = 'dns-prefetch';
    link.href = `//${hostname}`;

    document.head.appendChild(link);

    setTimeout(() => {
      link.remove();
      resolve();
    }, 1000);
  });
}


/* -------------------------------------------------------------------------- */
/* Test                                                                       */
/* -------------------------------------------------------------------------- */

async function runTest() {
  /*
   * Sprečavamo double-click i paralelno pokretanje vise testova.
   */
  startBtn.disabled = true;
  retryBtn.disabled = true;


  startCard.classList.add('hidden');
  resultsCard.classList.add('hidden');

  progressCard.classList.remove('hidden');

  progressText.textContent =
    'Starting DNS leak test...';


  try {

    /* ---------------------------------------------------------------------- */
    /* 1. Create session                                                      */
    /* ---------------------------------------------------------------------- */

    const startRes = await fetchWithTimeout(
      '/api/test/start',
      {
        method: 'POST',
      }
    );


    if (!startRes.ok) {
      throw new Error(
        `Unable to start test (${startRes.status}).`
      );
    }


    const startData =
      await startRes.json();


    const {
      testId,
      dnsTestDomain,
      probeCount,
    } = startData;


    /* ---------------------------------------------------------------------- */
    /* Backend response validation                                            */
    /* ---------------------------------------------------------------------- */

    /*
     * Nikada slepo ne verujemo ni sopstvenom API odgovoru.
     *
     * Ako bug ili pogresna konfiguracija vrate los podatak,
     * frontend treba kontrolisano da prekine test.
     */

    const testIdRegex =
      /^[a-f0-9]{32}$/;


    const domainRegex =
      /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;


    if (!testIdRegex.test(testId)) {
      throw new Error(
        'Server returned an invalid test ID.'
      );
    }


    if (
      typeof dnsTestDomain !== 'string' ||
      !domainRegex.test(dnsTestDomain)
    ) {
      throw new Error(
        'Server returned an invalid DNS test domain.'
      );
    }


    if (
      !Number.isInteger(probeCount) ||
      probeCount < 1 ||
      probeCount > 20
    ) {
      throw new Error(
        'Server returned an invalid probe count.'
      );
    }


    /* ---------------------------------------------------------------------- */
    /* 2. DNS probes                                                          */
    /* ---------------------------------------------------------------------- */

    progressText.textContent =
      `Sending ${probeCount} DNS probes...`;


    const probes = [];


    for (
      let i = 0;
      i < probeCount;
      i += 1
    ) {

      const probeId =
        generateProbeId();


      const hostname =
        `${probeId}.${testId}.${dnsTestDomain}`;


      probes.push(
        sendProbe(hostname)
      );
    }


    await Promise.all(probes);


    /* ---------------------------------------------------------------------- */
    /* 3. Wait for slower recursive resolvers                                 */
    /* ---------------------------------------------------------------------- */

    progressText.textContent =
      'Collecting DNS resolver results...';


    await sleep(2000);


    /* ---------------------------------------------------------------------- */
    /* 4. Results                                                             */
    /* ---------------------------------------------------------------------- */

    const resultsRes =
      await fetchWithTimeout(
        `/api/test/${encodeURIComponent(testId)}/results`
      );


    if (!resultsRes.ok) {
      throw new Error(
        `Unable to retrieve results (${resultsRes.status}).`
      );
    }


    const data =
      await resultsRes.json();


    renderResults(data);

  } catch (error) {

    console.error(
      '[DNS Leak Test]',
      error
    );


    progressText.textContent =
      'The test could not be completed. Please try again.';


    /*
     * Omogucavamo korisniku da proba ponovo.
     */
    setTimeout(() => {
      progressCard.classList.add('hidden');
      startCard.classList.remove('hidden');

      startBtn.disabled = false;
    }, 1500);


    return;
  }


  startBtn.disabled = false;
  retryBtn.disabled = false;
}


/* -------------------------------------------------------------------------- */
/* Results                                                                    */
/* -------------------------------------------------------------------------- */

function createTableCell(text) {
  const td =
    document.createElement('td');

  /*
   * BITNO:
   *
   * Koristimo textContent, NE innerHTML.
   *
   * ISP/org/city podaci dolaze iz eksternog geo API-ja.
   * Nikada ih ne zelimo interpretirati kao HTML.
   */
  td.textContent =
    String(text ?? '');

  return td;
}


function renderResults(data) {
  progressCard.classList.add('hidden');

  resultsCard.classList.remove('hidden');

  resultsBody.replaceChildren();


  const resolvers =
    Array.isArray(data.resolvers)
      ? data.resolvers
      : [];


  /* ------------------------------------------------------------------------ */
  /* No results                                                               */
  /* ------------------------------------------------------------------------ */

  if (resolvers.length === 0) {

    /*
     * Ovo NIJE dokaz da nema DNS leak-a.
     *
     * Test je jednostavno inconclusive.
     */
    verdictEl.className =
      'verdict info';


    verdictEl.textContent =
      'No DNS resolvers were detected. The test is inconclusive. This may be caused by browser or network behavior, DNS configuration, or an incorrectly configured authoritative DNS delegation.';

    return;
  }


  /* ------------------------------------------------------------------------ */
  /* Provider summary                                                         */
  /* ------------------------------------------------------------------------ */

  const providerNames =
    new Set();


  for (const resolver of resolvers) {

    const provider =
      resolver.org ||
      resolver.isp;


    if (
      typeof provider === 'string' &&
      provider.trim()
    ) {
      providerNames.add(
        provider.trim()
      );
    }
  }


  verdictEl.className =
    'verdict info';


  if (providerNames.size > 1) {

    verdictEl.textContent =
      `${resolvers.length} DNS resolver(s) across ${providerNames.size} provider organizations were detected. Compare the providers below with the DNS service expected from your VPN or network configuration.`;

  } else {

    verdictEl.textContent =
      `${resolvers.length} DNS resolver(s) were detected. Check whether the provider shown below matches the DNS service expected from your VPN or network configuration.`;
  }


  /* ------------------------------------------------------------------------ */
  /* Table                                                                    */
  /* ------------------------------------------------------------------------ */

  for (const resolver of resolvers) {

    const tr =
      document.createElement('tr');


    const ip =
      typeof resolver.ip === 'string'
        ? resolver.ip
        : '-';


    let provider =
      resolver.isp || 'Unknown';


    if (
      resolver.org &&
      resolver.org !== resolver.isp
    ) {
      provider +=
        ` (${resolver.org})`;
    }


    let location = '-';


    if (
      resolver.city &&
      resolver.country
    ) {
      location =
        `${resolver.city}, ${resolver.country}`;

    } else if (resolver.country) {

      location =
        resolver.country;
    }


    const hitCount =
      Number.isFinite(resolver.hitCount)
        ? resolver.hitCount
        : 0;


    tr.appendChild(
      createTableCell(ip)
    );


    tr.appendChild(
      createTableCell(provider)
    );


    tr.appendChild(
      createTableCell(location)
    );


    tr.appendChild(
      createTableCell(hitCount)
    );


    resultsBody.appendChild(tr);
  }
}


/* -------------------------------------------------------------------------- */
/* Buttons                                                                    */
/* -------------------------------------------------------------------------- */

startBtn.addEventListener(
  'click',
  runTest
);


retryBtn.addEventListener(
  'click',
  () => {

    resultsCard.classList.add(
      'hidden'
    );

    progressCard.classList.add(
      'hidden'
    );

    startCard.classList.remove(
      'hidden'
    );


    verdictEl.textContent = '';

    resultsBody.replaceChildren();


    startBtn.disabled = false;
    retryBtn.disabled = false;
  }
);


/* -------------------------------------------------------------------------- */
/* Initial page state                                                         */
/* -------------------------------------------------------------------------- */

showPrivacyNotice();