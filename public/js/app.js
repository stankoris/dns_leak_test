'use strict';

const startBtn = document.getElementById('start-btn');
const retryBtn = document.getElementById('retry-btn');
const privacyCheck = document.getElementById('privacy-check');
const termsCheck = document.getElementById('terms-check');
const startState = document.getElementById('start-state');
const progressState = document.getElementById('progress-state');
const resultsState = document.getElementById('results-state');
const progressText = document.getElementById('progress-text');
const progressBar = document.getElementById('progress-bar');
const resultsBody = document.getElementById('results-body');
const verdict = document.getElementById('verdict');
const geoNote = document.getElementById('geo-note');
const startError = document.getElementById('start-error');

let currentResultToken = null;

function randomHex(byteLength = 8) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function setProgress(percent, message) {
  progressBar.style.width = `${percent}%`;
  progressText.textContent = message;
}

function updateStartButton() {
  const ready = privacyCheck.checked && termsCheck.checked;
  startBtn.dataset.ready = String(ready);
  startBtn.setAttribute('aria-disabled', String(!ready));
  if (ready) showStartError('');
}

function showStartError(message) {
  startError.textContent = message;
  startError.classList.toggle('hidden', !message);
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function triggerDnsProbe(hostname) {
  return new Promise((resolve) => {
    const image = new Image();
    let finished = false;

    const finish = () => {
      if (finished) return;
      finished = true;
      image.onload = null;
      image.onerror = null;
      resolve();
    };

    image.onload = finish;
    image.onerror = finish;

    // HTTPS avoids mixed-content blocking when the main site is served over HTTPS.
    // The image itself is expected to fail; the DNS lookup is the signal we need.
    const scheme = window.location.protocol === 'https:' ? 'https' : 'http';
    image.src = `${scheme}://${hostname}/dns-probe.gif?cache=${randomHex(4)}`;

    setTimeout(finish, 2200);
  });
}

async function createTestSession() {
  const response = await fetch('/api/tests', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    cache: 'no-store',
    body: JSON.stringify({
      privacyAcknowledged: privacyCheck.checked,
      termsAccepted: termsCheck.checked,
    }),
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || 'Unable to start the test.');
  }
  return data;
}

async function fetchResults(resultToken) {
  const response = await fetch(`/api/tests/${encodeURIComponent(resultToken)}`, {
    cache: 'no-store',
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || 'Unable to retrieve test results.');
  }
  return data;
}

async function removeSession() {
  if (!currentResultToken) return;
  const token = currentResultToken;
  currentResultToken = null;
  try {
    await fetch(`/api/tests/${encodeURIComponent(token)}`, {
      method: 'DELETE',
      cache: 'no-store',
    });
  } catch (_) {
    // Session cleanup is best-effort. It also expires automatically server-side.
  }
}

function renderResults(data) {
  startBtn.disabled = false;
  resultsBody.innerHTML = '';

  if (!data.resolvers || data.resolvers.length === 0) {
    verdict.className = 'verdict caution';
    verdict.innerHTML = `
      <strong>No resolver was detected</strong>
      <p>No DNS query reached the test server during the collection window. Try again once. If this persists, verify the authoritative DNS delegation and browser/network filtering.</p>
    `;
  } else {
    verdict.className = 'verdict good';
    verdict.innerHTML = `
      <strong>${data.resolverCount} DNS resolver${data.resolverCount === 1 ? '' : 's'} detected</strong>
      <p>Compare the provider shown below with the DNS service you expect to use. An unexpected ISP resolver may indicate a DNS leak.</p>
    `;

    for (const resolver of data.resolvers) {
      const provider = resolver.organization || resolver.asn || 'Not available';
      const location = [resolver.city, resolver.country].filter(Boolean).join(', ') || 'Not available';
      const row = document.createElement('tr');
      row.innerHTML = `
        <td class="mono">${escapeHtml(resolver.ip)}</td>
        <td>${escapeHtml(provider)}</td>
        <td>${escapeHtml(location)}</td>
        <td>${escapeHtml(resolver.count)}</td>
      `;
      resultsBody.appendChild(row);
    }
  }

  geoNote.textContent = data.geoLookupEnabled
    ? 'Provider and location data come from the configured local IP database.'
    : 'Local ISP/location enrichment is disabled; resolver IP detection still works normally.';

  progressState.classList.add('hidden');
  resultsState.classList.remove('hidden');
}

async function runTest() {
  if (!privacyCheck.checked || !termsCheck.checked) {
    showStartError('Please check both boxes before starting the test.');
    return;
  }

  showStartError('');
  startBtn.disabled = true;
  startState.classList.add('hidden');
  resultsState.classList.add('hidden');
  progressState.classList.remove('hidden');

  try {
    setProgress(16, 'Creating a private test session…');
    const session = await createTestSession();
    currentResultToken = session.resultToken;

    setProgress(36, `Sending ${session.probeCount} unique DNS probes…`);
    const probes = [];
    for (let index = 0; index < session.probeCount; index += 1) {
      const hostname = `${randomHex(4)}.${session.testId}.${session.dnsTestDomain}`;
      probes.push(triggerDnsProbe(hostname));
    }
    await Promise.all(probes);

    setProgress(72, 'Waiting for DNS resolvers to reach the authoritative server…');
    await new Promise((resolve) => setTimeout(resolve, 1800));

    setProgress(90, 'Collecting results…');
    const data = await fetchResults(session.resultToken);
    setProgress(100, 'Done');
    renderResults(data);
  } catch (error) {
    progressState.classList.add('hidden');
    startState.classList.remove('hidden');
    showStartError(error.message || 'The test failed. Please try again.');
    startBtn.disabled = false;
    updateStartButton();
  }
}

privacyCheck.addEventListener('change', updateStartButton);
termsCheck.addEventListener('change', updateStartButton);
startBtn.addEventListener('click', runTest);
retryBtn.addEventListener('click', async () => {
  await removeSession();
  resultsState.classList.add('hidden');
  progressState.classList.add('hidden');
  startState.classList.remove('hidden');
  progressBar.style.width = '18%';
  showStartError('');
  updateStartButton();
});

updateStartButton();
