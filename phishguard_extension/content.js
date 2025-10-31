// PhishGuard Link Verifier - content script
// Intercepts <a> clicks, shows a top banner, verifies via backend, and decides navigation.

// CONFIG
const VERIFY_ENDPOINT = 'http://127.0.0.1:8001/verify';
const DASHBOARD_BASE = 'http://127.0.0.1:5173';
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const AUTO_OPEN_SAFE_MS = 1000; // safe -> open after 1s

// State
let pendingNav = null;
let banner = null;
let bannerTimer = null;

// Utils
function isModifiedClick(e) {
  return e.button === 1 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey;
}

function findAnchor(el) {
  while (el && el !== document.body) {
    if (el.tagName === 'A' && el.href) return el;
    el = el.parentElement;
  }
  return null;
}

function getStatusClass(status, confidence) {
  const s = String(status || '').toLowerCase();
  if (s.includes('phish') || s.includes('malicious') || s.includes('bad')) return 'pg-red';
  if (s.includes('suspicious') || (typeof confidence === 'number' && confidence < 0.7)) return 'pg-yellow';
  if (s.includes('legit') || s.includes('safe')) return 'pg-green';
  return 'pg-blue'; // verifying/unknown
}

function runtimeUrl(path) {
  return chrome.runtime.getURL(path);
}

function openInBackgroundTab(url) {
  try {
    chrome.runtime.sendMessage({ type: 'PG_OPEN_BG_TAB', url });
  } catch (_) {
    // ignore
  }
}

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return;
  } catch (_) {
    // Fallback: hidden textarea
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    } catch (_) {}
  }
}

async function loadCache() {
  return new Promise((resolve) => {
    try {
      chrome.storage.local.get(['pgCache'], (obj) => {
        resolve(obj.pgCache || {});
      });
    } catch (_) {
      resolve({});
    }
  });
}

async function saveCache(cache) {
  try {
    await chrome.storage.local.set({ pgCache: cache });
  } catch (_) {}
}

async function getCached(url) {
  const cache = await loadCache();
  const item = cache[url];
  if (!item) return null;
  if (Date.now() - item.ts > CACHE_TTL_MS) return null;
  return item;
}

async function setCached(url, data) {
  const cache = await loadCache();
  cache[url] = { ...data, ts: Date.now() };
  await saveCache(cache);
}

function showBanner({ url, mode = 'verifying', statusText = 'Verifying…', confidence, reason }) {
  if (!banner) {
    banner = document.createElement('div');
    banner.id = 'pg-banner';
    banner.innerHTML = `
      <div class="pg-wrap">
        <div class="pg-text">
          <strong>PhishGuard</strong> detected a link: <span class="pg-url"></span>.
          <span class="pg-msg"></span>
        </div>
        <div class="pg-actions">
          <button class="pg-verify">Verify</button>
          <button class="pg-ignore">Ignore</button>
        </div>
      </div>
    `;
    document.documentElement.appendChild(banner);

    // Styles (blue/green/yellow/red themes)
    const style = document.createElement('style');
    style.textContent = `
      #pg-banner {
        position: fixed;
        top: 0; left: 0; right: 0;
        z-index: 999999;
        font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      }
      #pg-banner .pg-wrap {
        display: flex; align-items: center; justify-content: space-between;
        padding: 10px 14px;
        color: #ffffff;
      }
      #pg-banner.pg-blue .pg-wrap { background: #2563eb; }     /* Verifying */
      #pg-banner.pg-green .pg-wrap { background: #059669; }    /* Safe */
      #pg-banner.pg-yellow .pg-wrap { background: #ca8a04; }   /* Suspicious */
      #pg-banner.pg-red .pg-wrap { background: #dc2626; }      /* Phishing */
      #pg-banner .pg-text { font-size: 14px; }
      #pg-banner .pg-text .pg-url { font-weight: 600; }
      #pg-banner .pg-actions { display: flex; gap: 8px; }
      #pg-banner .pg-actions button {
        padding: 8px 12px; border: none; border-radius: 8px; cursor: pointer;
        background: #111827; color: #fff;
      }
      #pg-banner .pg-actions button.pg-ignore { background: rgba(0,0,0,0.35); }
    `;
    document.documentElement.appendChild(style);

    banner.querySelector('.pg-verify').addEventListener('click', onClickVerify);
    banner.querySelector('.pg-ignore').addEventListener('click', onClickIgnore);
  }

  banner.querySelector('.pg-url').textContent = url;
  const confText = typeof confidence === 'number' ? ` (confidence ${confidence.toFixed(2)})` : '';
  const msg = reason ? `Status: ${statusText}${confText}. Reason: ${reason}` : `Status: ${statusText}${confText}`;
  banner.querySelector('.pg-msg').textContent = mode === 'verifying'
    ? ' Would you like to verify it?'
    : ` ${msg}`;

  banner.classList.remove('pg-blue', 'pg-green', 'pg-yellow', 'pg-red');
  if (mode === 'verifying') banner.classList.add('pg-blue');
  else banner.classList.add(getStatusClass(statusText, confidence));

  banner.style.display = 'block';

  // Do NOT auto-dismiss: keep navigation blocked until user chooses.
  clearTimeout(bannerTimer);
}

function hideBanner() {
  if (banner) banner.style.display = 'none';
  clearTimeout(bannerTimer);
}

async function verifyUrl(targetUrl) {
  try {
    const res = await fetch(VERIFY_ENDPOINT, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ url: targetUrl })
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (e) {
    return { status: 'unknown', confidence: 0, reason: `Network error: ${e?.message || e}` };
  }
}

function deriveResult(data) {
  let status = data?.status || (data?.is_phishing === true ? 'phishing' : (data?.is_phishing === false ? 'legitimate' : 'unknown'));
  const confidence = (typeof data?.confidence === 'number')
    ? data.confidence
    : (typeof data?.meta?.confidence === 'number' ? data.meta.confidence : undefined);
  const reason = data?.reason || data?.meta?.reason || '';
  const s = String(status).toLowerCase();
  return { status, confidence, reason, s };
}

function continueNavigation() {
  const nav = pendingNav;
  pendingNav = null;
  hideBanner();
  if (!nav) return;

  if (nav.newTab) {
    window.open(nav.href, '_blank', 'noopener');
  } else {
    window.location.href = nav.href;
  }
}

function goToWarningPage(reason, phishing = false) {
  const nav = pendingNav;
  pendingNav = null;
  hideBanner();
  if (!nav) return;

  if (phishing) {
    // Use extension’s internal warning page
    const url = runtimeUrl(`warning.html?url=${encodeURIComponent(nav.href)}&reason=${encodeURIComponent(reason || '')}`);
    window.location.href = url;
  } else {
    // Suspicious -> use web app’s warning page
    const url = `${DASHBOARD_BASE}/warning?url=${encodeURIComponent(nav.href)}&reason=${encodeURIComponent(reason || '')}`;
    window.location.href = url;
  }
}

async function onClickVerify() {
  if (!pendingNav) return;
  const { href } = pendingNav;

  await copyToClipboard(href);

  // Cache check
  const cached = await getCached(href);
  if (cached) {
    const { status, confidence, reason } = cached;
    showBanner({ url: href, mode: 'result', statusText: status, confidence, reason });

    const s = String(status).toLowerCase();
    if (s.includes('phish') || s.includes('malicious')) return goToWarningPage(reason, true);
    if (s.includes('suspicious') || (typeof confidence === 'number' && confidence < 0.7)) {
      openInBackgroundTab(`${DASHBOARD_BASE}/verify?url=${encodeURIComponent(href)}`);
      return goToWarningPage(reason, false);
    }
    setTimeout(continueNavigation, AUTO_OPEN_SAFE_MS);
    return;
  }

  // Live verify
  showBanner({ url: href, mode: 'verifying' });
  const data = await verifyUrl(href);
  const { status, confidence, reason, s } = deriveResult(data);
  await setCached(href, { status, confidence, reason });

  showBanner({ url: href, mode: 'result', statusText: status, confidence, reason });

  // Decision:
  // - Phishing/Malicious: block via warning page
  // - Legitimate/Safe: open immediately
  // - Suspicious or low-confidence: redirect to your app's warning page
  // - Unknown: keep banner; wait for explicit user action
  if (s.includes('phish') || s.includes('malicious')) {
    return goToWarningPage(reason, true);
  }
  if (s.includes('legit') || s.includes('safe')) {
    return continueNavigation();
  }
  if (s.includes('suspicious') || (typeof confidence === 'number' && confidence < 0.7)) {
    return goToWarningPage(reason, false);
  }
  // Unknown: no auto navigation. User can click "Open Anyway" or "Block".
}

function onClickIgnore() {
  // Treat as immediate allow
  continueNavigation();
}

addEventListener('click', (e) => {
  const a = findAnchor(e.target);
  if (!a) return;
  const href = a.href;
  if (!href || href.startsWith('javascript:') || href.startsWith('#')) return;

  // Intercept initial navigation
  e.preventDefault();
  e.stopPropagation();

  pendingNav = { href, newTab: isModifiedClick(e) || a.target === '_blank' };

  // Show banner invitation to verify
  showBanner({ url: href, mode: 'verifying' });
}, true); // capture phase to act early
