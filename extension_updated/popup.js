// ─── Threat Scanner ─────────────────────────────────────────────────────────

const statusCard    = document.getElementById('current-status');
const statusValue   = document.getElementById('status-value');
const statusPill    = document.getElementById('status-pill');
const statusMeta    = document.getElementById('status-meta');
const statusUrl     = document.getElementById('status-url');
const confRow       = document.getElementById('conf-row');
const confFill      = document.getElementById('conf-fill');
const confVal       = document.getElementById('conf-val');
const historyList   = document.getElementById('history');
const scanActiveBtn = document.getElementById('scan-active-btn');
const allowSiteBtn  = document.getElementById('allow-site-btn');

function _esc(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function _timeAgo(isoString) {
  if (!isoString) return '';
  const diff = Date.now() - new Date(isoString).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60)  return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60)  return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24)  return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function renderHistory(items) {
  historyList.innerHTML = '';
  if (!items || items.length === 0) {
    historyList.innerHTML = '<li class="history-empty">No scans yet</li>';
    return;
  }

  [...items].reverse().forEach((item) => {
    const cls  = item.label === 'phishing' ? 'phishing' : 'safe';
    const risk = (item.risk || '').toLowerCase();
    const isNewDomain = item.reason === 'new_domain';
    const pct  = typeof item.confidence === 'number' ? (item.confidence * 100).toFixed(1) : '0.0';

    const li = document.createElement('li');
    li.className = `history-item ${cls}`;

    // Badge row
    const row = document.createElement('div');
    row.className = 'history-row';

    const badgeWrap = document.createElement('div');
    badgeWrap.style.cssText = 'display:flex;align-items:center;gap:5px;';

    const badge = document.createElement('span');
    badge.className = `history-badge ${cls}`;
    badge.textContent = (item.label || 'unknown').toUpperCase();
    badgeWrap.appendChild(badge);

    if (isNewDomain) {
      const nd = document.createElement('span');
      nd.className = 'history-newdomain';
      nd.textContent = '⚠ New Domain';
      badgeWrap.appendChild(nd);
    }

    const meta = document.createElement('div');
    meta.className = 'history-meta';
    meta.innerHTML = `<span class="history-risk ${risk}">${(item.risk || '').toUpperCase()}</span>
                      <span class="history-conf">${pct}%</span>`;

    row.appendChild(badgeWrap);
    row.appendChild(meta);
    li.appendChild(row);

    // URL row — set via textContent so special chars render correctly
    const urlWrap = document.createElement('div');
    urlWrap.className = 'history-url-wrap';

    const urlSpan = document.createElement('span');
    urlSpan.className = 'history-url';
    urlSpan.textContent = item.url || '(no url)';   // textContent, never innerHTML
    urlWrap.appendChild(urlSpan);
    li.appendChild(urlWrap);

    // Timestamp
    if (item.ts) {
      const ts = document.createElement('div');
      ts.className = 'history-ts';
      ts.textContent = _timeAgo(item.ts);
      li.appendChild(ts);
    }

    historyList.appendChild(li);
  });
}

function updateCurrentStatus(last) {
  const cls = last.label === 'phishing' ? 'phishing' : 'safe';
  const pct = (last.confidence * 100).toFixed(1);

  statusCard.className = `status-card ${cls}`;
  statusValue.className = `status-value ${cls}`;
  statusValue.textContent = last.label === 'phishing' ? 'PHISHING DETECTED' : 'SAFE';
  statusPill.className = `status-pill ${cls}`;
  statusPill.textContent = cls === 'phishing' ? 'Threat' : 'Clear';

  const reasonNote = last.reason === 'new_domain' ? ' · ⚠ Domain < 30 days old' : '';
  statusMeta.textContent = `${pct}% confidence · Risk: ${(last.risk || '').toUpperCase()}${reasonNote}`;
  statusUrl.textContent = last.url || '';

  confRow.style.display = 'flex';
  confFill.style.width = `${pct}%`;
  confVal.textContent = `${pct}%`;
}

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  if (chrome.runtime.lastError) return;
  const tab = tabs && tabs[0];
  if (!tab) return;
  if (tab.url) statusUrl.textContent = tab.url;

  scanActiveBtn.addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'scan_current', tabId: tab.id, url: tab.url });
    window.close();
  });
  allowSiteBtn.addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'allow_phishing', tabId: tab.id, url: tab.url });
    window.close();
  });
});

chrome.storage.local.get(['scan_history'], (store) => {
  if (chrome.runtime.lastError) { statusValue.textContent = 'Unable to load history'; return; }
  const history = store.scan_history || [];
  renderHistory(history);
  if (history.length > 0) updateCurrentStatus(history[history.length - 1]);
});
