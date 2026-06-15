// ─── Threat Scanner ───────────────────────────────────────────────────────────

const BRIDGE_URL = 'http://127.0.0.1:8765/report';
const AUTH = 'change_this_secret'; // set to match desktop app

const _recentScans = new Map();
const _DEDUP_MS = 2500;
const _allowedPhishingTabs = new Map();

function _setBadge(text, color) {
  try {
    chrome.action.setBadgeText({ text });
    chrome.action.setBadgeBackgroundColor({ color });
  } catch (e) {
    console.warn('badge update failed', e);
  }
}

function _clearBadge(delay = 6000) {
  setTimeout(() => {
    try {
      chrome.action.setBadgeText({ text: '' });
    } catch (e) {
      console.warn('badge clear failed', e);
    }
  }, delay);
}

function _notify(id, options) {
  try {
    chrome.notifications.create(id, options, function (nid) {
      if (options.priority !== 2) {
        setTimeout(() => chrome.notifications.clear(nid), 6000);
      }
    });
  } catch (e) {
    console.warn('notification failed', e);
  }
}

function _sendTabMessage(tabId, message) {
  if (!tabId) return;
  chrome.tabs.sendMessage(tabId, message, () => {
    const err = chrome.runtime.lastError;
    if (err) console.debug('sendTabMessage failed', err.message);
  });
}

// ─── Domain Age Check (RDAP) ──────────────────────────────────────────────────
// Returns age in days, or null if lookup fails.
async function _getDomainAgeDays(hostname) {
  try {
    // Strip subdomains down to registrable domain (e.g. sub.example.com → example.com)
    const parts = hostname.split('.');
    const domain = parts.length > 2 ? parts.slice(-2).join('.') : hostname;

    const res = await fetch(`https://rdap.cloudflare.com/rdap/v1/domain/${domain}`, {
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return null;

    const data = await res.json();
    const events = data.events || [];
    const regEvent = events.find(
      (e) => e.eventAction === 'registration' || e.eventAction === 'last changed'
    );
    if (!regEvent) return null;

    const regDate = new Date(regEvent.eventDate);
    if (isNaN(regDate.getTime())) return null;

    return (Date.now() - regDate.getTime()) / (1000 * 60 * 60 * 24);
  } catch (e) {
    console.debug('RDAP lookup failed', e);
    return null;
  }
}

// ─── Main scan ────────────────────────────────────────────────────────────────
async function reportUrl(url, tabId) {
  const now = Date.now();
  const last = _recentScans.get(url) || 0;
  if (now - last < _DEDUP_MS) return;
  _recentScans.set(url, now);

  const scanId = `scan_${now}`;
  _notify(scanId, {
    type: 'basic',
    iconUrl: 'icon48.png',
    title: 'Threat scan started',
    message: `Scanning ${url}`,
    priority: 0,
  });
  _setBadge('...', '#007bff');

  try {
    let hostname = '';
    try { hostname = new URL(url).hostname.replace(/^www\./, ''); } catch (_) {}

    // Run ML scan and domain age check in parallel
    const [res, domainAgeDays] = await Promise.all([
      fetch(BRIDGE_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Bridge-Auth': AUTH },
        body: JSON.stringify({ url, source: 'browser' }),
      }),
      hostname ? _getDomainAgeDays(hostname) : Promise.resolve(null),
    ]);

    const data = await res.json().catch(() => ({}));

    const label = (data.label || data.prediction || 'unknown').toLowerCase();
    const confidence = typeof data.confidence === 'number' ? data.confidence : (data.score || 0);
    const risk = data.risk || (label === 'phishing' ? 'high' : 'low');

    // New-domain flag: registered < 30 days ago
    const isNewDomain = domainAgeDays !== null && domainAgeDays < 30;
    const isPhishing = isNewDomain || label === 'phishing' || (label === 'safe' && confidence >= 0.25);
    const reason = isNewDomain ? 'new_domain' : 'ml_scan';

    const title = isPhishing ? 'Potential threat detected' : 'Site appears safe';
    const message = isNewDomain
      ? `New domain (${Math.floor(domainAgeDays)}d old) — HIGH risk`
      : isPhishing
        ? `Threat: ${risk.toUpperCase()} (confidence ${(confidence * 100).toFixed(1)}%)`
        : `Safe (confidence ${(confidence * 100).toFixed(1)}%)`;

    _notify(`scan_result_${Date.now()}`, {
      type: 'basic',
      iconUrl: 'icon48.png',
      title,
      message,
      priority: isPhishing ? 2 : 0,
    });
    _setBadge(isPhishing ? '!' : '✔', isPhishing ? '#d9534f' : '#5cb85c');
    _clearBadge();

    if (tabId) {
      if (isPhishing && !_allowedPhishingTabs.has(tabId)) {
        _sendTabMessage(tabId, {
          type: 'block_page',
          url,
          confidence,
          risk: isNewDomain ? 'high' : risk,
          reason,
          domainAgeDays: isNewDomain ? Math.floor(domainAgeDays) : null,
        });
      } else {
        _sendTabMessage(tabId, { type: 'clear_block' });
      }
    }

    try {
      const key = 'scan_history';
      const store = await chrome.storage.local.get([key]);
      const history = (store[key] || []).slice(-200);
      history.push({
        url,
        label: isNewDomain ? 'phishing' : label,
        confidence,
        risk: isNewDomain ? 'high' : risk,
        reason,
        domainAgeDays: domainAgeDays !== null ? Math.floor(domainAgeDays) : null,
        ts: new Date().toISOString(),
      });
      await chrome.storage.local.set({ [key]: history });
      if (tabId) {
        await chrome.storage.local.set({ [`tab_${tabId}_last_scan`]: history[history.length - 1] });
      }
    } catch (e) {
      console.warn('storage save failed', e);
    }

    return data;
  } catch (e) {
    console.warn('reportUrl failed', e);
    _notify(`scan_error_${Date.now()}`, {
      type: 'basic',
      iconUrl: 'icon48.png',
      title: 'Scan failed',
      message: `Could not scan ${url}`,
      priority: 2,
    });
    return { error: 'failed' };
  }
}

chrome.webNavigation.onCommitted.addListener(function (details) {
  if (details.frameId === 0 && details.url) {
    reportUrl(details.url, details.tabId);
  }
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab && tab.url) reportUrl(tab.url, tab.id);
  } catch (e) {}
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    _allowedPhishingTabs.delete(tabId);
    reportUrl(tab.url, tabId);
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const senderTabId = sender.tab?.id;

  if (message && message.type === 'scan_link' && message.url) {
    reportUrl(message.url, senderTabId);
  }
  if (message && message.type === 'scan_current' && message.url) {
    reportUrl(message.url, senderTabId);
  }
  if (message && message.type === 'allow_phishing') {
    const tabId = message.tabId || senderTabId;
    const url = message.url || (sender.tab && sender.tab.url);
    if (tabId && url) {
      _allowedPhishingTabs.set(tabId, url);
      _sendTabMessage(tabId, { type: 'clear_block' });
    }
  }
});

// ─── Device Monitor (independent feature) ─────────────────────────────────────

const DM_ALARM = 'dm_check';

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create(DM_ALARM, { periodInMinutes: 1 });
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== DM_ALARM) return;

  const store = await chrome.storage.local.get(['dm_email', 'dm_api_url']);
  const email = store.dm_email;
  const apiUrl = store.dm_api_url || '';
  if (!email || !apiUrl) return;

  try {
    const res = await fetch(`${apiUrl}/check_alerts/${encodeURIComponent(email)}`);
    const data = await res.json();
    const devices = data.devices || [];
    if (devices.length === 0) return;

    const latest = devices[0];
    if (!latest.suspicious) return;

    const ts = new Date(latest.timestamp).getTime();
    if (Date.now() - ts > 2 * 60 * 1000) return;

    const location = `${latest.city}, ${latest.country}`;
    _notify(`dm_alert_${Date.now()}`, {
      type: 'basic',
      iconUrl: 'icon48.png',
      title: 'Suspicious Login Detected',
      message: `${location} — ${latest.ip}`,
      priority: 2,
    });
  } catch (e) {
    console.debug('DM check failed', e);
  }
});
