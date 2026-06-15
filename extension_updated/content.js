// ─── Block Overlay ────────────────────────────────────────────────────────────

let _blockOverlay = null;
let _blockedUrl   = null;
let _pendingBlock = null; // holds message if DOM not ready yet

const CSS = `
  @keyframes utr-in {
    from { opacity: 0; transform: scale(0.93) translateY(20px); }
    to   { opacity: 1; transform: scale(1)    translateY(0); }
  }
  @keyframes utr-pulse {
    0%,100% { box-shadow: 0 0 0 0   rgba(239,68,68,0.45); }
    50%      { box-shadow: 0 0 0 20px rgba(239,68,68,0);   }
  }
  @keyframes utr-shake {
    0%,100%{ transform:rotate(0deg); }
    20%    { transform:rotate(-7deg); }
    40%    { transform:rotate( 7deg); }
    60%    { transform:rotate(-4deg); }
    80%    { transform:rotate( 4deg); }
  }
  @keyframes utr-bar {
    from { background-position: 0 0; }
    to   { background-position: 40px 0; }
  }
  #utr-overlay {
    position: fixed !important;
    inset: 0 !important;
    z-index: 2147483647 !important;
    background: linear-gradient(135deg,#09000f 0%,#180008 50%,#09000e 100%) !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    padding: 20px !important;
    font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif !important;
    overflow: auto !important;
  }
  #utr-card {
    max-width: 620px; width: 100%;
    background: rgba(16,5,5,0.98);
    border: 1.5px solid rgba(239,68,68,0.35);
    border-radius: 20px;
    padding: 44px 40px 36px;
    box-shadow: 0 0 80px rgba(239,68,68,0.2), 0 30px 70px rgba(0,0,0,0.7);
    animation: utr-in 0.4s cubic-bezier(.2,1,.4,1) forwards;
    position: relative;
    overflow: hidden;
    text-align: center;
  }
  #utr-topbar {
    position: absolute; top:0; left:0; right:0; height:3px;
    background: repeating-linear-gradient(
      90deg,
      #ef4444 0px, #ef4444 20px,
      #f97316 20px,#f97316 40px
    );
    background-size: 40px 3px;
    animation: utr-bar 0.8s linear infinite;
    opacity: 0.9;
  }
  #utr-icon-wrap {
    width:80px; height:80px; border-radius:50%;
    background: rgba(239,68,68,0.1);
    border: 2px solid rgba(239,68,68,0.35);
    display: flex; align-items:center; justify-content:center;
    margin: 0 auto 22px;
    animation: utr-pulse 2.2s ease-in-out infinite, utr-shake 0.65s ease 0.5s;
  }
  #utr-eyebrow {
    font-size:11px; font-weight:800; letter-spacing:0.2em;
    text-transform:uppercase; color:#ef4444; margin-bottom:10px;
  }
  #utr-title {
    font-size:26px; font-weight:800; letter-spacing:-0.02em;
    color:#fff; margin-bottom:14px; line-height:1.2;
  }
  #utr-url-box {
    background: rgba(239,68,68,0.07);
    border: 1px solid rgba(239,68,68,0.22);
    border-radius:10px; padding:11px 15px;
    margin-bottom:20px;
    font-family:'SF Mono','Fira Code','Cascadia Code',Menlo,monospace;
    font-size:12px; color:#fca5a5;
    word-break:break-all; line-height:1.55;
    max-height:80px; overflow-y:auto; text-align:left;
  }
  #utr-stats {
    display:flex; gap:10px; justify-content:center;
    flex-wrap:wrap; margin-bottom:30px;
  }
  .utr-stat {
    background:rgba(239,68,68,0.09);
    border:1px solid rgba(239,68,68,0.25);
    border-radius:10px; padding:11px 20px; min-width:100px;
  }
  .utr-stat-label {
    font-size:9px; font-weight:800; letter-spacing:0.14em;
    text-transform:uppercase; color:#f87171; margin-bottom:5px;
  }
  .utr-stat-value {
    font-size:20px; font-weight:800; color:#ef4444;
  }
  #utr-buttons {
    display:flex; gap:10px; flex-wrap:wrap; justify-content:center;
    margin-bottom:20px;
  }
  .utr-btn {
    padding:13px 22px; font-size:14px; font-weight:700;
    border:none; border-radius:11px; cursor:pointer;
    letter-spacing:0.03em; min-width:145px;
    transition: opacity 0.15s, transform 0.1s;
  }
  .utr-btn:hover  { opacity:0.85; transform:translateY(-1px); }
  .utr-btn:active { transform:scale(0.97); }
  #utr-btn-back    { background:#ef4444; color:#fff; }
  #utr-btn-rescan  { background:rgba(59,130,246,0.14); color:#93c5fd;
                     border:1.5px solid rgba(59,130,246,0.3); }
  #utr-btn-proceed { background:rgba(100,116,139,0.14); color:#94a3b8;
                     border:1.5px solid rgba(100,116,139,0.25); }
  #utr-footer {
    font-size:11.5px; color:#475569; line-height:1.65;
  }
`;

function _ensureStyle() {
  if (document.getElementById('utr-style')) return;
  const s = document.createElement('style');
  s.id = 'utr-style';
  s.textContent = CSS;
  (document.head || document.documentElement).appendChild(s);
}

function _createBlockOverlay({ url, confidence, risk, reason, domainAgeDays }) {
  if (_blockOverlay) return;

  _ensureStyle();

  const isNewDomain = reason === 'new_domain';
  const pct = typeof confidence === 'number' ? (confidence * 100).toFixed(1) : null;
  const riskLabel = (risk || 'HIGH').toUpperCase();

  _blockedUrl = url;
  _blockOverlay = document.createElement('div');
  _blockOverlay.id = 'utr-overlay';

  _blockOverlay.innerHTML = `
    <div id="utr-card">
      <div id="utr-topbar"></div>

      <div id="utr-icon-wrap">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none">
          <path d="M12 2L4 6v6c0 4.42 3.47 8.56 8 9.56 4.53-1 8-5.14 8-9.56V6l-8-4z"
                fill="rgba(239,68,68,0.2)" stroke="#ef4444" stroke-width="1.5" stroke-linejoin="round"/>
          <line x1="12" y1="8" x2="12" y2="13" stroke="#ef4444" stroke-width="2.2" stroke-linecap="round"/>
          <circle cx="12" cy="16.5" r="1.1" fill="#ef4444"/>
        </svg>
      </div>

      <div id="utr-eyebrow">⚠&nbsp; Security Warning &nbsp;⚠</div>
      <div id="utr-title">
        ${isNewDomain ? 'Newly Registered Domain' : 'Phishing Threat Detected'}
      </div>

      <div id="utr-url-box">${url}</div>

      <div id="utr-stats">
        <div class="utr-stat">
          <div class="utr-stat-label">Risk Level</div>
          <div class="utr-stat-value">${riskLabel}</div>
        </div>
        ${isNewDomain ? `
        <div class="utr-stat">
          <div class="utr-stat-label">Domain Age</div>
          <div class="utr-stat-value">${domainAgeDays !== null && domainAgeDays !== undefined ? domainAgeDays + 'd' : '<30d'}</div>
        </div>` : ''}
        ${pct !== null ? `
        <div class="utr-stat">
          <div class="utr-stat-label">Confidence</div>
          <div class="utr-stat-value">${pct}%</div>
        </div>` : ''}
      </div>

      <div id="utr-buttons">
        <button class="utr-btn" id="utr-btn-back">← Go Back</button>
        <button class="utr-btn" id="utr-btn-rescan">↺ Rescan Page</button>
        <button class="utr-btn" id="utr-btn-proceed">Proceed Anyway</button>
      </div>

      <div id="utr-footer">
        This page was flagged by URL Threat Reporter.<br>
        Proceeding may expose you to credential theft or malware.
      </div>
    </div>
  `;

  // Attach to documentElement so it works even before <body> is parsed
  const root = document.body || document.documentElement;
  root.appendChild(_blockOverlay);
  if (document.body) document.body.style.overflow = 'hidden';

  document.getElementById('utr-btn-back').addEventListener('click', () => {
    window.history.back();
  });

  document.getElementById('utr-btn-rescan').addEventListener('click', () => {
    const target = _blockedUrl;
    _removeBlockOverlay();
    if (target) {
      chrome.runtime.sendMessage({ type: 'scan_current', url: target });
      window.location.reload();
    }
  });

  document.getElementById('utr-btn-proceed').addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'allow_phishing' });
    _removeBlockOverlay();
  });
}

function _removeBlockOverlay() {
  if (_blockOverlay) {
    _blockOverlay.remove();
    _blockOverlay = null;
    _blockedUrl = null;
    _pendingBlock = null;
    if (document.body) document.body.style.overflow = '';
  }
}

// ─── Message listener ─────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message) => {
  if (!message || !message.type) return;

  if (message.type === 'block_page') {
    if (document.body) {
      _createBlockOverlay(message);
    } else {
      // DOM not ready yet — wait for it
      _pendingBlock = message;
      document.addEventListener('DOMContentLoaded', () => {
        if (_pendingBlock) { _createBlockOverlay(_pendingBlock); _pendingBlock = null; }
      }, { once: true });
    }
  }

  if (message.type === 'clear_block') {
    _removeBlockOverlay();
  }
});

// ─── Link scanner ─────────────────────────────────────────────────────────────

document.addEventListener('click', (event) => {
  const anchor = event.target.closest('a[href]');
  if (!anchor) return;
  const url = anchor.href;
  if (!url) return;
  chrome.runtime.sendMessage({ type: 'scan_link', url });
});
