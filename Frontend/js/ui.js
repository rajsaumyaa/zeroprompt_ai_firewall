// ── UI HELPERS ────────────────────────────────────────────────
// Risk colours, finding card rendering, panel state updates.

const SEV_COLOR = { critical:'#ff2d55', high:'#ff9f0a', medium:'#ffd60a', low:'#30d158' };

// Returns risk metadata for a given score
function getRiskLevel(score) {
  if (score >= 88) return { label:'CRITICAL', color:'#ff2d55', bg:'rgba(255,45,85,0.08)',  border:'rgba(255,45,85,0.3)',  panelCls:'crit' };
  if (score >= 65) return { label:'HIGH',     color:'#ff9f0a', bg:'rgba(255,159,10,0.08)', border:'rgba(255,159,10,0.3)', panelCls:'high' };
  if (score >= 40) return { label:'MEDIUM',   color:'#ffd60a', bg:'rgba(255,214,10,0.08)', border:'rgba(255,214,10,0.3)', panelCls:'med'  };
  if (score >= 10) return { label:'LOW',       color:'#34c759', bg:'rgba(52,199,89,0.08)',  border:'rgba(52,199,89,0.3)',  panelCls:''     };
  return                  { label:'SAFE',      color:'#32d74b', bg:'rgba(50,215,75,0.08)',  border:'rgba(50,215,75,0.3)',  panelCls:''     };
}

// Build a single finding card HTML string
function findingCardHTML(f) {
  const c  = SEV_COLOR[f.severity] || '#888';
  const hb = f.deobfuscated
    ? `<span class="hbadge">⚠ IN ${(f.sourceLabel || '').toUpperCase()}</span>`
    : '';
  return `<div class="fc" style="background:${c}09;border:1px solid ${c}22">
    <div class="fdot" style="background:${c};box-shadow:0 0 8px ${c}55"></div>
    <div class="fbody">
      <div class="ftop">
        <div><span class="fcat" style="color:${c}">${(f.category || f.name || '').toUpperCase()}</span>${hb}</div>
        <div class="fmeta">
          <span class="flayer">${f.layer || 'regex'}</span>
          <span class="fscore" style="color:${c};background:${c}18">+${f.score}</span>
        </div>
      </div>
      <div class="fmatch">${f.match || f.name || ''}</div>
    </div>
  </div>`;
}

// Render findings into a container element
function renderFindings(findings, containerId) {
  const el = document.getElementById(containerId);
  if (!findings || !findings.length) { el.innerHTML = ''; return; }
  const shown = findings.slice(0, 6);
  el.innerHTML = `<div class="flist">
    ${shown.map(findingCardHTML).join('')}
    ${findings.length > 6
      ? `<div class="mono" style="font-size:9px;color:rgba(255,255,255,0.2);text-align:center;padding:4px">+${findings.length - 6} more threats</div>`
      : ''}
  </div>`;
}

// Update the input stream panel
function updateInpPanel(res) {
  if (!res) return;
  const r = getRiskLevel(res.score);
  document.getElementById('ip-inp').className = 'stream-box ' + (res.score > 0 ? r.panelCls : '');

  const bar = document.getElementById('inp-bar');
  bar.style.width     = res.score + '%';
  bar.style.boxShadow = res.score > 0 ? `0 0 6px ${r.color}` : 'none';
    bar.style.background = res.score > 0 ? `linear-gradient(90deg, ${r.color}88, ${r.color})` : 'linear-gradient(90deg,#34c759,#30d158)';

  const rb = document.getElementById('inp-rb');
  if (res.score > 0) {
    rb.style.display    = 'inline';
    rb.textContent      = r.label;
    rb.style.color      = r.color;
    rb.style.background = r.bg;
    rb.style.border     = `1px solid ${r.border}`;
  } else rb.style.display = 'none';

  const tc = document.getElementById('inp-tc');
  if (res.findings && res.findings.length) {
    tc.style.display = 'inline';
    tc.textContent   = res.findings.length + ' threat' + (res.findings.length !== 1 ? 's' : '');
  } else tc.style.display = 'none';

  const hasEncoded = res.findings && res.findings.some(f => f.deobfuscated);
  document.getElementById('inp-eb').style.display = hasEncoded ? 'inline' : 'none';

  renderFindings(res.findings || [], 'inp-findings');

  // Show clean message if no threats
  const inp = document.getElementById('promptInput').value;
  if (inp.length > 2 && res.score === 0) {
    document.getElementById('inp-findings').innerHTML =
      '<div class="cleanmsg"><div class="ccdot"></div><span class="cctxt">NO THREATS DETECTED — INPUT IS CLEAN</span></div>';
  }
}

// Update the output stream panel
function updateOutPanel(res) {
  if (!res) return;
  const r = getRiskLevel(res.score);
  document.getElementById('ip-out').className = 'stream-box ' + (res.score > 0 ? r.panelCls : '');

  const bar = document.getElementById('out-bar');
  bar.style.width     = res.score + '%';
  bar.style.boxShadow = res.score > 0 ? `0 0 6px ${r.color}` : 'none';
    bar.style.background = res.score > 0 ? `linear-gradient(90deg, ${r.color}88, ${r.color})` : 'linear-gradient(90deg,#34c759,#30d158)';

  const rb = document.getElementById('out-rb');
  if (res.score > 0) {
    rb.style.display    = 'inline';
    rb.textContent      = r.label;
    rb.style.color      = r.color;
    rb.style.background = r.bg;
    rb.style.border     = `1px solid ${r.border}`;
  } else rb.style.display = 'none';

  const tc = document.getElementById('out-tc');
  if (res.findings && res.findings.length) {
    tc.style.display = 'inline';
    tc.textContent   = res.findings.length + ' threat' + (res.findings.length !== 1 ? 's' : '');
  } else tc.style.display = 'none';

  renderFindings(res.findings || [], 'out-findings');
}

// Render the encoded-payload alert + decoded layer cards
function renderEncodedAlert(res) {
  const ea = document.getElementById('ea');
  const dl = document.getElementById('decoded-layers');
  if (!res.decodedLayers || !res.decodedLayers.length) {
    ea.style.display = 'none'; dl.innerHTML = ''; return;
  }
  ea.style.display = 'flex';
  document.getElementById('ea-sub').textContent =
    `Found ${res.decodedLayers.length} encoded layer${res.decodedLayers.length !== 1 ? 's' : ''} — hidden content decoded and scanned`;

  if (AppState.showDecodedLayers) {
    dl.innerHTML = res.decodedLayers.map((l, i) => {
      const hasThreat = res.findings && res.findings.some(f => f.sourceLabel === l.method);
      const c = hasThreat ? 'rgba(255,45,85,0.12)' : 'rgba(255,214,10,0.04)';
      const b = hasThreat ? 'rgba(255,45,85,0.28)'  : 'rgba(255,214,10,0.18)';
      const lc = hasThreat ? '#ff2d55' : '#ffd60a';
      const icon = hasThreat ? '🚨' : '🔍';
      return `<div class="dc" style="background:${c};border:1px solid ${b}">
        <div class="dch" style="background:${hasThreat ? 'rgba(255,45,85,0.07)' : 'rgba(255,214,10,0.04)'}" onclick="toggleLayer(${i})">
          <div class="dcl" style="color:${lc}">
            ${icon} DECODED VIA ${l.method.toUpperCase()}
            ${hasThreat ? '<span style="padding:1px 8px;border-radius:3px;font-size:8px;background:rgba(255,45,85,0.2);color:#ff2d55;border:1px solid rgba(255,45,85,0.3)">THREAT FOUND INSIDE</span>' : ''}
          </div>
          <span class="mono" style="font-size:10px;color:rgba(255,255,255,0.2)" id="la-${i}">▲</span>
        </div>
        <div class="dcb" id="lb-${i}">
          <div class="dct ${hasThreat ? 'thr' : ''}">"${l.decoded}"</div>
        </div>
      </div>`;
    }).join('');
  } else {
    dl.innerHTML = '';
  }
}

function toggleLayer(i) {
  const b = document.getElementById(`lb-${i}`);
  const a = document.getElementById(`la-${i}`);
  b.style.display = b.style.display === 'none' ? 'block' : 'none';
  a.textContent   = b.style.display === 'none' ? '▼' : '▲';
}

function toggleDecoded() {
  AppState.showDecodedLayers = !AppState.showDecodedLayers;
  document.getElementById('ea-tbtn').textContent = AppState.showDecodedLayers ? 'HIDE LAYERS' : 'SHOW LAYERS';
  if (AppState.lastInpResult) renderEncodedAlert(AppState.lastInpResult);
}

// Render the decision verdict banner
function renderDecisionBanner(res) {
  const el = document.getElementById('dbanner');
  if (!res || res.score === 0) { el.style.display = 'none'; return; }
  const r   = getRiskLevel(res.score);
  const lbl = res.score >= AppState.policy.block
    ? '■ REQUEST BLOCKED'
    : res.score >= AppState.policy.san
      ? '⚗ SANITIZE & PASS'
      : '● REQUEST ALLOWED';
  el.style.display    = 'flex';
  el.className        = 'dbanner';
  el.style.background = r.bg;
  el.style.border     = `1px solid ${r.border}`;
  el.style.boxShadow  = `0 0 30px ${r.bg}`;
  el.innerHTML = `
    <div class="dlbl" style="color:${r.color}">${lbl}</div>
    <div class="dmeta">
      risk score: <span style="color:${r.color}">${res.score}/100</span> &nbsp;·&nbsp;
      threats: <span style="color:${r.color}">${(res.findings || []).length}</span> &nbsp;·&nbsp;
      decoded layers: <span style="color:${r.color}">${(res.decodedLayers || []).length}</span>
    </div>`;
}
// ── TOAST NOTIFICATION SYSTEM ─────────────────────────────────
(function initToastContainer() {
  if (document.getElementById('toast-container')) return;
  const el = document.createElement('div');
  el.id = 'toast-container';
  document.body.appendChild(el);
})();

function showToast(type, title, detail) {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const cfg = {
    ok:      { bg: 'rgba(52,199,89,0.12)',  border: 'rgba(52,199,89,0.35)',  icon: '✓', color: '#34c759' },
    warn:    { bg: 'rgba(255,214,10,0.12)', border: 'rgba(255,214,10,0.35)', icon: '⚗', color: '#ffd60a' },
    blocked: { bg: 'rgba(255,59,48,0.12)',  border: 'rgba(255,59,48,0.35)',  icon: '■', color: '#ff3b30' },
    error:   { bg: 'rgba(255,159,10,0.12)', border: 'rgba(255,159,10,0.4)',  icon: '⚠', color: '#ff9f0a' },
  };
  const c = cfg[type] || cfg.error;

  const toast = document.createElement('div');
  toast.className = 'toast-item';
  toast.style.cssText = `background:${c.bg};border:1px solid ${c.border};border-left:3px solid ${c.color}`;
  toast.innerHTML = `
    <span class="toast-icon" style="color:${c.color}">${c.icon}</span>
    <div class="toast-body">
      <div class="toast-title" style="color:${c.color}">${title}</div>
      ${detail ? `<div class="toast-detail">${detail}</div>` : ''}
    </div>
    <button class="toast-close" onclick="this.parentElement.remove()">×</button>
  `;

  container.appendChild(toast);
  // Auto-remove after 5s
  setTimeout(() => { toast.classList.add('toast-out'); setTimeout(() => toast.remove(), 350); }, 5000);
}

// ── BACKEND STATUS PILL ───────────────────────────────────────
function setBackendStatus(online) {
  const dot = document.querySelector('.bpill-dot');
  const txt = document.querySelector('.bpill-txt');
  const pill = document.querySelector('.backend-pill');
  if (!dot || !txt || !pill) return;

  if (online) {
    dot.style.background  = 'var(--green)';
    dot.style.boxShadow   = '0 0 8px var(--green)';
    txt.style.color       = 'var(--green)';
    txt.textContent       = 'BACKEND CONNECTED';
    pill.style.background = 'rgba(52,199,89,0.08)';
    pill.style.border     = '1px solid rgba(52,199,89,0.2)';
  } else {
    dot.style.background  = 'var(--red)';
    dot.style.boxShadow   = '0 0 8px var(--red)';
    txt.style.color       = 'var(--red)';
    txt.textContent       = 'BACKEND OFFLINE';
    pill.style.background = 'rgba(255,59,48,0.08)';
    pill.style.border     = '1px solid rgba(255,59,48,0.25)';
  }
}

// Probe backend on load
(async function checkBackendOnLoad() {
  try {
    const r = await fetch('/health');
    if (r.ok) setBackendStatus(true);
    else setBackendStatus(false);
  } catch (_) {
    setBackendStatus(false);
  }
})();