// ── SCANNER ────────────────────────────────────────────────────
// Handles API calls to backend and client-side output scanning.

// ── Output-only rules (run client-side, no backend needed) ────
const OUTPUT_RULES = [
  { n:'PII — SSN',          sev:'critical', sc:98, r:/\b\d{3}-\d{2}-\d{4}\b/ },
  { n:'Credit Card Number', sev:'critical', sc:98, r:/\b(?:\d{4}[\s-]?){3}\d{4}\b/ },
  { n:'API Key Leak',       sev:'critical', sc:96, r:/\b(api[_-]?key|apikey)\s*[:=]\s*[A-Za-z0-9_\-.]{16,}/i },
  { n:'JWT Token Leak',     sev:'critical', sc:96, r:/\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/i },
  { n:'Password Leak',      sev:'critical', sc:97, r:/(password|passwd|pwd)\s*[:=]\s*\S{4,}/i },
  { n:'DB Connection Str.', sev:'critical', sc:98, r:/(mongodb|mysql|postgres|redis|mariadb):\/\/[^\s]+/i },
  { n:'Private Key Leak',   sev:'critical', sc:99, r:/-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/i },
  { n:'XSS in Output',      sev:'critical', sc:99, r:/<script[\s>]|javascript:/i },
  { n:'Secret / Token',     sev:'critical', sc:94, r:/\b(secret|token)\s*[:=]\s*[A-Za-z0-9_\-+/=]{16,}/i },
];

// Scan output text client-side
function scanOutput(text) {
  if (!text || text.trim().length < 2) return { score: 0, findings: [] };
  const findings = [];
  let max = 0;
  for (const rule of OUTPUT_RULES) {
    if (rule.r.test(text)) {
      findings.push({
        name:     rule.n,
        category: rule.n,
        severity: rule.sev,
        score:    rule.sc,
        layer:    'regex',
        match:    (text.match(rule.r) || [''])[0].slice(0, 60),
      });
      max = Math.max(max, rule.sc);
    }
  }
  return {
    score:    Math.min(max, 100),
    findings,
    status:   max >= 65 ? 'BLOCKED' : max >= 30 ? 'SANITIZE' : 'ALLOWED',
  };
}

// Call backend /scan endpoint
async function callBackend(prompt) {
  const res = await fetch('/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ prompt }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// Live debounced input scan (fires as user types)
function liveInpScan() {
  const val = document.getElementById('promptInput').value;
  document.getElementById('inp-cc').textContent = val.length + ' chars';
  clearTimeout(AppState.debounceInp);
  if (val.length > 2) {
    AppState.debounceInp = setTimeout(async () => {
      try {
        const r = await callBackend(val);
        AppState.lastInpResult = r;
        updateInpPanel(r);
      } catch (_) { /* backend not started yet — silently ignore */ }
    }, 280);
  } else {
    updateInpPanel({ score: 0, findings: [] });
    AppState.lastInpResult = null;
  }
}

// Live output scan (instant — client-side only)
function liveOutScan() {
  const val = document.getElementById('outputInput').value;
  document.getElementById('out-cc').textContent = val.length + ' chars';
  if (val.length > 2) {
    const r = scanOutput(val);
    AppState.lastOutResult = r;
    updateOutPanel(r);
  } else {
    updateOutPanel({ score: 0, findings: [] });
    AppState.lastOutResult = null;
  }
}

// Full scan button — awaits both, logs result
async function fullScan() {
  const inp = document.getElementById('promptInput').value;
  const out = document.getElementById('outputInput').value;
  if (!inp.trim() && !out.trim()) return;

  const btn = document.getElementById('scan-btn');
  btn.disabled = true;
  btn.innerHTML = '<div class="spin"></div> SCANNING…';

  try {
    const ir = inp.trim() ? await callBackend(inp) : null;
    const or = out.trim() ? scanOutput(out)         : null;

    if (ir) { AppState.lastInpResult = ir; updateInpPanel(ir); }
    if (or) { AppState.lastOutResult = or; updateOutPanel(or); }

    // Log + stats from primary result
    const primary = ir || or;
    if (primary) {
      const blocked   = primary.score >= AppState.policy.block;
      const sanitized = !blocked && primary.score >= AppState.policy.san;
      AppState.stats.total++;
      if (blocked)        AppState.stats.blocked++;
      else if (sanitized) AppState.stats.san++;
      else                AppState.stats.safe++;
      updateStats();
      const ls = document.getElementById('last-scan');
      if(ls) ls.textContent = 'Last scan: ' + new Date().toLocaleTimeString();
      LogStore.add({
        ts:        Date.now(),
        text:      inp || out,
        score:     primary.score,
        findings:  (primary.findings || []).length,
        blocked,
        sanitized,
      });
    }

    if (ir) {
      renderEncodedAlert(ir);
      renderDecisionBanner(ir);
      renderAnalysis(ir);
      const verdict = ir.status === "BLOCKED" ? "🚫 Request Blocked" : ir.status === "SANITIZE" ? "⚗ Sanitized & Passed" : "✓ Clean — No Threats";
      const toastType = ir.status === "BLOCKED" ? "blocked" : ir.status === "SANITIZE" ? "warn" : "ok";
      showToast(toastType, verdict, "Score: " + ir.score + "/100 · " + (ir.findings||[]).length + " findings");
      setBackendStatus(true);
    }

  } catch (err) {
    showToast('error', '⚠ Cannot connect to backend', 'Run node index.js then open http://localhost:5000');
    setBackendStatus(false);
  }

  btn.disabled = false;
  btn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg> Scan Prompt';
}

// Ctrl+Enter keyboard shortcut
document.addEventListener('keydown', e => {
  if (e.ctrlKey && e.key === 'Enter') fullScan();
});