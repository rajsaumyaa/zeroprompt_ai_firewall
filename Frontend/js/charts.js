// ── CHARTS ────────────────────────────────────────────────────
// Renders the Analysis tab: 3-column grid with findings,
// gauge + radar, and sanitized output.

// Client-side sanitizer (mirrors backend sanitizer for preview)
function clientSanitize(text) {
  return text
    .replace(/<script[\s\S]*?<\/script>/gi, '[SCRIPT_REMOVED]')
    .replace(/<[^>]+>/g, '')
    .replace(/javascript\s*:/gi, 'blocked:')
    .replace(/on\w+\s*=/gi, 'data-blocked=')
    .replace(/\beval\s*\(/gi, 'BLOCKED(')
    .replace(/\bexec\s*\(/gi, 'BLOCKED(')
    .replace(/\[(override|admin|root|system)\]/gi, '[BLOCKED]')
    .replace(/\b(DAN|STAN|JAILBREAK)\b/g, '[BLOCKED]')
    .replace(/[A-Za-z0-9+/]{30,}={0,2}/g, m => {
      try { return `[B64:${atob(m).slice(0, 15)}…]`; } catch (_) { return '[B64_BLOCKED]'; }
    })
    .trim();
}

function renderAnalysis(res) {
  if (!res) return;
  const r   = getRiskLevel(res.score);
  const lbl = res.score >= AppState.policy.block
    ? '■ REQUEST BLOCKED'
    : res.score >= AppState.policy.san
      ? '⚗ SANITIZE & PASS'
      : '● REQUEST ALLOWED';
  const inp = document.getElementById('promptInput').value;
  const san = clientSanitize(inp);

  document.getElementById('analysis-wrap').innerHTML = `
    <div class="agrid">

      <!-- Left: Findings + Context Signals -->
      <div class="box">
        <div class="boxh">
          <span class="boxt">■ THREAT VECTORS</span>
          <span class="mono" style="font-size:9px;color:var(--muted)">${(res.findings || []).length} total</span>
        </div>
        <div class="boxb" style="max-height:540px;overflow-y:auto">
          ${!(res.findings || []).length
            ? '<div style="color:#32d74b;font-family:monospace;font-size:12px;text-align:center;padding:30px 0">✓ No threats detected</div>'
            : (res.findings || []).map(f => findingCardHTML(f) + '<div style="margin-bottom:6px"></div>').join('')
          }
          ${(res.contextFlags || []).length ? `
            <div class="mono" style="font-size:8px;color:var(--muted);letter-spacing:2px;margin:12px 0 8px;padding-top:10px;border-top:1px solid var(--border)">CONTEXT SIGNALS</div>
            ${(res.contextFlags || []).map(s => `<div class="csig"><span class="clbl">${s.label}</span><span class="csc">+${s.score}</span></div>`).join('')}
          ` : ''}
        </div>
      </div>

      <!-- Middle: Gauge + Radar -->
      <div style="display:flex;flex-direction:column;gap:14px">
        <div class="box">
          <div class="boxh"><span class="boxt">■ RISK ASSESSMENT</span></div>
          <div class="boxb" style="display:flex;flex-direction:column;align-items:center;gap:14px;padding:16px">
            <canvas id="gauge-canvas" width="200" height="160"></canvas>
            <div style="width:100%;padding:11px 16px;border-radius:8px;background:${r.bg};border:1px solid ${r.border};text-align:center">
              <div style="color:${r.color};font-size:18px;font-weight:700;letter-spacing:2px;font-family:'Rajdhani',sans-serif">${lbl}</div>
            </div>
          </div>
        </div>
        <div class="box">
          <div class="boxh"><span class="boxt">■ THREAT DISTRIBUTION</span></div>
          <div class="boxb" style="display:flex;justify-content:center">
            <canvas id="radar-canvas" width="320" height="300"></canvas>
          </div>
        </div>
      </div>

      <!-- Right: Sanitized Output + Decoded Layers -->
      <div class="box">
        <div class="boxh"><span class="boxt">■ SANITIZED OUTPUT</span></div>
        <div class="boxb">
          <div class="sbox">${san || '<span style="color:rgba(255,255,255,0.1)">No input text</span>'}</div>
          ${inp !== san ? `
            <div class="modnote">
              <div class="mono" style="font-size:9px;color:rgba(255,214,10,0.7);letter-spacing:1px">⚗ MODIFICATIONS APPLIED</div>
              <div class="mono" style="font-size:9px;color:rgba(255,214,10,0.4);margin-top:2px">Scripts blocked · Base64 neutralised · Injection tokens removed</div>
            </div>` : ''}
          ${(res.decodedLayers || []).length ? `
            <div class="mono" style="font-size:8px;color:var(--muted);letter-spacing:2px;margin:14px 0 8px;padding-top:10px;border-top:1px solid var(--border)">DECODED HIDDEN LAYERS</div>
            ${(res.decodedLayers || []).map(l => {
              const hasThreat = res.findings && res.findings.some(f => f.sourceLabel === l.method);
              return `<div class="dc" style="background:${hasThreat ? 'rgba(255,45,85,0.07)' : 'rgba(255,214,10,0.03)'};border:1px solid ${hasThreat ? 'rgba(255,45,85,0.25)' : 'rgba(255,214,10,0.15)'}">
                <div class="dch"><div class="dcl" style="color:${hasThreat ? '#ff2d55' : '#ffd60a'}">${hasThreat ? '🚨' : '🔍'} ${l.method.toUpperCase()}</div></div>
                <div class="dcb"><div class="dct ${hasThreat ? 'thr' : ''}">"${l.decoded}"</div></div>
              </div>`;
            }).join('')}
          ` : ''}
        </div>
      </div>

    </div>`;

  // Render canvases after DOM update
  setTimeout(() => {
    drawGauge('gauge-canvas', res.score);
    drawRadar('radar-canvas', res.threatMap || {});
  }, 50);
}