// ── LOGS COMPONENT ────────────────────────────────────────────
// Renders and manages the security event log.

const LogStore = {
  entries: [],
  MAX: 200,

  add(entry) {
    this.entries.unshift(entry);
    if (this.entries.length > this.MAX) this.entries.pop();
    this.render();
    document.getElementById('log-cnt').textContent = this.entries.length + ' events';
  },

  clear() {
    this.entries = [];
    this.render();
    document.getElementById('log-cnt').textContent = '0 events';
  },

  render() {
    const el = document.getElementById('log-rows');
    if (!this.entries.length) {
      el.innerHTML = '<div style="padding:50px;text-align:center;color:rgba(255,255,255,0.1);font-family:monospace;font-size:11px">No events — run scans to populate log</div>';
      return;
    }
    el.innerHTML = this.entries.map(e => {
      const r   = getRiskLevel(e.score);
      const act = e.blocked
        ? { lbl: '■ BLOCKED',  c: '#ff2d55' }
        : e.sanitized
          ? { lbl: '⚗ SANITIZE', c: '#ffd60a' }
          : { lbl: '● ALLOWED',  c: '#32d74b' };
      const t = new Date(e.ts).toLocaleTimeString([], { hour12: false });
      return `<div class="lrow">
        <span class="lt">${t}</span>
        <span class="rbadge" style="display:inline;color:${r.color};background:${r.bg};border:1px solid ${r.border};text-align:center">${r.label}</span>
        <span class="mono" style="font-size:9px;font-weight:700;color:${act.c};letter-spacing:1px">${act.lbl}</span>
        <span class="lp">${e.text.slice(0, 70)}${e.text.length > 70 ? '…' : ''}</span>
        <span class="lth">${e.findings} threats</span>
      </div>`;
    }).join('');
  }
};
