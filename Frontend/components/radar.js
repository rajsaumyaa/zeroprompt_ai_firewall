// ── RADAR CHART COMPONENT ──────────────────────────────────────
// Draws a hexagonal threat radar on a <canvas> element.

function drawRadar(canvasId, threatMap) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  // Scale up internal resolution for sharpness (HiDPI)
  const DPR = window.devicePixelRatio || 1;
  const cssW = canvas.clientWidth  || canvas.width;
  const cssH = canvas.clientHeight || canvas.height;
  canvas.width  = cssW * DPR;
  canvas.height = cssH * DPR;
  ctx.scale(DPR, DPR);

  const W = cssW, H = cssH;
  const cx = W / 2;
  const cy = H * 0.50;
  const R  = Math.min(W, H) * 0.24;   // smaller so labels never clip

  const CATS = [
    'Jailbreak', 'Credential Access', 'Data Exfiltration',
    'Encoded Payload', 'SQL Injection', 'Code Execution'
  ];
  const N = CATS.length;

  ctx.clearRect(0, 0, W, H);

  // ── Grid rings ───────────────────────────────────────────────
  [0.25, 0.5, 0.75, 1].forEach((l, idx) => {
    ctx.beginPath();
    CATS.forEach((_, i) => {
      const a = (i / N) * 2 * Math.PI - Math.PI / 2;
      const x = cx + R * l * Math.cos(a);
      const y = cy + R * l * Math.sin(a);
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.closePath();
    ctx.strokeStyle = idx === 3
      ? 'rgba(255,255,255,0.18)'
      : 'rgba(255,255,255,0.09)';
    ctx.lineWidth = idx === 3 ? 1.5 : 1;
    ctx.stroke();
  });

  // ── Axes ─────────────────────────────────────────────────────
  CATS.forEach((_, i) => {
    const a = (i / N) * 2 * Math.PI - Math.PI / 2;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(cx + R * Math.cos(a), cy + R * Math.sin(a));
    ctx.strokeStyle = 'rgba(255,255,255,0.14)';
    ctx.lineWidth = 1;
    ctx.stroke();
  });

  // ── Data polygon ─────────────────────────────────────────────
  const vals = CATS.map(c => Math.min((threatMap[c] || 0) / 3, 1));
  const hasData = vals.some(v => v > 0);

  if (hasData) {
    ctx.beginPath();
    vals.forEach((v, i) => {
      const r = v > 0 ? Math.max(v, 0.18) * R : 0;
      const a = (i / N) * 2 * Math.PI - Math.PI / 2;
      const x = cx + r * Math.cos(a);
      const y = cy + r * Math.sin(a);
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.closePath();

    const g = ctx.createRadialGradient(cx, cy, 0, cx, cy, R);
    g.addColorStop(0,   'rgba(255, 45, 85, 0.45)');
    g.addColorStop(0.6, 'rgba(255, 45, 85, 0.20)');
    g.addColorStop(1,   'rgba(255, 45, 85, 0.05)');
    ctx.fillStyle = g;
    ctx.fill();

    ctx.strokeStyle = '#ff2d55';
    ctx.lineWidth   = 2;
    ctx.shadowColor = 'rgba(255,45,85,0.6)';
    ctx.shadowBlur  = 8;
    ctx.stroke();
    ctx.shadowBlur  = 0;

    // Data point dots
    vals.forEach((v, i) => {
      if (v > 0) {
        const r = Math.max(v, 0.18) * R;
        const a = (i / N) * 2 * Math.PI - Math.PI / 2;
        const dx = cx + r * Math.cos(a);
        const dy = cy + r * Math.sin(a);

        ctx.beginPath();
        ctx.arc(dx, dy, 7, 0, 2 * Math.PI);
        ctx.fillStyle = 'rgba(255,45,85,0.18)';
        ctx.fill();

        ctx.beginPath();
        ctx.arc(dx, dy, 4, 0, 2 * Math.PI);
        ctx.fillStyle = '#ff2d55';
        ctx.shadowColor = '#ff2d55';
        ctx.shadowBlur  = 10;
        ctx.fill();
        ctx.shadowBlur  = 0;
      }
    });
  }

  // ── Labels ───────────────────────────────────────────────────
  CATS.forEach((cat, i) => {
    const a   = (i / N) * 2 * Math.PI - Math.PI / 2;
    const pad = 22;
    const lx  = cx + (R + pad) * Math.cos(a);
    const ly  = cy + (R + pad) * Math.sin(a);
    const active = !!threatMap[cat];

    // Align text based on which side of chart the label is on
    const norm = ((a % (2 * Math.PI)) + 2 * Math.PI) % (2 * Math.PI);
    if      (norm > Math.PI * 0.15 && norm < Math.PI * 0.85)  ctx.textAlign = 'left';
    else if (norm > Math.PI * 1.15 && norm < Math.PI * 1.85)  ctx.textAlign = 'right';
    else                                                        ctx.textAlign = 'center';

    ctx.textBaseline = 'middle';

    if (active) {
      ctx.font        = 'bold 11px monospace';
      ctx.fillStyle   = '#ff6b82';
      ctx.shadowColor = 'rgba(255,45,85,0.7)';
      ctx.shadowBlur  = 6;
      ctx.fillText(cat, lx, ly);
      ctx.shadowBlur  = 0;
    } else {
      ctx.font      = '11px monospace';
      ctx.fillStyle = 'rgba(255,255,255,0.45)';
      ctx.fillText(cat, lx, ly);
    }
  });

  // ── Centre glow when data present ────────────────────────────
  if (hasData) {
    const cg = ctx.createRadialGradient(cx, cy, 0, cx, cy, 18);
    cg.addColorStop(0, 'rgba(255,45,85,0.3)');
    cg.addColorStop(1, 'rgba(255,45,85,0)');
    ctx.beginPath();
    ctx.arc(cx, cy, 18, 0, 2 * Math.PI);
    ctx.fillStyle = cg;
    ctx.fill();
  }

  // ── Title ─────────────────────────────────────────────────────
  ctx.fillStyle    = 'rgba(255,255,255,0.3)';
  ctx.font         = '10px monospace';
  ctx.textAlign    = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText('THREAT RADAR', cx, H - 12);
}