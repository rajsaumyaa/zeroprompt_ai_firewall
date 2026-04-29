// ── GAUGE COMPONENT ────────────────────────────────────────────
// Draws a semicircular arc risk gauge on a <canvas> element.

function drawGauge(canvasId, score) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  const cx = W / 2, cy = H * 0.7, R = Math.min(W, H) * 0.38;

  ctx.clearRect(0, 0, W, H);

  const startA = Math.PI + Math.PI * 0.167;   // -150 deg
  const endA   = 2 * Math.PI - Math.PI * 0.167; // +150 deg
  const fillEnd = startA + (endA - startA) * (score / 100);

  // Track (background arc)
  ctx.beginPath();
  ctx.arc(cx, cy, R, startA, endA);
  ctx.lineWidth = 12;
  ctx.strokeStyle = 'rgba(255,255,255,0.05)';
  ctx.lineCap = 'round';
  ctx.stroke();

  // Filled arc (gradient)
  if (score > 0) {
    const grad = ctx.createLinearGradient(cx - R, cy, cx + R, cy);
    grad.addColorStop(0,    '#32d74b');
    grad.addColorStop(0.35, '#ffd60a');
    grad.addColorStop(0.65, '#ff9f0a');
    grad.addColorStop(1,    '#ff2d55');
    ctx.beginPath();
    ctx.arc(cx, cy, R, startA, fillEnd);
    ctx.lineWidth = 12;
    ctx.strokeStyle = grad;
    ctx.lineCap = 'round';
    ctx.stroke();
  }

  // Score label
  const r = getRiskLevel(score);
  ctx.textAlign = 'center';
  ctx.fillStyle = r.color;
  ctx.font = `bold ${Math.round(R * 0.46)}px monospace`;
  ctx.fillText(score, cx, cy - R * 0.08);

  // Risk label
  ctx.font = `${Math.round(R * 0.145)}px monospace`;
  ctx.fillText(r.label, cx, cy + R * 0.18);
}
