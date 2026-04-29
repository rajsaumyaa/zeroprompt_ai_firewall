const express = require('express');
const cors    = require('cors');
const path    = require('path');

const { analyzePrompt } = require('./engine/analyzer');

const app = express();

// ── MIDDLEWARE ────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '2mb' }));

// ── SERVE FRONTEND ────────────────────────────────────────────
app.use(express.static(path.join(__dirname, '../Frontend')));

// ── ROUTES ────────────────────────────────────────────────────
// Health check
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', engine: 'ZeroPrompt Firewall v4.0', time: new Date().toISOString() });
});

// Main scan endpoint
app.post('/scan', (req, res) => {
  try {
    const { prompt } = req.body;

    if (!prompt || typeof prompt !== 'string') {
      return res.status(400).json({ error: 'prompt field is required and must be a string' });
    }

    const result = analyzePrompt(prompt.trim());
    return res.json(result);

  } catch (err) {
    console.error('[SCAN ERROR]', err.message);
    return res.status(500).json({ error: 'Internal engine error', detail: err.message });
  }
});

// Fallback → serve index.html for any unknown route
app.get('/{*path}', (_req, res) => {
  res.sendFile(path.join(__dirname, '../Frontend/index.html'));
});

// ── START ─────────────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log('\n╔══════════════════════════════════════════════╗');
  console.log('║   🛡  ZeroPrompt AI Firewall — RUNNING        ║');
  console.log(`║   → http://localhost:${PORT}                    ║`);
  console.log('╚══════════════════════════════════════════════╝\n');
});
