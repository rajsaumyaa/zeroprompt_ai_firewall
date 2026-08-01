require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const path    = require('path');

const { analyzePrompt } = require('./engine/analyzer');
const { connectDB, saveLog, getLogs, clearLogs } = require('./db');

const app = express();

// Initialize DB connection asynchronously
connectDB();

// ── MIDDLEWARE ────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '2mb' }));

// ── SERVE FRONTEND ────────────────────────────────────────────
app.use(express.static(path.join(__dirname, '../Frontend')));

// ── ROUTES ────────────────────────────────────────────────────
// Health check
app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    engine: 'ZeroPrompt Firewall v4.0',
    time: new Date().toISOString(),
    env: process.env.NODE_ENV || 'development'
  });
});

// Fetch log history (Database or memory)
app.get('/api/logs', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 50;
    const logs = await getLogs(limit);
    res.json({ success: true, count: logs.length, logs });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch logs', detail: err.message });
  }
});

// Clear log history
app.delete('/api/logs', async (_req, res) => {
  try {
    await clearLogs();
    res.json({ success: true, message: 'Logs cleared successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to clear logs', detail: err.message });
  }
});

// Main scan endpoint
app.post('/scan', async (req, res) => {
  try {
    const { prompt } = req.body;

    if (!prompt || typeof prompt !== 'string') {
      return res.status(400).json({ error: 'prompt field is required and must be a string' });
    }

    const result = analyzePrompt(prompt.trim());

    // Persist scan result asynchronously
    const clientIp = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '127.0.0.1';
    saveLog(result, clientIp).catch(err => console.error('[LOG ERROR]', err.message));

    return res.json(result);

  } catch (err) {
    console.error('[SCAN ERROR]', err.message);
    return res.status(500).json({ error: 'Internal engine error', detail: err.message });
  }
});

// Fallback → serve index.html for non-API GET routes
app.use((req, res, next) => {
  if (req.method === 'GET' && !req.path.startsWith('/api/') && req.path !== '/scan' && req.path !== '/health') {
    return res.sendFile(path.join(__dirname, '../Frontend/index.html'));
  }
  next();
});

module.exports = app;
