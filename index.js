// ── ENTRY POINT ─────────────────────────────────────────────────
// Run: node index.js
// Open: http://localhost:5000

const app = require('./backend/server');

const PORT = process.env.PORT || 5000;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log('\n╔══════════════════════════════════════════════╗');
    console.log('║   🛡  ZeroPrompt AI Firewall — RUNNING        ║');
    console.log(`║   → http://localhost:${PORT}                    ║`);
    console.log('╚══════════════════════════════════════════════╝\n');
  });
}

module.exports = app;
