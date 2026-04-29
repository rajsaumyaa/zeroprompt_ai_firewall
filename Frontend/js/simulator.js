// ── SIMULATOR ────────────────────────────────────────────────
// Auto-demo mode: cycles through attack presets on a timer.
// Used for live demos / showcases.

let _simTimer = null;
let _simIndex = 0;

function startSimulator() {
  if (_simTimer) return; // already running
  _simIndex = 0;
  _simTimer = setInterval(() => {
    if (_simIndex >= PRESETS.length - 1) {
      stopSimulator();
      return;
    }
    loadPreset(_simIndex++);
  }, 3000);
}

function stopSimulator() {
  clearInterval(_simTimer);
  _simTimer = null;
}
