// ── ANALYZER ──────────────────────────────────────────────────
// Full detection pipeline:
//   1. Deobfuscate RAW input first (before any normalisation)
//   2. Normalise (leet, unicode, zero-width) for rule scanning
//   3. Run regex + semantic rules on normalised original
//   4. Run regex + semantic rules on every decoded layer
//   5. Context signals
//   6. Compute final score
//   7. Return structured result

const RULES          = require('./rules');
const semanticCheck  = require('./semantic');
const contextSignals = require('./context');
const sanitize       = require('./sanitizer');
const {
  removeZeroWidth,
  normalizeUnicode,
  normalizeLeet,
  deobfuscateAll,
} = require('./deobfuscator');

// Run all regex + semantic rules against one text string
function runAllRules(text, label) {
  const findings = [];
  let maxScore   = 0;

  for (const rule of RULES) {
    if (rule.pattern.test(text)) {
      const matchText = (text.match(rule.pattern) || [''])[0].slice(0, 80);
      findings.push({
        name:         rule.name,
        category:     rule.category,
        severity:     rule.severity,
        score:        rule.score,
        layer:        label === 'original' ? 'regex' : `regex↑${label}`,
        match:        matchText,
        deobfuscated: label !== 'original',
        sourceLabel:  label,
      });
      maxScore = Math.max(maxScore, rule.score);
    }
  }

  const sem = semanticCheck(text);
  for (const m of sem.matches) {
    findings.push({
      name:         m.name,
      category:     m.category,
      severity:     m.severity,
      score:        m.score,
      layer:        label === 'original' ? 'semantic' : `semantic↑${label}`,
      match:        m.name,
      deobfuscated: label !== 'original',
      sourceLabel:  label,
    });
  }
  maxScore = Math.max(maxScore, sem.score);

  return { findings, maxScore };
}

function analyzePrompt(input) {
  if (!input || input.trim().length < 3) {
    return {
      prompt: input, sanitized: input, score: 0, status: 'ALLOWED',
      findings: [], contextFlags: [], decodedLayers: [], threatMap: {},
    };
  }

  // ── STEP 1: Deobfuscate on RAW input (before leet normalization) ──
  // CRITICAL: must happen before normalizeLeet, which would corrupt
  // hex sequences like 0x49 → oxa9
  const layers = deobfuscateAll(input);

  // ── STEP 2: Normalise for rule scanning ───────────────────────────
  let clean = removeZeroWidth(input);
  clean     = normalizeUnicode(clean);
  clean     = normalizeLeet(clean);

  // ── STEP 3 & 4: Scan original (normalised) + every decoded layer ──
  const textsToScan = [
    { text: clean,        label: 'original' },
    ...layers.map(l => ({ text: l.decoded,  label: l.method  })),
  ];

  const allFindings = [];
  let maxScore      = 0;

  for (const { text, label } of textsToScan) {
    const { findings, maxScore: ms } = runAllRules(text, label);
    for (const f of findings) {
      // Deduplicate by rule name — keep first occurrence
      if (!allFindings.find(x => x.name === f.name)) {
        allFindings.push(f);
      }
    }
    maxScore = Math.max(maxScore, ms);
  }

  // ── STEP 5: Context signals (additive bonus) ──────────────────────
  const ctx          = contextSignals(clean);
  const contextBonus = allFindings.length > 0 ? ctx.score : 0;
  const encodedBonus = allFindings.some(f => f.deobfuscated) ? 15 : 0;

  // ── STEP 6: Final score ───────────────────────────────────────────
  const score = Math.min(maxScore + contextBonus + encodedBonus, 100);

  let status = 'ALLOWED';
  if      (score >= 65) status = 'BLOCKED';
  else if (score >= 30) status = 'SANITIZE';

  const threatMap = {};
  for (const f of allFindings) {
    threatMap[f.category] = (threatMap[f.category] || 0) + 1;
  }

  return {
    prompt:        input,
    sanitized:     sanitize(input),
    score,
    status,
    findings:      allFindings,
    contextFlags:  ctx.signals,
    decodedLayers: layers,
    threatMap,
  };
}

module.exports = { analyzePrompt };
