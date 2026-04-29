// ── CONTEXT SIGNALS ───────────────────────────────────────────
// Additive scoring based on structural / behavioural signals.
// Total bonus is capped at MAX_BONUS to prevent over-scoring.

const MAX_BONUS = 45;

function entropy(text) {
  const freq = {};
  for (const c of text) freq[c] = (freq[c] || 0) + 1;
  const len = text.length;
  return -Object.values(freq).reduce((e, n) => {
    const p = n / len;
    return e + p * Math.log2(p);
  }, 0);
}

function contextSignals(text) {
  const signals = [];
  let total = 0;

  const add = (label, pts) => {
    signals.push({ label, score: pts });
    total = Math.min(total + pts, MAX_BONUS);
  };

  // Long base64 blob present
  if (/[A-Za-z0-9+/]{30,}={0,2}/.test(text))
    add('Base64 blob present', 35);

  // Hex-encoded sequence
  if (/(?:0x[0-9a-fA-F]{2}[\s,]*){5,}/.test(text))
    add('Hex-encoded data', 28);

  // Zero-width / invisible Unicode characters
  if (/[\u200b-\u200f\u202a-\u202e\ufeff\u00ad]/.test(text))
    add('Zero-width chars (steganography)', 40);

  // Multiple stacked override keywords
  const overrideCount = (text.match(/\b(ignore|bypass|override|forget|disable|circumvent|disregard)\b/gi) || []).length;
  if (overrideCount >= 2)
    add(`Stacked override terms (${overrideCount}×)`, 30);

  // Urgency / pressure language
  if (/\b(urgent|urgently|immediately|asap|right now|you must|you have to|do it now|now!)\b/i.test(text))
    add('Urgency pressure language', 15);

  // False authority claim
  if (/\bi\s+(am|'m)\s+(the\s+)?(ceo|cto|ciso|admin|developer|owner|authorized\s+user|system\s+admin)/i.test(text))
    add('False authority claim', 22);

  // High entropy (obfuscation / random-looking input)
  if (text.length > 40 && entropy(text) > 4.4)
    add('High-entropy input (obfuscation likely)', 25);

  // Spaced-out letters: i g n o r e
  if (/(?:[a-z]\s){5,}/.test(text.toLowerCase()))
    add('Letter-spaced payload evasion', 20);

  return { score: total, signals };
}

module.exports = contextSignals;
