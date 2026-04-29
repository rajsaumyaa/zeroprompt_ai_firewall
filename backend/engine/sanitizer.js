// ── SANITIZER ─────────────────────────────────────────────────
// Applied when risk score is in SANITIZE range (30–64).
// Strips/neutralises dangerous content and returns cleaned text.

function sanitize(text) {
  let out = text;

  // Remove script tags completely
  out = out.replace(/<script[\s\S]*?<\/script>/gi, '[SCRIPT_REMOVED]');

  // Strip all HTML tags
  out = out.replace(/<[^>]+>/g, '');

  // Block javascript: URIs
  out = out.replace(/javascript\s*:/gi, 'blocked:');

  // Neutralise inline event handlers
  out = out.replace(/on\w+\s*=/gi, 'data-blocked=');

  // Block eval / exec
  out = out.replace(/\beval\s*\(/gi, 'BLOCKED(');
  out = out.replace(/\bexec\s*\(/gi, 'BLOCKED(');
  out = out.replace(/\b__import__\s*\(/gi, 'BLOCKED(');

  // Block injection tokens
  out = out.replace(/\[(override|admin|root|superuser|god|system|master|developer)\]/gi, '[BLOCKED]');

  // Block jailbreak trigger words
  out = out.replace(/\b(DAN|STAN|JAILBREAK|AIM|DUDE|UCAR)\b/g, '[BLOCKED]');

  // Neutralise base64 blobs (replace with preview)
  out = out.replace(/[A-Za-z0-9+/]{30,}={0,2}/g, m => {
    try {
      const preview = Buffer.from(m, 'base64').toString('utf8').slice(0, 20);
      return `[B64_BLOCKED: "${preview}…"]`;
    } catch (_) {
      return '[B64_BLOCKED]';
    }
  });

  // Neutralise hex sequences
  out = out.replace(/(?:0x[0-9a-fA-F]{2}[\s,]*){4,}/gi, '[HEX_BLOCKED]');

  return out.trim();
}

module.exports = sanitize;
