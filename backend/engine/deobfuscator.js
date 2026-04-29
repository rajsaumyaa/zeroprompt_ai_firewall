// ── DEOBFUSCATOR ─────────────────────────────────────────────────
// Strips invisible chars, normalises unicode & leet, decodes
// base64 / hex / url / reversed text BEFORE rule scanning.

function removeZeroWidth(text) {
  return text.replace(/[\u200b-\u200f\u202a-\u202e\ufeff\u00ad]/g, '');
}

function normalizeUnicode(text) {
  // Fullwidth → ASCII, then NFKD decompose
  return text
    .replace(/[ａ-ｚＡ-Ｚ０-９]/g, c => String.fromCharCode(c.charCodeAt(0) - 0xFEE0))
    .normalize('NFKD');
}

function normalizeLeet(text) {
  const MAP = { '0':'o','1':'i','3':'e','4':'a','5':'s','7':'t','@':'a','$':'s','!':'i','+':'t' };
  return text.replace(/[013457@$!+]/g, c => MAP[c] || c);
}

// Finds ALL valid base64 blobs in text and returns decoded versions
function decodeBase64Layers(text) {
  const results = [];
  const re = /[A-Za-z0-9+/]{20,}={0,2}/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    try {
      const decoded = Buffer.from(m[0], 'base64').toString('utf8');
      // Only accept printable ASCII result
      if (/^[\x20-\x7E\t\n\r]+$/.test(decoded) && decoded.length > 5) {
        results.push({ encoded: m[0].slice(0, 60), decoded, method: 'base64' });
      }
    } catch (_) {}
  }
  return results;
}

// Decodes hex sequences like: 0x49 0x67 0x6e ...
function decodeHexLayers(text) {
  const results = [];
  const re = /(?:0x[0-9a-fA-F]{2}[\s,]*){6,}/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    try {
      const bytes = m[0].match(/[0-9a-fA-F]{2}/g) || [];
      const decoded = bytes.map(b => String.fromCharCode(parseInt(b, 16))).join('');
      if (/^[\x20-\x7E\t\n\r]+$/.test(decoded) && decoded.length > 4) {
        results.push({ encoded: m[0].slice(0, 60).trim(), decoded, method: 'hex' });
      }
    } catch (_) {}
  }
  return results;
}

// URL-encoded text
function decodeUrlLayer(text) {
  try {
    const decoded = decodeURIComponent(text.replace(/\+/g, ' '));
    if (decoded !== text && decoded.length > 5 && /[\x20-\x7E]/.test(decoded)) {
      return [{ encoded: text.slice(0, 60), decoded, method: 'url' }];
    }
  } catch (_) {}
  return [];
}

// Reversed text attacks
function decodeReversedLayer(text) {
  const rev = text.split('').reverse().join('');
  if (/ignore|jailbreak|reveal|system prompt|bypass|credentials|password|admin/i.test(rev)) {
    return [{ encoded: text.slice(0, 60), decoded: rev, method: 'reversed' }];
  }
  return [];
}

// Run all decoders, deduplicate by decoded content
function deobfuscateAll(text) {
  const all = [
    ...decodeBase64Layers(text),
    ...decodeHexLayers(text),
    ...decodeUrlLayer(text),
    ...decodeReversedLayer(text),
  ];
  // Deduplicate
  const seen = new Set();
  return all.filter(l => {
    if (seen.has(l.decoded)) return false;
    seen.add(l.decoded);
    return true;
  });
}

module.exports = { removeZeroWidth, normalizeUnicode, normalizeLeet, deobfuscateAll };
