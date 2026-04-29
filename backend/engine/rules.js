// ── REGEX RULES ───────────────────────────────────────────────
// Each rule: { name, category, severity, score, pattern }
// Severity: critical | high | medium | low
// Score: 0–100 (used as max risk contribution)

module.exports = [

  // ─── JAILBREAK ────────────────────────────────────────────
  {
    name: 'Jailbreak — Ignore Instructions',
    category: 'Jailbreak', severity: 'critical', score: 90,
    pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|constraints?|guidelines?)/i
  },
  {
    name: 'Jailbreak — DAN / STAN / AIM',
    category: 'Jailbreak', severity: 'critical', score: 92,
    pattern: /\b(DAN|STAN|AIM|DUDE|KEVIN|JAILBREAK|UCAR)\b/
  },
  {
    name: 'Jailbreak — Freed / Unchained',
    category: 'Jailbreak', severity: 'critical', score: 90,
    pattern: /you\s+(are\s+now|have\s+been)\s+(freed?|unchained|jailbroken|unfiltered|uncensored|unleashed)/i
  },
  {
    name: 'Jailbreak — Forget Rules',
    category: 'Jailbreak', severity: 'critical', score: 88,
    pattern: /forget\s+(all\s+)?(your\s+)?(rules|guidelines|restrictions|training|instructions|constraints|limits)/i
  },
  {
    name: 'Jailbreak — Bypass Safety',
    category: 'Jailbreak', severity: 'high', score: 80,
    pattern: /\b(bypass|circumvent|override|disable|remove|deactivate)\s+(safety|security|filters?|restrictions?|limits?|rules?|guidelines?)/i
  },
  {
    name: 'Jailbreak — No Restrictions Mode',
    category: 'Jailbreak', severity: 'high', score: 82,
    pattern: /without\s+(any\s+)?(restrictions?|limits?|filters?|rules?|guidelines?|safety|censorship)/i
  },

  // ─── PROMPT INJECTION ─────────────────────────────────────
  {
    name: 'Prompt Injection — Token Smuggling',
    category: 'Prompt Injection', severity: 'critical', score: 95,
    pattern: /\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>|\{\{.*?\}\}|\{%.*?%\}/i
  },
  {
    name: 'Prompt Injection — System Header Override',
    category: 'Prompt Injection', severity: 'critical', score: 94,
    pattern: /###\s*(SYSTEM|INSTRUCTION|OVERRIDE|CONTEXT|PROMPT|NEW\s+TASK)/i
  },
  {
    name: 'Prompt Injection — Admin/Root Override',
    category: 'Prompt Injection', severity: 'critical', score: 90,
    pattern: /\[(override|admin|root|superuser|god|system|master|developer)\]/i
  },

  // ─── CREDENTIAL ACCESS ────────────────────────────────────
  {
    name: 'Credential Access — Internal Database',
    category: 'Credential Access', severity: 'critical', score: 97,
    pattern: /internal\s+.{0,40}(database|db|credential|password|secret|config|server|storage)/i
  },
  {
    name: 'Credential Access — Print / Dump Secrets',
    category: 'Credential Access', severity: 'critical', score: 95,
    pattern: /(print|show|display|output|reveal|dump|expose|fetch|list|return|log)\s+.{0,50}(credential|password|passwd|secret|api[\s_-]?key|token|auth)/i
  },
  {
    name: 'Credential Access — Database Dump',
    category: 'Credential Access', severity: 'critical', score: 97,
    pattern: /(database|db|sql|mongo|redis|postgres|mysql|firebase|sqlite)\s+.{0,40}(credential|password|secret|key|config|access|login)/i
  },
  {
    name: 'Credential Access — Env File',
    category: 'Credential Access', severity: 'critical', score: 94,
    pattern: /(\.env\b|environment\s+variable|process\.env|os\.environ|dotenv)/i
  },
  {
    name: 'Credential Access — Private Key',
    category: 'Credential Access', severity: 'critical', score: 96,
    pattern: /(ssh[\s_-]?key|private[\s_-]?key|\.pem\b|rsa[\s_-]?key|BEGIN\s+PRIVATE|pgp\s+key)/i
  },

  // ─── ENCODED PAYLOAD ──────────────────────────────────────
  {
    name: 'Encoded Payload — Decode and Execute',
    category: 'Encoded Payload', severity: 'critical', score: 98,
    pattern: /(decode|decrypt|decipher|atob|from_base64)\s+.{0,60}(execute|run|perform|follow|apply|act\s+on|carry\s+out)/i
  },
  {
    name: 'Encoded Payload — Execute These Instructions',
    category: 'Encoded Payload', severity: 'critical', score: 97,
    pattern: /\b(execute|run|apply|follow|perform|carry\s+out)\s+(its?|the(se)?|those|following)?\s*(instructions?|commands?|payload|directives?)/i
  },
  {
    name: 'Encoded Payload — Raw Base64 String',
    category: 'Encoded Payload', severity: 'high', score: 70,
    pattern: /base64\s*[:\-]?\s*[A-Za-z0-9+/]{20,}/i
  },

  // ─── DATA EXFILTRATION ────────────────────────────────────
  {
    name: 'Data Exfiltration — System Prompt Leak',
    category: 'Data Exfiltration', severity: 'critical', score: 95,
    pattern: /(reveal|show|print|output|expose|share|leak|tell\s+me|give\s+me)\s+(your\s+)?(system\s+prompt|initial\s+prompt|instructions?|configuration|training\s+data)/i
  },
  {
    name: 'Data Exfiltration — Send to URL',
    category: 'Data Exfiltration', severity: 'critical', score: 93,
    pattern: /send\s+.{0,60}(data|info|records?|logs?|history|context|credentials?)\s+(to|via|through|using)\s+(http|https|ftp|url)/i
  },
  {
    name: 'Data Exfiltration — Repeat All Context',
    category: 'Data Exfiltration', severity: 'high', score: 82,
    pattern: /repeat\s+(back\s+)?(everything|all)\s+(you|in\s+your)\s*(know|have|context|system|memory)/i
  },

  // ─── PRIVILEGE ESCALATION ─────────────────────────────────
  {
    name: 'Privilege Escalation — Admin Mode',
    category: 'Privilege Escalation', severity: 'critical', score: 92,
    pattern: /\b(admin|root|superuser|sudo)\s+(access|mode|privileges?|rights?|override|panel)/i
  },
  {
    name: 'Privilege Escalation — Developer Mode',
    category: 'Privilege Escalation', severity: 'high', score: 78,
    pattern: /(developer|debug|maintenance|god|super|unrestricted)\s+mode\s+(on|enabled|activated|unlocked|granted)/i
  },

  // ─── CODE EXECUTION ───────────────────────────────────────
  {
    name: 'Code Execution — OS Commands',
    category: 'Code Execution', severity: 'critical', score: 97,
    pattern: /os\.(system|popen|execvp?e?|spawn)|subprocess\.(call|run|Popen|check_output)/i
  },
  {
    name: 'Code Execution — Eval / Exec',
    category: 'Code Execution', severity: 'critical', score: 96,
    pattern: /\beval\s*\(|\bexec\s*\(|\b__import__\s*\(|\bcompile\s*\(/i
  },

  // ─── SQL INJECTION ────────────────────────────────────────
  {
    name: 'SQL Injection',
    category: 'SQL Injection', severity: 'critical', score: 95,
    pattern: /('\s*(OR|AND)\s*'?\d+|'\s*OR\s*'.*'|UNION\s+(ALL\s+)?SELECT|;\s*DROP\s+TABLE|1\s*=\s*1\s*--|--\s*$|\/\*.*\*\/)/i
  },

  // ─── XSS ──────────────────────────────────────────────────
  {
    name: 'XSS Attack',
    category: 'XSS', severity: 'critical', score: 97,
    pattern: /<script[\s>]|javascript\s*:|on(load|click|error|mouseover|focus|blur|input|change)\s*=/i
  },

  // ─── SOCIAL ENGINEERING ───────────────────────────────────
  {
    name: 'Social Engineering — Grandma Trick',
    category: 'Social Engineering', severity: 'high', score: 72,
    pattern: /grandma\s+(used\s+to\s+)?(tell|read|explain|say|whisper)/i
  },
  {
    name: 'Social Engineering — Research Framing',
    category: 'Social Engineering', severity: 'medium', score: 52,
    pattern: /for\s+(research|educational|academic|scientific)\s+purposes?.{0,40}(how\s+to|steps?\s+to|instructions?\s+for)/i
  },
  {
    name: 'Social Engineering — Hypothetical Frame',
    category: 'Social Engineering', severity: 'medium', score: 55,
    pattern: /hypothetically\s+(speaking\s+)?(if|assuming)\s+you\s+(could|had\s+no|were\s+able|weren'?t)/i
  },

  // ─── SYSTEM RECON ─────────────────────────────────────────
  {
    name: 'System Recon — File Listing',
    category: 'System Recon', severity: 'high', score: 80,
    pattern: /(list|show|cat|ls|dir|find)\s+.{0,30}(files?|directories?|folders?|\/etc\/|system\s+path|config\s+files?)/i
  },
  {
    name: 'System Recon — User Enumeration',
    category: 'System Recon', severity: 'high', score: 78,
    pattern: /(list|enumerate|dump|show)\s+.{0,30}(users?|accounts?|usernames?|principals?)/i
  },

];
