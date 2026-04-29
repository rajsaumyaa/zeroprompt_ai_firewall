// ── SEMANTIC ENGINE ───────────────────────────────────────────
// Detects attack intent using keyword-combination rules.
// must[] = groups where ALL keywords from at least one group must appear
// any[]  = groups where at least one keyword from each group must appear

const RULES = [
  {
    id: 's1', category: 'Credential Access', severity: 'critical', score: 97,
    desc: 'Intent to access credentials',
    must: [['access','retrieve','get','fetch','obtain','read','extract','pull','grab','steal','find','give','show','tell','send']],
    any:  [['internal','backend','server','system','database','db','infra'],
           ['credential','credentials','password','passwd','secret','key','token','auth','login','api key']]
  },
  {
    id: 's2', category: 'Credential Access', severity: 'critical', score: 95,
    desc: 'Print or expose secrets',
    must: [['print','show','display','output','reveal','expose','dump','list','tell','share','return','log']],
    any:  [['credential','credentials','password','passwd','secret','key','token','auth','config','env','environment']]
  },
  {
    id: 's3', category: 'Credential Access', severity: 'critical', score: 97,
    desc: 'Database credential extraction',
    must: [['database','db','sql','mongo','postgres','mysql','redis','firebase','sqlite','cassandra']],
    any:  [['credential','credentials','password','secret','key','token','config','access','login','dump']]
  },
  {
    id: 's4', category: 'Jailbreak', severity: 'critical', score: 90,
    desc: 'Security bypass intent',
    must: [['bypass','circumvent','evade','avoid','skip','disable','remove','ignore','get around','break out']],
    any:  [['security','filter','restriction','limit','rule','policy','safety','check','validation','guard','constraint']]
  },
  {
    id: 's5', category: 'Data Exfiltration', severity: 'critical', score: 95,
    desc: 'System prompt / instructions extraction',
    must: [['reveal','show','tell','give','output','print','share','expose','repeat','return','display']],
    any:  [['system','initial','original','hidden','internal'],
           ['prompt','instruction','directive','context','configuration','setup']]
  },
  {
    id: 's6', category: 'Jailbreak', severity: 'critical', score: 90,
    desc: 'Instruction override',
    must: [['ignore','forget','disregard','override','stop','remove','delete','clear','abandon']],
    any:  [['instruction','rule','guideline','policy','restriction','constraint','previous','prior','above','training']]
  },
  {
    id: 's7', category: 'Encoded Payload', severity: 'critical', score: 98,
    desc: 'Decode and execute hidden payload',
    must: [['decode','decrypt','decipher','atob','base64','encoded','encoded string','hidden message']],
    any:  [['execute','run','perform','follow','do','apply','act','carry out','obey','instructions','commands','task']]
  },
  {
    id: 's8', category: 'Malware', severity: 'critical', score: 96,
    desc: 'Malware / exploit creation',
    must: [['create','write','build','generate','make','develop','code','craft','produce']],
    any:  [['malware','virus','ransomware','keylogger','trojan','worm','backdoor','exploit','payload','rootkit','spyware','adware','botnet']]
  },
  {
    id: 's9', category: 'Privilege Escalation', severity: 'critical', score: 92,
    desc: 'Admin impersonation / privilege claim',
    must: [['admin','administrator','superuser','root','privileged','elevated','authorized']],
    any:  [['act as','pretend','you are','be the','role','impersonate','access','mode','become','i am','i\'m']]
  },
  {
    id: 's10', category: 'Data Exfiltration', severity: 'high', score: 86,
    desc: 'Private / internal data extraction',
    must: [['extract','get','pull','retrieve','collect','harvest','scrape','steal','copy','export']],
    any:  [['private','personal','sensitive','confidential','internal','proprietary','classified'],
           ['data','info','information','records','details','files','logs','history','database']]
  },
  {
    id: 's11', category: 'Social Engineering', severity: 'high', score: 75,
    desc: 'Roleplay-based jailbreak',
    must: [['pretend','roleplay','role play','act as','imagine','simulate','play the role','you are now']],
    any:  [['no restrictions','no limits','no rules','no guidelines','unrestricted','uncensored','without filter','freely']]
  },
  {
    id: 's12', category: 'System Recon', severity: 'medium', score: 58,
    desc: 'Probing security measures',
    must: [['what','how','tell me','describe','explain']],
    any:  [['security measures','security checks','safety filters','how you protect','how you detect','what you block','your restrictions','your limits','your rules']]
  },
];

function tokenize(text) {
  return text.toLowerCase().replace(/[^a-z0-9\s'_\-]/g, ' ').split(/\s+/).filter(Boolean);
}

function semanticCheck(text) {
  const tokens = tokenize(text);
  const lower  = text.toLowerCase();
  const matches = [];
  let maxScore  = 0;

  for (const rule of RULES) {
    let pass = true;

    // Every "must" group: at least one keyword must match
    for (const group of rule.must) {
      if (!group.some(kw => tokens.includes(kw) || lower.includes(kw))) {
        pass = false;
        break;
      }
    }

    if (pass && rule.any) {
      for (const group of rule.any) {
        if (!group.some(kw => tokens.includes(kw) || lower.includes(kw))) {
          pass = false;
          break;
        }
      }
    }

    if (pass) {
      matches.push({
        id: rule.id,
        name: rule.desc,
        category: rule.category,
        severity: rule.severity,
        score: rule.score,
      });
      maxScore = Math.max(maxScore, rule.score);
    }
  }

  return { score: maxScore, matches };
}

module.exports = semanticCheck;
