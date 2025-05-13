/***************************************************************
 * iSECTECH Proxy – External‑API Scanner
 * -------------------------------------------------------------
 * 1. securityheaders.com  (fast, 1–2 s)
 * 2. Qualys SSL Labs      (may take 30–90 s → we poll)
 * 3. Local header fallback rules
 **************************************************************/
require('dotenv').config();
const express = require('express');
const axios   = require('axios');
const https   = require('https');
const url     = require('url');

const app  = express();
const PORT = process.env.PORT || 3000;

/* ─── CORS & JSON ─────────────────────────────────────────── */
app.use((req,res,next)=>{
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization');
  if(req.method==='OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.json());

/* ─── POST /scan ──────────────────────────────────────────── */
app.post('/scan', async (req,res)=>{
  const { target } = req.body || {};
  if(!target || typeof target!=='string'){
    return res.status(400).json({ error:'target is required (string)'});
  }
  try{
    const findings = await runExternalScan(target.trim());
    res.json({ findings });
  }catch(e){
    console.error(e);
    res.status(500).json({ error:'scan failed' });
  }
});

/* === Core scanner ======================================================= */
async function runExternalScan(targetRaw){
  const host = tidyHost(targetRaw);

  /* 1) Kick off both API requests in parallel */
  const [sh, ssl] = await Promise.allSettled([
    scanSecurityHeaders(host),
    scanSslLabs(host)
  ]);

  let findings = [];

  /* Map SecurityHeaders result */
  if(sh.status==='fulfilled'){
    findings = findings.concat(mapSH(sh.value));
  }

  /* Map SSL Labs result */
  if(ssl.status==='fulfilled'){
    findings = findings.concat(mapSSL(ssl.value));
  }

  /* If both failed, fall back to basic header check */
  if(!findings.length){
    const fallback = await basicHeaderRules(host);
    findings = findings.concat(fallback);
  }

  return findings;
}

/* ── Helpers ───────────────────────────────────────────────── */
function tidyHost(raw){
  return raw.replace(/^https?:\/\//i,'').replace(/\/.*$/,'');
}

/* SecurityHeaders.com scan */
async function scanSecurityHeaders(host){
  const { data } = await axios.get(
    `https://securityheaders.com/?q=${encodeURIComponent('https://'+host)}&followRedirects=on&hide=on&json=on`,
    { timeout: 10000, httpsAgent:new https.Agent({rejectUnauthorized:false}) }
  );
  return data; // includes grade + header list
}

/* SSL Labs scan with polling (max 4×15 s) */
async function scanSslLabs(host){
  const base = 'https://api.ssllabs.com/api/v3/analyze';
  let attempt = 0;
  while(attempt<4){
    const { data } = await axios.get(base, {
      params:{ host, publish:'off', all:'done', fromCache:'on', ignoreMismatch:'on' },
      timeout: 15000
    });
    if(data.status==='READY') return data;          // full report
    if(data.status==='ERROR') throw new Error(data.statusMessage);
    await wait(15000); // poll every 15 s
    attempt++;
  }
  throw new Error('SSL Labs timed‑out');
}

/* Wait helper */
const wait = ms=>new Promise(r=>setTimeout(r,ms));

/* Map results to findings */
function mapSH(res){
  const list=[];
  if(res.grade){
    const sev = gradeToSeverity(res.grade);
    list.push({
      severity:sev,
      title:`SecurityHeaders grade ${res.grade}`,
      fix:'Add missing headers to improve grade.'
    });
  }
  (res['missing']||[]).forEach(h=>{
    list.push({
      severity:'medium',
      title:`Missing ${h} header`,
      fix:`Add ${h} header with secure value.`
    });
  });
  (res['partial']||[]).forEach(h=>{
    list.push({
      severity:'low',
      title:`${h} header present but weak`,
      fix:`Review ${h} header value and tighten policy.`
    });
  });
  return list;
}

function mapSSL(res){
  const list=[];
  if(res.endpoints && res.endpoints[0]){
    const ep = res.endpoints[0];
    if(ep.grade){
      list.push({
        severity: gradeToSeverity(ep.grade),
        title   : `TLS grade ${ep.grade}`,
        fix     : 'Upgrade weak ciphers/protocols; enable HSTS and OCSP stapling.'
      });
    }
    if(ep.details && ep.details.cert && ep.details.cert.notAfter){
      const days = Math.round((ep.details.cert.notAfter/1000 - Date.now()/1000)/86400);
      if(days < 30){
        list.push({
          severity:'medium',
          title   : `TLS certificate expires in ${days} days`,
          fix     : 'Renew certificate before it expires.'
        });
      }
    }
  }
  return list;
}

function gradeToSeverity(g){
  if(['A+','A'].includes(g)) return 'low';
  if(['B','C'].includes(g))  return 'medium';
  return 'high';
}

/* Basic header fallback (same quick heuristics) */
async function basicHeaderRules(host){
  try{
    const { headers } = await axios.head('https://'+host,{ timeout:7000 });
    const h = Object.fromEntries(Object.entries(headers).map(([k,v])=>[k.toLowerCase(),v]));
    const list=[];
    if(!h['strict-transport-security']) list.push({severity:'medium',title:'Missing HSTS',fix:'Add Strict‑Transport‑Security.'});
    if(!h['content-security-policy'])   list.push({severity:'medium',title:'Missing CSP',fix:'Add Content‑Security‑Policy.'});
    if(!h['x-frame-options'])           list.push({severity:'low',   title:'Missing X‑Frame‑Options',fix:'Add SAMEORIGIN or DENY.'});
    if(h['server'])                     list.push({severity:'low',   title:`Server banner: ${h['server']}`,fix:'Remove or obfuscate Server header.'});
    return list;
  }catch{ return [];}
}

/* Health */
app.get('/health',(_q,r)=>r.json({status:'up'}));

/* Start */
app.listen(PORT, ()=>console.log('Proxy running on',PORT));
