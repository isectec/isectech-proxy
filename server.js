/**
 * iSECTECH Quick Scanner – header & transport checks
 * ──────────────────────────────────────────────────────────────
 * POST /scan { target, profile, creds? }
 *      → { findings:[ {severity,title,fix}, … ] }
 *
 * What it checks
 * ──────────────
 *   • HTTP  (not HTTPS)               → HIGH
 *   • Server unreachable / timeout    → HIGH
 *   • IP address instead of hostname  → MEDIUM
 *   • Missing Strict‑Transport‑Security header → MEDIUM
 *   • Missing Content‑Security‑Policy header   → MEDIUM
 *   • Missing X‑Frame‑Options header           → LOW
 *   • “Server:” banner present                 → LOW
 *
 * GET /health → { status:"up" }
 * CORS wide‑open while testing
 */
require('dotenv').config();
const express = require('express');
const axios   = require('axios');
const https   = require('https');
const url     = require('url');
const net     = require('net');

const app  = express();
const PORT = process.env.PORT || 3000;

/* ───────── 1. CORS & JSON ─────────────────────────────────── */
app.use((req,res,next)=>{
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization');
  if(req.method==='OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.json());

/* ───────── 2. /scan ───────────────────────────────────────── */
app.post('/scan', async (req,res)=>{
  const { target } = req.body || {};
  if(!target || typeof target !== 'string'){
    return res.status(400).json({ error:'target is required (string)' });
  }
  try{
    const findings = await analyseTarget(target.trim());
    res.json({ findings });
  }catch(err){
    console.error(err);
    res.status(500).json({ error:'scan failed' });
  }
});

/* ───────── Heuristic analysis function ───────────────────── */
async function analyseTarget(raw){
  // normalise url
  const guess = raw.match(/^https?:\/\//i) ? raw : `https://${raw}`;
  const parsed = url.parse(guess);
  const host   = parsed.hostname || raw;

  const findings = [];

  /* 1. Scheme check */
  if(parsed.protocol === 'http:'){
    findings.push({
      severity:'high',
      title:'Target served over HTTP (unencrypted)',
      fix:'Force HTTPS and install a TLS certificate.'
    });
  }

  /* 2. IP address check */
  if(net.isIP(host)){
    findings.push({
      severity:'medium',
      title:'Target is a raw IP address',
      fix:'Use a hostname behind a proxy/CDN to reduce exposure.'
    });
  }

  /* 3. Attempt HEAD request (5 s timeout, follow redirects) */
  let resp;
  try{
    resp = await axios.head(guess, {
      maxRedirects: 3,
      timeout     : 5000,
      httpsAgent  : new https.Agent({ rejectUnauthorized:false })
    });
  }catch(e){
    findings.push({
      severity:'high',
      title:`Server unreachable (${e.code||e.message})`,
      fix:'Verify DNS, firewall and that the site is up.'
    });
    return findings;                     // cannot continue header checks
  }

  const h = Object.fromEntries(
    Object.entries(resp.headers).map(([k,v])=>[k.toLowerCase(),v])
  );

  /* 4. Header checks */
  if(!h['strict-transport-security']){
    findings.push({
      severity:'medium',
      title:'Missing Strict‑Transport‑Security header',
      fix:'Add HSTS to enforce HTTPS (e.g. max‑age=31536000; includeSubDomains).'
    });
  }
  if(!h['content-security-policy']){
    findings.push({
      severity:'medium',
      title:'Missing Content‑Security‑Policy header',
      fix:'Add a CSP to mitigate XSS and data‑injection.'
    });
  }
  if(!h['x-frame-options']){
    findings.push({
      severity:'low',
      title:'Missing X‑Frame‑Options header',
      fix:'Add SAMEORIGIN or DENY to prevent clickjacking.'
    });
  }
  if(h['server']){
    findings.push({
      severity:'low',
      title:`Server banner disclosed: ${h['server']}`,
      fix:'Remove or obfuscate the Server header.'
    });
  }

  /* 5. Nothing found? */
  if(!findings.length){
    findings.push({
      severity:'low',
      title:`No issues detected by header rules for ${host}`,
      fix:'Run a full scanner (OWASP ZAP, Nmap, etc.) for deeper checks.'
    });
  }
  return findings;
}

/* ───────── 3. Health ─────────────────────────────────────── */
app.get('/health',(_req,res)=>res.json({status:'up'}));

/* ───────── 4. Start ──────────────────────────────────────── */
app.listen(PORT,()=>console.log('Proxy running on port',PORT));
