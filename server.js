/*****************************************************************
 * iSECTECH Proxy – Quick + Advanced Scanner
 * --------------------------------------------------------------
 * POST /scan
 *   body:{
 *     target : "https://example.com" | "1.2.3.4",
 *     profile: "quick" | "full",
 *     creds? : "...",
 *     user?  : { email, phone, country }
 *   }
 *   → { findings:[ {severity,title,fix}, … ] }
 *
 * GET  /health → { status:"up" }
 *****************************************************************/
require('dotenv').config();
const express = require('express');
const axios   = require('axios');
const https   = require('https');
const url     = require('url');
const net     = require('net');

const app  = express();
const PORT = process.env.PORT || 3000;
const SHODAN_KEY = process.env.SHODAN_KEY;      // optional

/* ─── middleware (CORS + JSON) ───────────────────────────────── */
app.use((req,res,next)=>{
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization');
  if(req.method==='OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.json());

/* ─── POST /scan ─────────────────────────────────────────────── */
app.post('/scan', async (req,res)=>{
  const { target, profile='quick' } = req.body || {};
  if(!target || typeof target!=='string'){
    return res.status(400).json({ error:'target (string) is required' });
  }
  try{
    const findings = profile==='full'
      ? await runAdvancedScan(target.trim())
      : await runQuickScan(target.trim());
    res.json({ findings });
  }catch(e){
    console.error(e);
    res.status(500).json({ error:'scan failed' });
  }
});

/* ─── Quick scan (headers + simple heuristics) ───────────────── */
async function runQuickScan(raw){
  const snap = await getHeaderSnapshot(raw);
  if(snap.error){
    return [{ severity:'high', title:`Unreachable: ${snap.error}`, fix:'Check DNS / firewall.' }];
  }
  return basicHeaderRules(raw, snap.headers);
}

/* ─── Advanced scan (3 external services) ────────────────────── */
async function runAdvancedScan(raw){
  const host = tidyHost(raw);
  const [sh, ssl, shd] = await Promise.allSettled([
    axios.get(`https://securityheaders.com/?q=${encodeURIComponent('https://'+host)}&followRedirects=on&hide=on&json=on`,{timeout:10000}),
    sslLabsScan(host),
    SHODAN_KEY ? axios.get(`https://api.shodan.io/shodan/host/${host}?key=${SHODAN_KEY}`,{timeout:10000}) : Promise.resolve({status:'rejected'})
  ]);

  let findings = [];
  if(sh.status==='fulfilled')  findings.push(...mapSecurityHeaders(sh.value.data));
  if(ssl.status==='fulfilled') findings.push(...mapSsl(ssl.value));
  if(shd.status==='fulfilled') findings.push(...mapShodan(shd.value.data));

  /* fallback so user always gets something */
  if(!findings.length){
    const snap = await getHeaderSnapshot(raw);
    findings = snap.error ? [{
      severity:'high', title:`Unreachable: ${snap.error}`, fix:'Check DNS / firewall.'
    }] : basicHeaderRules(raw,snap.headers);
  }
  return findings;
}

/* ─── Helpers ░░ Network snapshots ░░─────────────────────────── */
function tidyHost(raw){return raw.replace(/^https?:\/\//i,'').replace(/\/.*$/,'');}

async function getHeaderSnapshot(raw){
  const guess = raw.match(/^https?:\/\//i) ? raw : `https://${raw}`;
  try{
    const r=await axios.head(guess,{timeout:6000,maxRedirects:3,httpsAgent:new https.Agent({rejectUnauthorized:false})});
    return { status:r.status, headers:r.headers };
  }catch(e){ return { error:e.code||e.message }; }
}

/* ─── Mapping helpers ────────────────────────────────────────── */
function basicHeaderRules(raw,headers){
  const h=Object.fromEntries(Object.entries(headers).map(([k,v])=>[k.toLowerCase(),v]));
  const list=[];
  if(!h['strict-transport-security']) list.push({severity:'medium',title:'Missing HSTS',fix:'Add Strict‑Transport‑Security.'});
  if(!h['content-security-policy'])   list.push({severity:'medium',title:'Missing CSP', fix:'Add Content‑Security‑Policy.'});
  if(!h['x-frame-options'])           list.push({severity:'low',   title:'Missing X‑Frame‑Options', fix:'Add SAMEORIGIN or DENY.'});
  if(h['server'])                     list.push({severity:'low',   title:`Server banner: ${h['server']}`, fix:'Remove or obfuscate Server header.'});
  return list.length?list:[{severity:'low',title:`No obvious header issues for ${tidyHost(raw)}`,fix:'Run advanced scan for deeper checks.'}];
}

function gradeToSeverity(g){ if(['A+','A'].includes(g))return'low'; if(['B','C'].includes(g))return 'medium'; return 'high'; }

function mapSecurityHeaders(d){
  const out=[];
  if(d.grade) out.push({severity:gradeToSeverity(d.grade),title:`SecurityHeaders grade ${d.grade}`,fix:'Add or strengthen headers to improve grade.'});
  (d.missing||[]).forEach(h=>out.push({severity:'medium',title:`Missing ${h} header`,fix:`Add ${h}`}));
  (d.partial||[]).forEach(h=>out.push({severity:'low',title:`${h} header weak`,fix:`Harden ${h}`}));
  return out;
}

function mapSsl(r){
  const ep=r.endpoints&&r.endpoints[0]; if(!ep) return [];
  const list=[{severity:gradeToSeverity(ep.grade||'F'),title:`TLS grade ${ep.grade||'F'}`,fix:'Upgrade weak ciphers / protocols, enable HSTS.'}];
  if(ep.details?.cert?.notAfter){
    const days=Math.round((ep.details.cert.notAfter/1000-Date.now()/1000)/86400);
    if(days<30) list.push({severity:'medium',title:`TLS cert expires in ${days} days`,fix:'Renew certificate.'});
  }
  return list;
}

function mapShodan(d){
  if(!d.ports) return [];
  return d.ports.map(p=>({
    severity:p===22||p===3389?'high':'medium',
    title   :`Port ${p} open (${d.hostnames?.[0]||d.ip_str})`,
    fix     :'Restrict access or close the service if not needed.'
  }));
}

/* ─── SSL Labs polling helper ───────────────────────────────── */
async function sslLabsScan(host){
  const base='https://api.ssllabs.com/api/v3/analyze';
  for(let i=0;i<12;i++){    // up to 12×15 s = 3 min
    const { data } = await axios.get(base,{params:{host,publish:'off',all:'done',fromCache:'on',ignoreMismatch:'on'},timeout:15000});
    if(data.status==='READY') return data;
    if(['ERROR','DNS'].includes(data.status)) throw new Error(data.statusMessage||'SSL Labs error');
    await new Promise(r=>setTimeout(r,15000));
  }
  throw new Error('SSL Labs timed out');
}

/* ─── Health ────────────────────────────────────────────────── */
app.get('/health',(_q,r)=>r.json({status:'up'}));

/* ─── Start ─────────────────────────────────────────────────── */
app.listen(PORT,()=>console.log('Proxy running on',PORT));
