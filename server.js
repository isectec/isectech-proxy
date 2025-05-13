/**********************************************************************
*  A.  iSECTECH Proxy — server.js  (drop‑in)                          *
*      • /scan   – quick or full header/TLS/Shodan scan               *
*      • /health – uptime probe                                       *
*      • CORS wide‑open while testing                                 *
**********************************************************************/

require('dotenv').config();
const express = require('express');
const axios   = require('axios');
const cors    = require('cors');
const app     = express();

/* ── 1. Middleware ─────────────────────────────────────────────── */
app.use(cors());                // any origin (tighten in prod)
app.use(express.json());        // parse JSON

/* ── 2. Health ping ────────────────────────────────────────────── */
app.get('/health', (_req,res)=>res.json({status:'up'}));

/* ── 3. /scan endpoint ─────────────────────────────────────────── */
app.post('/scan', async (req,res)=>{
  const { target, profile='quick', creds } = req.body || {};
  const lead = req.body.user;                      // {email,phone,country}

  if(!target || typeof target!=='string'){
    return res.status(400).json({error:'target is required'});
  }
  if(lead?.email) console.log('📩 Lead captured:', lead);

  const findings = [];                             // ← final array
  const safe = async (fn, label)=>{                // swallow 4xx/5xx
    try{ await fn(); }
    catch(e){
      console.warn(`${label} →`, e.response?.status||e.code||e.message);
      findings.push({
        severity:'low',
        title:`${label} unavailable (${e.response?.status||'ERR'})`,
        fix:'Remote service blocked or timed‑out – try again later.'
      });
    }
  };

  /* 3‑A  SecurityHeaders */
  await safe(async ()=>{
    const r=await axios.get(
      `https://securityheaders.com/?q=${encodeURIComponent(target)}&hide=on&followRedirects=on`,
      {headers:{'X-Requested-With':'XMLHttpRequest','User-Agent':'isectech-proxy'}}
    );
    (r.data.missing||[]).forEach(h=>findings.push({
      severity: h.score>50?'medium':'low',
      title   : `Missing ${h.header} header`,
      fix     : h.description
    }));
  },'SecurityHeaders');

  /* 3‑B  SSL Labs TLS grade */
  await safe(async ()=>{
    const r=await axios.get(
      `https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(target)}&fromCache=on&all=done`,
      {timeout:20000}
    );
    const g=r.data.endpoints?.[0]?.grade;
    if(g && !['A','A+'].includes(g)){
      findings.push({
        severity:g==='B'?'low':'medium',
        title:`TLS grade ${g}`,
        fix:'Harden ciphers / enable HSTS for an A grade'
      });
    }
  },'SSL Labs');

  /* 3‑C  Shodan (only on FULL + key present) */
  if(profile==='full'){
    if(!process.env.SHODAN_KEY){
      console.log('ℹ️ SHODAN_KEY not set – skipping Shodan scan');
    }else{
      await safe(async ()=>{
        const r=await axios.get(
          `https://api.shodan.io/shodan/host/${encodeURIComponent(target)}?key=${process.env.SHODAN_KEY}`
        );
        (r.data.vulns||[]).forEach(v=>findings.push({
          severity:'high',
          title:`Exposed service: ${v}`,
          fix:'Restrict firewall or patch the service'
        }));
      },'Shodan');
    }
  }

  /* 3‑D  Nothing found? add placeholder */
  if(!findings.length){
    findings.push({severity:'low',title:`No critical issues for ${target}`,fix:'Run a pen‑test for deeper coverage.'});
  }

  return res.json({findings});
});

/* 4. Keep process alive on rogue promises */
process.on('unhandledRejection',err=>console.error('UNHANDLED',err));

/* 5. Start */
const PORT=process.env.PORT||3000;
app.listen(PORT,()=>console.log('Proxy running on port',PORT));
