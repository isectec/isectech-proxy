/* ───────────────── iSECTECH Proxy – FINAL server.js ─────────────────
   • CORS wide‑open for browser testing
   • /scan   – quick or full (SecurityHeaders + SSL Labs + optional Shodan)
   • /health – uptime probe
   • Ignores / stores optional lead object { email, phone, country }
   ------------------------------------------------------------------- */
require('dotenv').config();
const express = require('express');
const axios    = require('axios');
const cors     = require('cors');
const app      = express();

/* ─ 1. CORS & JSON ─ */
app.use(cors());          // open for any origin while testing
app.use(express.json());  // parse JSON bodies

/* ─ 2. Health ping ─ */
app.get('/health', (_req,res)=>res.json({status:'up'}));

/* ─ 3. /scan endpoint ─ */
app.post('/scan', async (req,res)=>{
  /* pull the expected keys and IGNORE the rest (fix that broke adv. scan) */
  const { target, profile='quick', creds } = req.body || {};
  const lead = req.body.user; // {email, phone, country} if present

  if(!target || typeof target!=='string'){
    return res.status(400).json({error:'target is required'});
  }

  /* save / e‑mail the lead if provided (non‑blocking) */
  if(lead?.email){
    console.log('📩  New lead:', lead);
    // TODO: send to Mailchimp / Airtable / SMTP – here we just log
  }

  try{
    const findings = [];

    /* ─ Quick header scan via securityheaders.com ─ */
    const sh = await axios.get(
      `https://securityheaders.com/?q=${encodeURIComponent(target)}&hide=on&followRedirects=on`,
      {headers:{'X-Requested-With':'XMLHttpRequest'}}
    ).then(r=>r.data);

    if(sh.missing){
      sh.missing.forEach(h=>findings.push({
        severity: h.score>50?'medium':'low',
        title   : `Missing ${h.header} header`,
        fix     : h.description
      }));
    }

    /* ─ TLS / cipher grade via SSL Labs (takes ≈ 5 sec) ─ */
    const ssllabs = await axios.get(
      `https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(target)}&fromCache=on&all=done`
    ).then(r=>r.data);

    if(ssllabs.endpoints?.length){
      const g = ssllabs.endpoints[0].grade || 'T';
      if(g!=='A'&&g!=='A+'){
        findings.push({
          severity: g==='B'?'low':'medium',
          title   : `TLS grade ${g}`,
          fix     : 'Harden TLS ciphers / enable HSTS for an A grade'
        });
      }
    }

    /* ─ Optional Shodan check (only on FULL scan & if SHODAN_KEY is set) ─ */
    if(profile==='full' && process.env.SHODAN_KEY){
      const shodan = await axios.get(
        `https://api.shodan.io/shodan/host/${encodeURIComponent(target)}?key=${process.env.SHODAN_KEY}`
      ).then(r=>r.data);

      (shodan.vulns||[]).forEach(v=>findings.push({
        severity:'high',
        title   : `Exposed service: ${v}`,
        fix     : 'Restrict firewall or patch the service'
      }));
    }

    /* demo fallback */
    if(!findings.length){
      findings.push({severity:'low',title:`Nothing critical for ${target}`,fix:'Run a pen‑test for deeper issues.'});
    }

    res.json({findings});
  }catch(err){
    console.error(err.message);
    res.status(500).json({error:'scan failed'});
  }
});

/* ─ 4. start server ─ */
const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=>console.log('Proxy running on port',PORT));
