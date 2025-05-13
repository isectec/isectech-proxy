/****************************************************************
 * iSECTECH Proxy – AI‑Assisted Quick Scanner
 * -------------------------------------------------------------
 * POST /scan { target, profile, creds? }
 *         → { findings:[ {severity,title,fix}, … ] }
 * GET  /health → { status:"up" }
 *
 * Uses OpenAI to analyse HTTP response headers and return
 * structured findings.  Falls back to built‑in heuristics if
 * the AI call errors or returns nothing.
 ****************************************************************/
require('dotenv').config();
const express = require('express');
const axios   = require('axios');
const https   = require('https');
const url     = require('url');
const net     = require('net');

const app  = express();
const PORT = process.env.PORT || 3000;
const OPENAI_KEY = process.env.OPENAI_API_KEY;  // set this in Railway!

/* ─────── 1. Global middleware (CORS + JSON) ───────────────── */
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.json());

/* ─────── 2. Main scan endpoint ────────────────────────────── */
app.post('/scan', async (req, res) => {
  const { target } = req.body || {};
  if (!target || typeof target !== 'string') {
    return res.status(400).json({ error: 'target is required (string)' });
  }
  try {
    const findings = await generateFindings(target.trim());
    return res.json({ findings });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'scan failed' });
  }
});

/* ─────── Core logic: AI + fallback heuristics ─────────────── */
async function generateFindings(rawTarget) {
  /* 1. Snapshot headers/status */
  const snap = await getHeaderSnapshot(rawTarget);          // { status, headers } or { error }
  if (snap.error) {
    return [{ severity:'high', title:'Unreachable: ' + snap.error, fix:'Verify DNS / connectivity.' }];
  }

  /* 2. Try OpenAI */
  if (OPENAI_KEY) {
    try {
      const aiFindings = await askOpenAI(rawTarget, snap);
      if (aiFindings?.length) return aiFindings;
    } catch (e) {
      console.error('OpenAI failure, falling back:', e.response?.data || e.message);
    }
  }

  /* 3. Fallback heuristics */
  return basicHeaderRules(rawTarget, snap);
}

/* ── Helper: fetch headers with 6 s timeout & follow redirects */
async function getHeaderSnapshot(raw) {
  const guess = raw.match(/^https?:\/\//i) ? raw : `https://${raw}`;
  try {
    const resp = await axios.head(guess, {
      timeout      : 6000,
      maxRedirects : 3,
      httpsAgent   : new https.Agent({ rejectUnauthorized:false })
    });
    return {
      status  : resp.status,
      headers : resp.headers
    };
  } catch(e) {
    return { error: e.code || e.message };
  }
}

/* ── Helper: OpenAI function call style ────────────────────── */
async function askOpenAI(target, snap) {
  const systemMsg = `
You are a senior web‑application pentester.
Given an HTTP response snapshot, output JSON:
{
  "findings":[
    { "severity":"critical|high|medium|low", "title":"...", "fix":"..." }
  ]
}
Titles max 90 chars, fixes max 140 chars.`;
  const userMsg = JSON.stringify({ target, ...snap }, null, 2);

  const { data } = await axios.post(
    'https://api.openai.com/v1/chat/completions',
    {
      model: 'gpt-4o-mini',            // or gpt-4o / gpt-3.5-turbo
      temperature: 0.2,
      messages: [
        { role:'system', content: systemMsg },
        { role:'user',   content: userMsg  }
      ],
      response_format: { type:'json_object' }
    },
    { headers: { Authorization:`Bearer ${OPENAI_KEY}` } }
  );

  const parsed = JSON.parse(data.choices[0].message.content || '{}');
  return parsed.findings;
}

/* ── Fallback heuristic rules (same as before) ─────────────── */
function basicHeaderRules(raw, { headers }) {
  const host = url.parse(raw.match(/^https?:\/\//) ? raw : `https://${raw}`).hostname || raw;
  const h = Object.fromEntries(Object.entries(headers).map(([k,v])=>[k.toLowerCase(),v]));
  const list = [];

  if (net.isIP(host)) {
    list.push({ severity:'medium', title:'Target is an IP address', fix:'Use hostname behind CDN/proxy.' });
  }
  if (!h['strict-transport-security']) {
    list.push({ severity:'medium', title:'Missing Strict‑Transport‑Security header', fix:'Add HSTS max-age=31536000.' });
  }
  if (!h['content-security-policy']) {
    list.push({ severity:'medium', title:'Missing Content‑Security‑Policy header', fix:'Add CSP to mitigate XSS.' });
  }
  if (!h['x-frame-options']) {
    list.push({ severity:'low', title:'Missing X‑Frame‑Options header', fix:'Add SAMEORIGIN or DENY.' });
  }
  if (h['server']) {
    list.push({ severity:'low', title:`Server banner disclosed: ${h['server']}`, fix:'Remove or obfuscate Server header.' });
  }
  if (!list.length) {
    list.push({ severity:'low', title:`No obvious header issues for ${host}`, fix:'Run deeper dynamic scan for vulns.' });
  }
  return list;
}

/* ─────── 3. Health ────────────────────────────────────────── */
app.get('/health', (_req,res)=>res.json({ status:'up' }));

/* ─────── 4. Start ─────────────────────────────────────────── */
app.listen(PORT, () => console.log('Proxy running on port', PORT));
