// ────────────────────────────────────────────────────────────
// iSECTECH Proxy — server.js (FINAL COPY-PASTE VERSION)
// ----------------------------------------------------------------
// • Accepts  POST  /scan   { target, profile, creds? }
// • Returns  { findings:[ {severity,title,fix?}, … ] }
// • CORS wide-open during testing (tighten later)
// • Handles OPTIONS /scan so browsers never see a 404 pre-flight
// • Health check at GET /health
// ----------------------------------------------------------------

require('dotenv').config();
const express = require('express');
const app     = express();

// ─ 1) CORS & JSON parsing ──────────────────────────────────────
// Always send CORS headers and handle OPTIONS before any route
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.json());

// ─ 2) /scan endpoint ────────────────────────────────────────────
app.post('/scan', async (req, res) => {
  const { target, profile = 'quick', creds } = req.body || {};
  if (!target || typeof target !== 'string') {
    return res.status(400).json({ error: 'target is required (string)' });
  }

  // TODO: Call your real scanner here. For now, a placeholder:
  const findings = [{
    severity: 'medium',
    title:    `Demo finding for ${target}`,
    fix:      'Integrate your scanner logic in server.js'
  }];

  res.json({ findings });
});

// ─ 3) Health check ──────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({ status: 'up' });
});

// ─ 4) (Optional) OpenAI passthrough ─────────────────────────────
const axios = require('axios');
app.post('/api/scan', async (req, res) => {
  const { message } = req.body || {};
  if (!message) return res.status(400).json({ error: 'message required' });
  const key = process.env.OPENAI_API_KEY;
  if (!key) return res.status(500).json({ error: 'OPENAI_API_KEY not set' });

  try {
    const ai = await axios.post(
      'https://api.openai.com/v1/chat/completions',
      { model:'gpt-4', messages:[{role:'user',content:message}] },
      { headers:{ Authorization:`Bearer ${key}` } }
    );
    res.json({ completion: ai.data.choices[0].message.content });
  } catch (e) {
    console.error(e.response?.data||e.message);
    res.status(500).json({ error:'OpenAI call failed' });
  }
});

// ─ 5) Start server ──────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Proxy running on port ${PORT}`));
