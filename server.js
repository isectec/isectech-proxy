// ────────────────────────────────────────────────────────────
// iSECTECH Proxy – production server.js
// ----------------------------------------------------------------
// • POST  /scan   { target, profile, creds? } → { findings:[ … ] }
// • GET   /health                            → { status:"up" }
// • POST  /api/scan { message } (optional GPT helper)
// • Global CORS + OPTIONS handler
// ----------------------------------------------------------------
require('dotenv').config();
const express = require('express');
const axios   = require('axios');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─ 1) Global CORS & JSON body parsing
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);   // pre‑flight
  next();
});
app.use(express.json());

// ─ 2) Main scan endpoint
app.post('/scan', async (req, res) => {
  const { target, profile = 'quick', creds } = req.body || {};
  if (!target || typeof target !== 'string') {
    return res.status(400).json({ error: 'target is required (string)' });
  }

  try {
    // 🔄  REPLACE this stub with your real scanner
    const findings = await generateFindings({ target, profile, creds });
    res.json({ findings });
  } catch (err) {
    console.error('Scanner error:', err);
    res.status(500).json({ error: 'scan failed' });
  }
});

// Demo stub (keeps UI working)
async function generateFindings({ target }) {
  return [{
    severity : 'medium',
    title    : `Demo finding for ${target}`,
    fix      : 'Integrate your scanner logic in server.js'
  }];
}

// ─ 3) Health check
app.get('/health', (_req, res) => res.json({ status: 'up' }));

// ─ 4) Optional GPT helper
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
    res.json({ completion: ai.data.choices?.[0]?.message?.content || '' });
  } catch (e) {
    console.error('OpenAI error:', e.response?.data || e.message);
    res.status(500).json({ error: 'OpenAI request failed' });
  }
});

// ─ 5) Start server
app.listen(PORT, () => console.log(`Proxy running on port ${PORT}`));
