/**
 * iSECTECH Proxy – Simple‑Heuristic Scanner
 * ----------------------------------------
 * POST /scan   { target, profile, creds? } → { findings:[ … ] }
 * GET  /health                            → { status:"up" }
 * ----------------------------------------
 * The generateFindings() function below applies **basic rules**:
 *   • HTTP—not‑HTTPS  → HIGH
 *   • IP address      → MEDIUM (discloses infra)
 *   • Default port 80 → LOW
 *   • CIDR /24 range  → LOW
 * Replace generateFindings() with your own engine when ready.
 */
require('dotenv').config();
const express = require('express');
const url     = require('url');
const net     = require('net');

const app  = express();
const PORT = process.env.PORT || 3000;

/* ───────────────────── 1. CORS + JSON ─────────────────────── */
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.json());

/* ───────────────────── 2. /scan ───────────────────────────── */
app.post('/scan', async (req, res) => {
  const { target, profile = 'quick', creds } = req.body || {};
  if (!target || typeof target !== 'string') {
    return res.status(400).json({ error: 'target is required (string)' });
  }
  try {
    const findings = await generateFindings({ target, profile, creds });
    res.json({ findings });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'scan failed' });
  }
});

/* ─────────── Simple demo rules you can extend now ─────────── */
async function generateFindings({ target }) {
  const findings = [];
  const trimmed  = target.trim().split(/\s+/)[0];           // first line only
  const isCIDR   = /\/\d+$/.test(trimmed);
  const parsed   = url.parse(trimmed.startsWith('http') ? trimmed : `scheme://${trimmed}`);

  /* 1) HTTP (unencrypted) */
  if (parsed.protocol === 'http:') {
    findings.push({
      severity : 'high',
      title    : 'Target served over HTTP (unencrypted)',
      fix      : 'Redirect to HTTPS and install a valid TLS certificate.'
    });
  }

  /* 2) Raw IP address */
  if (net.isIP(parsed.hostname)) {
    findings.push({
      severity : 'medium',
      title    : 'Target is an IP address (possible direct server exposure)',
      fix      : 'Use a hostname behind reverse proxy/CDN if possible.'
    });
  }

  /* 3) Default port 80 with no TLS */
  if (parsed.port === '80' || (!parsed.port && parsed.protocol === 'http:')) {
    findings.push({
      severity : 'low',
      title    : 'Default port 80 detected',
      fix      : 'Close port 80 or redirect traffic to 443.'
    });
  }

  /* 4) CIDR range submitted */
  if (isCIDR) {
    findings.push({
      severity : 'low',
      title    : 'CIDR / range provided – large scope scan',
      fix      : 'Confirm you have permission to scan the whole range.'
    });
  }

  // Always return at least one finding so UI shows something.
  if (!findings.length) {
    findings.push({
      severity:'low',
      title:`No heuristic issues for ${parsed.hostname || trimmed}`,
      fix:'Run a full scanner (OWASP ZAP, Nmap, etc.) for deeper checks.'
    });
  }
  return findings;
}

/* ───────────────────── 3. /health ─────────────────────────── */
app.get('/health', (_req, res) => res.json({ status:'up' }));

/* ───────────────────── 4. start ───────────────────────────── */
app.listen(PORT, () => console.log(`Proxy running on port ${PORT}`));
