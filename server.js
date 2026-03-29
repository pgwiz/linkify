'use strict';

require('dotenv').config();

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Config ───────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
const PRIVATE_KEY_PATH = path.resolve(__dirname, process.env.PRIVATE_KEY_PATH || 'keys/private.pem');
const PUBLIC_KEY_PATH = path.resolve(__dirname, process.env.PUBLIC_KEY_PATH || 'keys/public.pem');

// The real secret payload lives only in env (never served as-is to the public)
let SECRET_DATA;
try {
  SECRET_DATA = JSON.parse(process.env.SECRET_DATA || '{}');
} catch {
  SECRET_DATA = {};
}

// ─── First-run detection ─────────────────────────────────────────────────────
// A "first run" means no RSA keys were pre-configured anywhere: neither as
// inline env vars (PRIVATE_KEY / PUBLIC_KEY – the Vercel-friendly approach)
// nor as both key files on disk (local dev).  We capture this BEFORE loadKeys()
// so the flag stays accurate even after keys are written to process.env.
const IS_FIRST_RUN =
  !process.env.PRIVATE_KEY &&
  !process.env.PUBLIC_KEY &&
  !(fs.existsSync(PRIVATE_KEY_PATH) && fs.existsSync(PUBLIC_KEY_PATH));

// ─── Key loading ─────────────────────────────────────────────────────────────
// Priority:
//   1. PRIVATE_KEY / PUBLIC_KEY env vars (PEM content) – Vercel / any 12-factor env
//   2. Key files on disk – local dev after running `node generate-keys.js`
//   3. Auto-generate in-memory and store in process.env for this run.
//      Also attempt to persist to disk so local dev keeps the keys across
//      restarts; silently skips the write on read-only filesystems (Vercel).
function loadKeys() {
  if (process.env.PRIVATE_KEY && process.env.PUBLIC_KEY) {
    return {
      privateKey: process.env.PRIVATE_KEY,
      publicKey: process.env.PUBLIC_KEY,
    };
  }

  if (fs.existsSync(PRIVATE_KEY_PATH) && fs.existsSync(PUBLIC_KEY_PATH)) {
    return {
      privateKey: fs.readFileSync(PRIVATE_KEY_PATH, 'utf8'),
      publicKey: fs.readFileSync(PUBLIC_KEY_PATH, 'utf8'),
    };
  }

  // No keys anywhere – generate a fresh pair for this process lifetime.
  console.log('⚠️  RSA keys not found – generating a temporary key pair.');
  console.log('   On Vercel: set PRIVATE_KEY and PUBLIC_KEY environment variables to persist them.');

  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
  });

  // Store in process.env so every part of this process uses the same keys.
  process.env.PRIVATE_KEY = privateKey;
  process.env.PUBLIC_KEY = publicKey;

  // Best-effort disk persistence (works locally, silently skipped on Vercel).
  try {
    const keysDir = path.dirname(PRIVATE_KEY_PATH);
    if (!fs.existsSync(keysDir)) fs.mkdirSync(keysDir, { recursive: true });
    fs.writeFileSync(PRIVATE_KEY_PATH, privateKey, { mode: 0o600 });
    fs.writeFileSync(PUBLIC_KEY_PATH, publicKey, { mode: 0o644 });
    console.log('✔  RSA key pair also saved to', keysDir);
  } catch {
    console.log('   (filesystem is read-only – keys are in-memory only for this run)');
  }

  return { privateKey, publicKey };
}

const { privateKey: SERVER_PRIVATE_KEY, publicKey: SERVER_PUBLIC_KEY } = loadKeys();

// ─── Database (txt/json file) ─────────────────────────────────────────────────

const DB_PATH = path.join(__dirname, 'db.json');
const db = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));

// ─── App ──────────────────────────────────────────────────────────────────────

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Routes ───────────────────────────────────────────────────────────────────

/**
 * GET /api/data
 * Public endpoint – returns the "story" from db.json.
 * No secrets are exposed here.
 */
app.get('/api/data', (_req, res) => {
  res.json({ ok: true, data: db.story });
});

/**
 * GET /api/public-key
 * Returns the server's RSA public key so clients can verify the server's
 * identity or encrypt messages back.
 */
app.get('/api/public-key', (_req, res) => {
  res.json({ ok: true, publicKey: SERVER_PUBLIC_KEY });
});

/**
 * GET /api/first-run
 * Returns whether this is the first run (no pre-configured RSA keys found at
 * startup).  On a first run the generated key values are included ONCE so the
 * operator can copy them into Vercel (or another 12-factor host) as
 * environment variables, making subsequent runs stable and key-consistent.
 *
 * The private key is returned only on the very first request to this endpoint
 * (per process lifetime) to minimise the exposure window.
 */
let firstRunServed = false;
app.get('/api/first-run', (_req, res) => {
  if (!IS_FIRST_RUN || firstRunServed) {
    return res.json({ firstRun: false });
  }

  firstRunServed = true;
  return res.json({
    firstRun: true,
    message:
      'RSA keys were auto-generated for this run. ' +
      'Set the environment variables below in your Vercel project to persist them.',
    env: {
      PRIVATE_KEY: SERVER_PRIVATE_KEY,
      PUBLIC_KEY: SERVER_PUBLIC_KEY,
    },
    instructions: [
      '1. Copy PRIVATE_KEY and PUBLIC_KEY from this response.',
      '2. In Vercel → Project Settings → Environment Variables, add both variables.',
      '3. Redeploy. This setup panel will not appear again once the variables are set.',
    ],
  });
});

/**
 * POST /api/data
 * Body: { "publicKey": "<PEM-encoded RSA public key>" }
 *
 * Behaviour:
 *   1. Validate the submitted public key by comparing its fingerprint against
 *      the server's own public key fingerprint.
 *   2. If it matches, the SECRET_DATA payload is encrypted with the submitted
 *      public key (so only the holder of the matching private key can decrypt
 *      it) and returned as base64.
 *   3. If it does not match, a 403 is returned with the story data (same as
 *      the public GET endpoint).
 */
app.post('/api/data', (req, res) => {
  const { publicKey: submittedKey } = req.body || {};

  if (!submittedKey || typeof submittedKey !== 'string') {
    return res.status(400).json({
      ok: false,
      error: 'Body must contain a "publicKey" field with a PEM-encoded RSA public key.',
    });
  }

  // Normalise both keys to DER fingerprints for comparison
  let submittedFingerprint;
  try {
    const keyObj = crypto.createPublicKey(submittedKey);
    const der = keyObj.export({ type: 'pkcs1', format: 'der' });
    submittedFingerprint = crypto.createHash('sha256').update(der).digest('hex');
  } catch {
    return res.status(400).json({ ok: false, error: 'Invalid public key format.' });
  }

  const serverKeyObj = crypto.createPublicKey(SERVER_PUBLIC_KEY);
  const serverDer = serverKeyObj.export({ type: 'pkcs1', format: 'der' });
  const serverFingerprint = crypto.createHash('sha256').update(serverDer).digest('hex');

  if (submittedFingerprint !== serverFingerprint) {
    // Key doesn't match – return the story just like the public GET
    return res.status(403).json({
      ok: false,
      message: 'Public key does not match. Here is the public story instead.',
      data: db.story,
    });
  }

  // Key matches – encrypt the secret payload with the submitted public key
  // so only the holder of the matching private key can decrypt it.
  const plaintext = JSON.stringify(SECRET_DATA);
  const encrypted = crypto.publicEncrypt(
    { key: submittedKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    Buffer.from(plaintext, 'utf8')
  );

  return res.json({
    ok: true,
    message: 'Key verified. Secret payload encrypted with your public key.',
    encrypted: encrypted.toString('base64'),
    hint: 'Decrypt with: crypto.privateDecrypt({ key: yourPrivateKey, padding: RSA_PKCS1_OAEP_PADDING }, Buffer.from(encrypted, "base64"))',
  });
});

// ─── Start ────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`🔐  Linkify server running on http://localhost:${PORT}`);
  console.log(`    GET  /api/data        – public story`);
  console.log(`    GET  /api/public-key  – server RSA public key`);
  console.log(`    POST /api/data        – submit your public key to get the real payload`);
});

module.exports = app;
