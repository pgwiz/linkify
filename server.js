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

// Load RSA keys at startup – crash early if keys are missing so the operator
// knows they need to run `node generate-keys.js` first.
function loadKeys() {
  if (!fs.existsSync(PRIVATE_KEY_PATH) || !fs.existsSync(PUBLIC_KEY_PATH)) {
    console.error(
      '❌  RSA keys not found. Run `node generate-keys.js` to create them.'
    );
    process.exit(1);
  }
  return {
    privateKey: fs.readFileSync(PRIVATE_KEY_PATH, 'utf8'),
    publicKey: fs.readFileSync(PUBLIC_KEY_PATH, 'utf8'),
  };
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
