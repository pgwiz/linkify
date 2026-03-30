'use strict';

require('dotenv').config();

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Startup env diagnostics ──────────────────────────────────────────────────
// Print all environment variable NAMES so operators can confirm which vars have
// been injected, then show safe diagnostics for the two critical key vars.
(function logEnvDiagnostics() {
  const allKeys = Object.keys(process.env).sort();
  console.log(`\n📋  Environment variables present at startup (${allKeys.length} total):`);
  console.log('   ', allKeys.join(', '));

  const keyVars = ['PRIVATE_KEY', 'PUBLIC_KEY'];
  console.log('\n🔍  Key-variable diagnostics:');
  for (const name of keyVars) {
    const defined = name in process.env;          // key exists (even if empty)
    const val     = process.env[name] || '';

    if (!defined) {
      console.log(`   ${name}: ❌  NOT DEFINED (variable not injected at all – add it in Vercel → Project Settings → Environment Variables)`);
      continue;
    }
    if (!val) {
      console.log(`   ${name}: ❌  DEFINED BUT EMPTY (variable exists with blank value – paste the actual PEM content into Vercel)`);
      continue;
    }
    const byteLen = Buffer.byteLength(val, 'utf8');
    const firstLine = val.split('\n')[0].trim();
    const lastLine = val.trimEnd().split('\n').pop().trim();
    const looksLikePem =
      firstLine.startsWith('-----BEGIN') && lastLine.startsWith('-----END');
    console.log(`   ${name}: ✅  SET`);
    console.log(`            length  : ${byteLen} bytes`);
    console.log(`            firstLine: "${firstLine}"`);
    console.log(`            lastLine : "${lastLine}"`);
    console.log(`            PEM shape: ${looksLikePem ? '✅  looks valid' : '❌  DOES NOT look like a PEM block – check for missing newlines'}`);
  }
  console.log('');
})();

// ─── Config ───────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
const PRIVATE_KEY_PATH = path.resolve(__dirname, process.env.PRIVATE_KEY_PATH || 'keys/private.pem');
const PUBLIC_KEY_PATH = path.resolve(__dirname, process.env.PUBLIC_KEY_PATH || 'keys/public.pem');

// Env vars that must never be included in the encrypted payload.
const SECRET_ENV_EXCLUDES = new Set(['PRIVATE_KEY', 'PUBLIC_KEY']);

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
  const hasEnvPrivate = !!(process.env.PRIVATE_KEY);
  const hasEnvPublic  = !!(process.env.PUBLIC_KEY);
  console.log(`🔑  loadKeys() – PRIVATE_KEY in env: ${hasEnvPrivate}, PUBLIC_KEY in env: ${hasEnvPublic}`);

  // Partial configuration: one key present, the other missing/empty.
  if (hasEnvPrivate !== hasEnvPublic) {
    const missing = hasEnvPrivate ? 'PUBLIC_KEY' : 'PRIVATE_KEY';
    const present = hasEnvPrivate ? 'PRIVATE_KEY' : 'PUBLIC_KEY';
    console.error(
      `⚠️  PARTIAL KEY CONFIG: ${present} is set but ${missing} is missing or empty. ` +
      `Both PRIVATE_KEY and PUBLIC_KEY must be set in Vercel → Project Settings → Environment Variables. ` +
      `A fresh matched pair from: GET /api/first-run (local dev) or run \`node generate-keys.js\`.`
    );
  }

  if (hasEnvPrivate && hasEnvPublic) {
    console.log('🔑  loadKeys() → using PRIVATE_KEY / PUBLIC_KEY from environment variables.');
    return {
      privateKey: process.env.PRIVATE_KEY,
      publicKey: process.env.PUBLIC_KEY,
    };
  }

  const diskPrivateExists = fs.existsSync(PRIVATE_KEY_PATH);
  const diskPublicExists  = fs.existsSync(PUBLIC_KEY_PATH);
  console.log(`🔑  loadKeys() – disk check: ${PRIVATE_KEY_PATH} exists=${diskPrivateExists}, ${PUBLIC_KEY_PATH} exists=${diskPublicExists}`);

  if (diskPrivateExists && diskPublicExists) {
    console.log('🔑  loadKeys() → loading keys from disk files.');
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

// ─── Startup key validation ───────────────────────────────────────────────────
// 1. Verify the public key PEM is syntactically valid.
// 2. Derive the public key from the private key and compare fingerprints to
//    confirm the two keys form a matched pair.
// Returns { ok: true, fingerprint } on success or { ok: false, error } on failure.
// Never throws or exits – the result is exposed via GET /api/key-status so the
// frontend can surface a clear mismatch warning to operators.
function validateKeys(privateKeyPem, publicKeyPem) {
  // ── Syntax check ────────────────────────────────────────────────────────────
  let pubKeyObj;
  try {
    pubKeyObj = crypto.createPublicKey(publicKeyPem);
  } catch (err) {
    const msg = 'PUBLIC_KEY has invalid PEM syntax: ' + err.message;
    console.error('❌ ', msg);
    return { ok: false, error: msg };
  }

  let privKeyObj;
  try {
    privKeyObj = crypto.createPrivateKey(privateKeyPem);
  } catch (err) {
    const msg = 'PRIVATE_KEY has invalid PEM syntax: ' + err.message;
    console.error('❌ ', msg);
    return { ok: false, error: msg };
  }

  // ── Pair check ───────────────────────────────────────────────────────────────
  // Derive the public key from the private key and compare DER fingerprints.
  const derivedPubObj = crypto.createPublicKey(privKeyObj);

  function fingerprint(keyObj) {
    const der = keyObj.export({ type: 'pkcs1', format: 'der' });
    return crypto.createHash('sha256').update(der).digest('hex');
  }

  const storedFP  = fingerprint(pubKeyObj);
  const derivedFP = fingerprint(derivedPubObj);

  if (storedFP !== derivedFP) {
    const msg =
      'Private key and public key are NOT a matched pair. ' +
      `Stored fingerprint: ${storedFP} — Derived fingerprint: ${derivedFP}. ` +
      'Run `node generate-keys.js` to regenerate a matching pair, ' +
      'then update PRIVATE_KEY and PUBLIC_KEY in your environment.';
    console.error('❌ ', msg);
    return { ok: false, error: msg };
  }

  return { ok: true, fingerprint: storedFP };
}

const KEY_STATUS = validateKeys(SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY);
const KEY_FINGERPRINT = KEY_STATUS.ok ? KEY_STATUS.fingerprint : null;

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
 * GET /api/key-status
 * Returns whether the server's RSA key pair is valid and matched.
 * Used by the frontend to surface a configuration warning to operators.
 * Never exposes key material.
 */
app.get('/api/key-status', (_req, res) => {
  if (KEY_STATUS.ok) {
    return res.json({ ok: true, fingerprint: KEY_FINGERPRINT });
  }
  return res.status(500).json({ ok: false, error: KEY_STATUS.error });
});

/**
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
 *   2. If it matches, all environment variables (except PRIVATE_KEY and
 *      PUBLIC_KEY) are serialised and encrypted with the submitted public key
 *      so only the holder of the matching private key can decrypt them.
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

  // Key matches – hybrid-encrypt all env vars (minus key material):
  //   1. Random AES-256-GCM key encrypts the (arbitrarily large) payload.
  //   2. RSA-OAEP encrypts the small AES key so only the private-key holder
  //      can unwrap it.
  const envPayload = Object.fromEntries(
    Object.entries(process.env).filter(([k]) => !SECRET_ENV_EXCLUDES.has(k))
  );
  const plaintext = JSON.stringify(envPayload);

  const aesKey = crypto.randomBytes(32);          // 256-bit AES key
  const iv     = crypto.randomBytes(12);          // 96-bit IV for GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(plaintext, 'utf8')),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();             // 16-byte GCM auth tag

  const encryptedKey = crypto.publicEncrypt(
    { key: submittedKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    aesKey
  );

  return res.json({
    ok: true,
    message: 'Key verified. Payload encrypted with hybrid RSA-OAEP + AES-256-GCM.',
    encryptedKey: encryptedKey.toString('base64'),
    iv:           iv.toString('base64'),
    ciphertext:   ciphertext.toString('base64'),
    authTag:      authTag.toString('base64'),
    hint: 'Decrypt: RSA-OAEP-unwrap(encryptedKey) → AES-256-GCM-decrypt(ciphertext, iv, authTag)',
  });
});

// ─── Start ────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`🔐  Linkify server running on http://localhost:${PORT}`);
  console.log(`    GET  /api/data        – public story`);
  console.log(`    GET  /api/public-key  – server RSA public key`);
  console.log(`    GET  /api/key-status  – key pair validation status`);
  console.log(`    POST /api/data        – submit your public key to get the real payload`);
  if (KEY_STATUS.ok) {
    console.log(`\n🔑  Server public key (fingerprint: ${KEY_FINGERPRINT}):`);
    console.log(SERVER_PUBLIC_KEY.trimEnd());
  } else {
    console.error(`\n⚠️  Key pair is INVALID – see /api/key-status for details.`);
  }
});

module.exports = app;
