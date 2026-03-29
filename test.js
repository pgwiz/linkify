'use strict';
/**
 * test.js – Basic integration tests for the Linkify server.
 * Run with:  node test.js
 *
 * Requires:  node generate-keys.js  to have been run first.
 */

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Helpers ──────────────────────────────────────────────────────────────────

function request(method, urlPath, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const options = {
      hostname: '127.0.0.1',
      port: 3000,
      path: urlPath,
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
      },
    };
    const req = http.request(options, (res) => {
      let raw = '';
      res.on('data', (c) => (raw += c));
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(raw) }));
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

let passed = 0;
let failed = 0;

function assert(label, condition, detail = '') {
  if (condition) {
    console.log(`  ✔ ${label}`);
    passed++;
  } else {
    console.error(`  ✘ ${label}${detail ? ' – ' + detail : ''}`);
    failed++;
  }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

async function run() {
  console.log('\nLinkify – integration tests\n');

  // 1. GET /api/data returns the story
  {
    console.log('1. GET /api/data');
    const { status, body } = await request('GET', '/api/data');
    assert('HTTP 200', status === 200, `got ${status}`);
    assert('ok: true', body.ok === true);
    assert('has title', typeof body.data?.title === 'string');
    assert('has chapters', Array.isArray(body.data?.chapters));
  }

  // 2. GET /api/public-key returns the server PEM
  {
    console.log('\n2. GET /api/public-key');
    const { status, body } = await request('GET', '/api/public-key');
    assert('HTTP 200', status === 200, `got ${status}`);
    assert('has publicKey', typeof body.publicKey === 'string');
    assert('PEM header', body.publicKey.includes('BEGIN RSA PUBLIC KEY'));
  }

  // 3. POST /api/data without body returns 400
  {
    console.log('\n3. POST /api/data – missing publicKey field');
    const { status, body } = await request('POST', '/api/data', {});
    assert('HTTP 400', status === 400, `got ${status}`);
    assert('ok: false', body.ok === false);
  }

  // 4. POST /api/data with wrong key returns 403 + story
  {
    console.log('\n4. POST /api/data – wrong public key');
    const { publicKey: wrongKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    });
    const { status, body } = await request('POST', '/api/data', { publicKey: wrongKey });
    assert('HTTP 403', status === 403, `got ${status}`);
    assert('ok: false', body.ok === false);
    assert('returns story', typeof body.data?.title === 'string');
  }

  // 5. POST /api/data with the correct server public key returns encrypted payload
  {
    console.log('\n5. POST /api/data – correct server public key');
    // Load the server's public key from the file
    const pubKeyPath = path.join(__dirname, 'keys', 'public.pem');
    const serverPublicKey = fs.readFileSync(pubKeyPath, 'utf8');
    const { status, body } = await request('POST', '/api/data', { publicKey: serverPublicKey });
    assert('HTTP 200', status === 200, `got ${status}`);
    assert('ok: true', body.ok === true);
    assert('has encrypted field', typeof body.encrypted === 'string');

    // Decrypt with the server's private key to verify the round-trip
    const privKeyPath = path.join(__dirname, 'keys', 'private.pem');
    const serverPrivateKey = fs.readFileSync(privKeyPath, 'utf8');
    const decrypted = crypto.privateDecrypt(
      { key: serverPrivateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
      Buffer.from(body.encrypted, 'base64')
    );
    const payload = JSON.parse(decrypted.toString('utf8'));
    assert('decrypts to object', typeof payload === 'object');
  }

  // ─── Summary ────────────────────────────────────────────────────────────────

  console.log(`\n${passed + failed} assertions: ${passed} passed, ${failed} failed.\n`);
  if (failed > 0) process.exit(1);
}

run().catch((err) => {
  console.error('\nTest runner error:', err.message);
  console.error('Is the server running?  npm start');
  process.exit(1);
});
