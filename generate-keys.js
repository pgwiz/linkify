#!/usr/bin/env node
/**
 * generate-keys.js
 * Generates a 2048-bit RSA key pair and writes them to the keys/ directory,
 * then writes .env with the paths so the server can load them at runtime.
 *
 * Usage:
 *   node generate-keys.js
 */

'use strict';

const { generateKeyPairSync } = require('crypto');
const fs = require('fs');
const path = require('path');

const KEYS_DIR = path.join(__dirname, 'keys');
const PRIVATE_KEY_FILE = path.join(KEYS_DIR, 'private.pem');
const PUBLIC_KEY_FILE = path.join(KEYS_DIR, 'public.pem');
const ENV_FILE = path.join(__dirname, '.env');

if (!fs.existsSync(KEYS_DIR)) {
  fs.mkdirSync(KEYS_DIR, { recursive: true });
}

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
});

fs.writeFileSync(PRIVATE_KEY_FILE, privateKey, { mode: 0o600 });
fs.writeFileSync(PUBLIC_KEY_FILE, publicKey);

console.log('✔ RSA key pair written to keys/');

// Build .env content, preserving any existing values for non-key entries
let envContent = '';
if (fs.existsSync(ENV_FILE)) {
  // Strip old key-path lines so we don't duplicate them
  envContent = fs
    .readFileSync(ENV_FILE, 'utf8')
    .split('\n')
    .filter((l) => !l.startsWith('PRIVATE_KEY_PATH=') && !l.startsWith('PUBLIC_KEY_PATH='))
    .join('\n')
    .trimEnd();
  envContent += '\n';
}

envContent +=
  `PRIVATE_KEY_PATH=keys/private.pem\n` +
  `PUBLIC_KEY_PATH=keys/public.pem\n`;

// Ensure PORT and SECRET_DATA defaults exist
if (!envContent.includes('PORT=')) envContent += `PORT=3000\n`;
if (!envContent.includes('SECRET_DATA=')) {
  envContent += `SECRET_DATA={"api_key":"sk-prod-abc123xyz","db_password":"super$ecret!","admin_token":"eyJhbGciOiJSUzI1NiJ9.admin"}\n`;
}

fs.writeFileSync(ENV_FILE, envContent);
console.log('✔ .env updated with key paths');
console.log('\nPublic key (share this with clients):\n');
console.log(publicKey);
