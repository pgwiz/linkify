"""
unlock.py
---------
Reads private_rsa.key from the current directory, derives the matching
RSA public key, POSTs it to the Linkify server, then decrypts and prints
the secret payload.

Requirements (install once):
    pip install cryptography requests
"""

import base64
import hashlib
import json
import os
import sys

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# Override with the LINKIFY_SERVER environment variable for local dev or staging.
SERVER = os.environ.get("LINKIFY_SERVER", "https://linkify-ten-sable.vercel.app")

# ── 1. Load the private key (no password on this key) ────────────────────────
try:
    with open("private_rsa.key", "rb") as fh:
        private_key = serialization.load_pem_private_key(fh.read(), password=None)
except FileNotFoundError:
    sys.exit("ERROR: private_rsa.key not found in the current directory.")
except Exception as exc:
    sys.exit(f"ERROR loading private key: {exc}")

# ── 2. Derive the public key in PKCS1 PEM format ─────────────────────────────
public_key_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.PKCS1,
).decode()

# ── 3. Compare fingerprints against the server before posting ─────────────────
def _fingerprint(pem: str) -> str:
    """SHA-256 of the PKCS1 DER form of an RSA public key."""
    key = load_pem_public_key(pem.encode())
    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.PKCS1,
    )
    return hashlib.sha256(der).hexdigest()

print(f"GET  {SERVER}/api/public-key  …")
try:
    pk_resp = requests.get(f"{SERVER}/api/public-key", timeout=20)
    pk_resp.raise_for_status()
    server_pub_pem = pk_resp.json()["publicKey"]
except Exception as exc:
    sys.exit(f"ERROR fetching server public key: {exc}")

server_fp = _fingerprint(server_pub_pem)
local_fp  = _fingerprint(public_key_pem)

if local_fp != server_fp:
    print("\nKey mismatch — your local key pair does not match the server.")
    print("To fix:")
    print("  1. Run:  node generate-keys.js")
    print(f"  2. Set the PUBLIC_KEY environment variable on the server to the")
    print(f"     contents of keys/public.pem, then redeploy.")
    print(f"  3. Copy keys/private.pem → private_rsa.key and retry.")
    print(f"\n  Local  fingerprint: {local_fp}")
    print(f"  Server fingerprint: {server_fp}")
    sys.exit(1)

# ── 4. POST to /api/data ──────────────────────────────────────────────────────
print(f"POST {SERVER}/api/data  …")
resp = requests.post(
    f"{SERVER}/api/data",
    json={"publicKey": public_key_pem},
    timeout=20,
)

body = resp.json()

if resp.status_code == 403:
    print("\nServer rejected the key (unexpected after fingerprint check passed).")
    print("Server returned:", json.dumps(body.get("data"), indent=2))
    sys.exit(1)

if not body.get("ok"):
    print("Server error:", body)
    sys.exit(1)

# ── 5. Decrypt the payload (hybrid RSA-OAEP + AES-256-GCM) ──────────────────
# Step 1: RSA-OAEP-unwrap the AES key
encrypted_key = base64.b64decode(body["encryptedKey"])
aes_key = private_key.decrypt(
    encrypted_key,
    # Node.js RSA_PKCS1_OAEP_PADDING defaults to SHA-1 for hash and MGF1.
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA1(),
        label=None,
    ),
)

# Step 2: AES-256-GCM decrypt the payload
iv         = base64.b64decode(body["iv"])
ciphertext = base64.b64decode(body["ciphertext"])
auth_tag   = base64.b64decode(body["authTag"])

# The `cryptography` AESGCM API expects ciphertext || authTag concatenated.
aesgcm   = AESGCM(aes_key)
plaintext = aesgcm.decrypt(iv, ciphertext + auth_tag, None)

result = json.loads(plaintext.decode("utf-8"))
print("\n✔  Secret payload decrypted successfully:\n")
print(json.dumps(result, indent=2))
