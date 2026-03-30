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
import json
import os
import sys

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

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

# ── 3. POST to /api/data ──────────────────────────────────────────────────────
print(f"POST {SERVER}/api/data  …")
resp = requests.post(
    f"{SERVER}/api/data",
    json={"publicKey": public_key_pem},
    timeout=20,
)

body = resp.json()

if resp.status_code == 403:
    print("\nServer says: Public key does not match.")
    print("The private_rsa.key you have does NOT correspond to the key Vercel was")
    print("configured with.  Retrieve the correct private key from Vercel first.")
    print("\nServer also returned the public story:")
    print(json.dumps(body.get("data"), indent=2))
    sys.exit(1)

if not body.get("ok"):
    print("Server error:", body)
    sys.exit(1)

# ── 4. Decrypt the payload ────────────────────────────────────────────────────
ciphertext = base64.b64decode(body["encrypted"])

plaintext = private_key.decrypt(
    ciphertext,
    # SHA-1 is required here: Node.js crypto.publicEncrypt with
    # RSA_PKCS1_OAEP_PADDING defaults to SHA-1 for both the hash and MGF1.
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA1(),
        label=None,
    ),
)

result = json.loads(plaintext.decode("utf-8"))
print("\n✔  Secret payload decrypted successfully:\n")
print(json.dumps(result, indent=2))
