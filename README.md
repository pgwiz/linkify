# linkify

A Node.js/Express **key-vault demo** that uses RSA public/private key gating to protect a secret JSON payload.

## Concept

- `GET /api/data` — any visitor receives a **cover story** (fictional narrative) from `db.json`.
- `POST /api/data` with `{ "publicKey": "<PEM>" }` — if the submitted public key matches the server's key, the **real secret payload** (from `.env`) is encrypted with that public key and returned as base-64.  Only the holder of the matching private key can decrypt it.

```
Visitor ──── GET /api/data ──────────────────→ { story }
Client  ──── POST /api/data { publicKey } ───→ { encrypted secret } (if key matches)
                                           ───→ { story }            (if key is wrong)
```

## Quick start

```bash
# 1. Install dependencies
npm install

# 2. Generate RSA key pair + create .env
node generate-keys.js

# 3. Start the server
npm start
# → http://localhost:3000
```

## Endpoints

| Method | Path             | Description                                         |
|--------|------------------|-----------------------------------------------------|
| GET    | `/api/data`      | Returns the public "story" from `db.json`           |
| GET    | `/api/public-key`| Returns the server's RSA public key (PEM)           |
| POST   | `/api/data`      | Body `{ publicKey }` – returns encrypted secret or story |

## Project layout

```
.
├── server.js          # Express app
├── generate-keys.js   # RSA key-pair generator + .env bootstrap
├── db.json            # JSON "text database" (story + metadata)
├── .env.example       # Environment variable template
├── public/
│   └── index.html     # Interactive browser demo
├── keys/
│   ├── public.pem     # RSA public key  (committed)
│   └── private.pem    # RSA private key (gitignored – keep secret!)
└── test.js            # Integration tests (node test.js)
```

## Environment variables

| Variable           | Default                  | Description                          |
|--------------------|--------------------------|--------------------------------------|
| `PORT`             | `3000`                   | HTTP port                            |
| `PRIVATE_KEY_PATH` | `keys/private.pem`       | Path to RSA private key              |
| `PUBLIC_KEY_PATH`  | `keys/public.pem`        | Path to RSA public key               |
| `SECRET_DATA`      | `{"api_key":"…","…":"…"}`| JSON string – the real secret payload|

## Running tests

```bash
# In one terminal:
npm start

# In another:
node test.js
```
