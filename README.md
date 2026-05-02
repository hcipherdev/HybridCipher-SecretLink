# HybridCipher SecretLink

Share sensitive text, credentials, and configuration fragments without dropping
plaintext into chat, email, or ticket systems.

SecretLink is a lightweight secret-sharing application with browser-side
encryption, a clean recipient flow, and a separate management link for status
checks or revocation. It is built for teams that need a fast way to hand off
secrets while keeping the trust boundary explicit.

## Why SecretLink

- Encrypt in the browser before upload
- Send a recipient link without exposing the key in the request path
- Revoke access or inspect status with a separate management link
- Support one-time retrieval or expiry-based sharing with a small operational
  footprint

## How It Works

1. The sender enters a secret in the browser.
2. SecretLink encrypts that plaintext locally before it is sent to the server.
3. The app generates:
   - a recipient link containing the decryption key in the URL fragment
   - a separate management link for revoke and status actions
4. The backend stores encrypted share data plus the metadata required to manage
   the share lifecycle.

## Security Model

- A fresh 32-byte secret key is generated in the browser for each share.
- The plaintext is encrypted locally with WebCrypto `AES-256-GCM` before upload.
- A random nonce is generated per encryption operation.
- Share metadata such as share ID and expiry are bound into the ciphertext as
  additional authenticated data, so tampering breaks decryption.
- The backend stores ciphertext, nonce, expiry, status metadata, and hashed
  management credentials. It does not store the recipient decryption key.
- The recipient key lives in the URL fragment, which is intended to keep it out
  of the normal request path seen by the server.

## Trust Model

- Plaintext is encrypted in the browser before it is sent to the service.
- The recipient decryption key stays in the URL fragment, so it is not part of
  the normal server request path.
- The backend stores encrypted share data, metadata required for share
  lifecycle handling, and management-token verification data.

## Why We Describe SecretLink As Quantum-Resistant

SecretLink uses 256-bit symmetric encryption for the secret payload. That is a
meaningfully different security posture from systems that depend on classical
public-key cryptography for payload confidentiality.

- Known quantum attacks are far more damaging to common public-key systems than
  to large-key symmetric encryption.
- For symmetric key search, the usual quantum discussion is a square-root style
  speedup rather than a complete break.
- As a result, 256-bit symmetric encryption is commonly treated as retaining a
  very large security margin, often described as roughly 128-bit brute-force
  strength even in the presence of that known quantum speedup model.

## Technical Snapshot

- Frontend: plain JavaScript browser application
- Backend: Rust, Axum, SQLite
- Share controls: one-time retrieval, explicit reveal flow, revocation, expiry
- Public surfaces: create, reveal, manage, explainer, privacy, and terms pages

## Repository Layout

- `frontend/` browser application
- `backend/` Rust + Axum + SQLite service

This public repository contains only the publishable product subset. Private
planning notes, deployment runbooks, and internal-only documentation stay in
the private development repository.

## Quick Start

Run the backend:

```bash
cargo run --manifest-path backend/Cargo.toml
```

The backend serves the frontend and API together. By default it listens on
`127.0.0.1:8787` and uses a local SQLite database file.

Useful environment variables:

- `SECRETLINK_DATABASE_URL` for the SQLite connection string
- `SECRETLINK_BIND_ADDR` for the HTTP bind address
- `SECRETLINK_WEB_DEV_DIR` to serve local frontend files during development

## Test

```bash
cargo test --manifest-path backend/Cargo.toml
cd frontend && node --test tests/*.test.js
```

Optional browser smoke tests:

```bash
cd frontend
npm install
npx playwright install
npx playwright test
```

## Intended Use

SecretLink is well suited for:

- temporary password delivery
- API key handoff
- secure transfer of config snippets or JSON payloads
- any case where the sender wants a narrow, auditable sharing flow instead of
  pasting secrets into general collaboration tools

## Additional Docs

- [Backend notes](backend/README.md)
- [Frontend notes](frontend/README.md)

## License

See [LICENSE](LICENSE).
