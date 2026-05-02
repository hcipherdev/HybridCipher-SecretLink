# HybridCipher SecretLink

SecretLink is a lightweight secret-sharing application with a browser-based UI
and a Rust backend. The browser encrypts the plaintext before upload, then
generates a recipient link and a separate management link.

## Trust Model

- Plaintext is encrypted in the browser before it is sent to the service.
- The recipient decryption key stays in the URL fragment, so it is not part of
  the normal server request path.
- The backend stores encrypted share data, metadata required for share
  lifecycle handling, and management-token verification data.

## Repository Layout

- `frontend/` browser application
- `backend/` Rust + Axum + SQLite service

This public repository contains only the publishable product subset. Private
planning notes, deployment runbooks, and internal-only documentation stay in
the private development repository.

## Quick Start

Backend:

```bash
cargo run --manifest-path backend/Cargo.toml
```

Frontend and integration behavior are served by the backend. By default the
service listens on `127.0.0.1:8787` and uses a local SQLite database file.

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

## Additional Docs

- [Backend notes](backend/README.md)
- [Frontend notes](frontend/README.md)

## License

See [LICENSE](LICENSE).
