# SecretLink Backend

The backend is a Rust service built with Axum and SQLite. It stores encrypted
shares, manages claim and revoke flows, and serves the frontend assets.

## Responsibilities

- Create shares and persist encrypted payloads plus lifecycle metadata
- Claim, consume, revoke, and expire shares
- Serve the public frontend routes and static assets
- Apply lightweight request rate limiting

## Runtime Configuration

- `SECRETLINK_DATABASE_URL`
  - SQLite connection string
  - Default: `sqlite://secretlink.db`
- `SECRETLINK_BIND_ADDR`
  - bind address for the HTTP server
  - Default: `127.0.0.1:8787`
- `SECRETLINK_WEB_DEV_DIR`
  - optional path to `frontend/public` for serving local frontend files during
    development instead of embedded assets

## Development

Run:

```bash
cargo run --manifest-path backend/Cargo.toml
```

Test:

```bash
cargo test --manifest-path backend/Cargo.toml
```

## SQLite Notes

- The service uses SQLite with WAL mode enabled.
- Shares are stored with status metadata, timestamps, and hashed management or
  claim tokens as needed for the lifecycle flow.
- One-time reveals remove the stored ciphertext after successful consumption.

## Frontend Asset Behavior

- In normal operation, the backend serves embedded copies of the frontend
  assets from the repository source tree.
- In local development, `SECRETLINK_WEB_DEV_DIR` can point at
  `frontend/public`, and the backend will read the matching `frontend/src`
  files from disk when available.
