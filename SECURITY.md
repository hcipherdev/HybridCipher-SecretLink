# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in SecretLink, please report it
responsibly. Do not open a public issue.

Send an email to **support@hybridcipher.com** with:

- A description of the vulnerability
- Steps to reproduce, if possible
- Any relevant logs, screenshots, or proof-of-concept code

We will acknowledge receipt within 3 business days and aim to provide an
initial assessment within 10 business days.

## Scope

This policy covers the SecretLink application code in this repository,
including the Rust backend, the JavaScript frontend, and the cryptographic
flows between them.

Infrastructure, hosting, and third-party dependencies are handled separately.

## Encryption Details

SecretLink encrypts share payloads with AES-256-GCM using the WebCrypto API
in the browser. The 32-byte content key is generated per share and delivered
to the recipient via the URL fragment, which is not sent to the server in
normal HTTP requests. Share metadata (share ID, expiry, AAD version) is bound
as authenticated data during encryption.

For more details, see the [How It Works](https://secretlink.hybridcipher.com/how-it-works)
page or the project [README](README.md).
