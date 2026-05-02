# SecretLink Frontend

The frontend is a small browser application that handles encryption,
decryption, and the public product flows for creating, revealing, and managing
shares.

## Responsibilities

- Encrypt plaintext in the browser before upload
- Keep the recipient decryption key in the URL fragment
- Generate recipient and management links
- Render the create, reveal, management, explainer, privacy, and terms views

## Encryption Details

- The browser generates a fresh 32-byte content key for each share.
- Encryption uses WebCrypto `AES-256-GCM`.
- A random nonce is generated for each encryption operation.
- Share ID, expiry timestamp, and AAD version are included as authenticated
  metadata during encryption and decryption.
- The recipient decrypts locally in the browser using the key stored in the URL
  fragment.

## Quantum-Resistance Claim

SecretLink's quantum-resistance claim is specifically about payload encryption.
The share content is protected with 256-bit symmetric cryptography, which is
substantially more resilient to known quantum attacks than classical public-key
confidentiality schemes.

## Route Surfaces

- `/` create a share
- `/s/:id` open a recipient view and reveal on explicit action
- `/manage/:id` inspect status or revoke access using the management fragment
- `/how-it-works` public trust-boundary explainer
- `/privacy` privacy notice
- `/terms` terms of service

## Development

Run unit tests:

```bash
cd frontend
node --test tests/*.test.js
```

Run browser smoke tests:

```bash
cd frontend
npm install
npx playwright install
npx playwright test
```

The frontend is served by the backend during development and production.
