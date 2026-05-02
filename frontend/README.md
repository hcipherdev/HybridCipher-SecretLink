# SecretLink Frontend

The frontend is a small browser application that handles encryption,
decryption, and the public product flows for creating, revealing, and managing
shares.

## Responsibilities

- Encrypt plaintext in the browser before upload
- Keep the recipient decryption key in the URL fragment
- Generate recipient and management links
- Render the create, reveal, management, explainer, privacy, and terms views

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
