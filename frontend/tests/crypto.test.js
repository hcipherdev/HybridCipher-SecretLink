import test from 'node:test';
import assert from 'node:assert/strict';

import * as cryptoModule from '../src/crypto.js';

test('base64url helpers round-trip arbitrary bytes', () => {
    const input = Uint8Array.from([0, 1, 2, 3, 250, 251, 252, 253, 254, 255]);

    const encoded = cryptoModule.bytesToBase64Url(input);
    const decoded = cryptoModule.base64UrlToBytes(encoded);

    assert.equal(encoded, 'AAECA_r7_P3-_w');
    assert.deepEqual(Array.from(decoded), Array.from(input));
});

test('createAad produces stable structured metadata bytes', () => {
    const aadBytes = cryptoModule.createAad({
        shareId: 'share-123',
        expiresAt: '2026-05-01T12:00:00Z',
        aadVersion: 1,
    });

    assert.equal(
        new TextDecoder().decode(aadBytes),
        '{"share_id":"share-123","expires_at":"2026-05-01T12:00:00Z","aad_version":1}'
    );
});

test('encryptSecret and decryptSecret round-trip plaintext with metadata-bound aad', async () => {
    const keyBytes = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
    const metadata = {
        shareId: 'share-roundtrip',
        expiresAt: '2026-05-01T12:00:00Z',
        aadVersion: 1,
    };

    const encrypted = await cryptoModule.encryptSecret('top secret value', keyBytes, metadata);
    const decrypted = await cryptoModule.decryptSecret(
        encrypted.ciphertext,
        encrypted.iv,
        keyBytes,
        metadata
    );

    assert.equal(decrypted, 'top secret value');
});

test('sha256Hex returns lowercase hex digest', async () => {
    const digest = await cryptoModule.sha256Hex('admin-token');
    assert.equal(digest.length, 64);
    assert.match(digest, /^[0-9a-f]{64}$/);
});
