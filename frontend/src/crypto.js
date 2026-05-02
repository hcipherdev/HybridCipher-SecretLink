function asUint8Array(input) {
    return input instanceof Uint8Array ? input : new Uint8Array(input);
}

export function bytesToBase64Url(bytes) {
    const view = asUint8Array(bytes);
    if (typeof Buffer !== 'undefined') {
        return Buffer.from(view)
            .toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/g, '');
    }

    let binary = '';
    for (const byte of view) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function base64UrlToBytes(value) {
    const normalized = String(value || '')
        .replace(/-/g, '+')
        .replace(/_/g, '/')
        .padEnd(Math.ceil(String(value || '').length / 4) * 4, '=');

    if (typeof Buffer !== 'undefined') {
        return new Uint8Array(Buffer.from(normalized, 'base64'));
    }

    const binary = atob(normalized);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
        bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
}

export async function sha256Hex(input) {
    const bytes = new TextEncoder().encode(String(input));
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function randomSecretBytes(length = 32) {
    return crypto.getRandomValues(new Uint8Array(length));
}

export function randomToken(length = 32) {
    return bytesToBase64Url(randomSecretBytes(length));
}

export function createAad({ shareId, expiresAt, aadVersion }) {
    if (!shareId || !expiresAt || !aadVersion) {
        throw new Error('shareId, expiresAt, and aadVersion are required');
    }

    return new TextEncoder().encode(
        JSON.stringify({
            share_id: shareId,
            expires_at: expiresAt,
            aad_version: aadVersion,
        })
    );
}

export async function encryptSecret(plaintext, keyBytes, metadata) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
    const aad = createAad(metadata);
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: aad },
        key,
        new TextEncoder().encode(plaintext)
    );

    return {
        iv,
        ciphertext: new Uint8Array(ciphertext),
    };
}

export async function decryptSecret(ciphertextBytes, ivBytes, keyBytes, metadata) {
    const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
    const aad = createAad(metadata);
    const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: ivBytes, additionalData: aad },
        key,
        ciphertextBytes
    );

    return new TextDecoder().decode(plaintext);
}
