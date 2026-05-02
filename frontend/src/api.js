export async function jsonRequest(url, options = {}) {
    const { body, headers, ...rest } = options;
    const response = await fetch(url, {
        credentials: 'same-origin',
        ...rest,
        headers: {
            ...(body ? { 'content-type': 'application/json' } : {}),
            ...(headers || {}),
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
    });

    const text = await response.text();
    const data = text ? JSON.parse(text) : null;
    if (!response.ok) {
        const error = new Error(data?.error || 'request_failed');
        error.status = response.status;
        error.payload = data;
        throw error;
    }
    return data;
}

export function createShare(payload) {
    return jsonRequest('/api/v1/shares', {
        method: 'POST',
        body: payload,
    });
}

export function claimShare(shareId) {
    return jsonRequest(`/api/v1/shares/${encodeURIComponent(shareId)}/claim`, {
        method: 'POST',
        body: {},
    });
}

export function consumeShare(shareId, claimToken) {
    return jsonRequest(`/api/v1/shares/${encodeURIComponent(shareId)}/consume`, {
        method: 'POST',
        body: { claim_token: claimToken },
    });
}

export function revokeShare(shareId, adminToken) {
    return jsonRequest(`/api/v1/shares/${encodeURIComponent(shareId)}/revoke`, {
        method: 'POST',
        body: { admin_token: adminToken },
    });
}

export function getShareStatus(shareId, adminToken) {
    return jsonRequest(`/api/v1/shares/${encodeURIComponent(shareId)}/status`, {
        method: 'GET',
        headers: {
            'x-secretlink-admin-token': adminToken,
        },
    });
}
