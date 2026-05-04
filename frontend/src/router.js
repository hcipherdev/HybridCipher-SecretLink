import { claimShare, consumeShare, createShare, getShareStatus, revokeShare } from './api.js';
import {
    base64UrlToBytes,
    bytesToBase64Url,
    decryptSecret,
    encryptSecret,
    randomSecretBytes,
    randomToken,
    sha256Hex,
} from './crypto.js';

const APP_NAME = 'SecretLink';
const BRAND_LINE = 'by HybridCipher';
const APP_TITLE = `${APP_NAME} ${BRAND_LINE}`;
const SUPPORT_EMAIL = 'support@hybridcipher.com';
const GITHUB_URL = 'https://github.com/hcipherdev/HybridCipher-SecretLink';
const PLAINTEXT_LIMIT = 64 * 1024;
const EXPIRY_PRESETS = {
    '1h': { label: '1 hour', hours: 1 },
    '24h': { label: '24 hours', hours: 24 },
    '7d': { label: '7 days', hours: 24 * 7 },
};
const AAD_VERSION = 1;

const SHARED_NAV_MODEL = {
    home: { label: 'Home', href: '/' },
    howItWorks: { label: 'How It Works', href: '/how-it-works' },
    github: { label: 'GitHub', href: GITHUB_URL },
};

const HOME_PAGE_CONTENT = {
    trustLabel: 'Zero-trust secret sharing',
    trustBody: 'Encrypted in your browser before it reaches the server.',
    title: APP_NAME,
    lede: 'Create a secure share in seconds. SecretLink encrypts your secret locally, then gives you a recipient link plus a separate management link.',
};

const HOW_IT_WORKS_PAGE = {
    title: 'How It Works',
    lede: 'SecretLink is built to keep the working surface simple while making the trust boundary clear.',
    sections: [
        {
            heading: '1. Encrypt in your browser',
            items: [
                'Your secret is encrypted in the browser before it is sent anywhere. The server receives encrypted data, not the plaintext.',
                'The decryption key stays in the recipient link fragment so it is not included in normal server requests.',
            ],
        },
        {
            heading: '2. Send the recipient link',
            items: [
                'After a share is created, send the recipient link to the person who should read the secret and keep the separate management link for yourself.',
                'The recipient link is used to reveal the secret, while the management link lets you inspect share status or revoke access.',
            ],
        },
        {
            heading: '3. Reveal once or until expiry',
            items: [
                'A one-time share is consumed after the first successful reveal. A reusable share stays available until it expires or you revoke it.',
                'SecretLink can also expire a share automatically, so older secrets do not stay available indefinitely.',
            ],
        },
        {
            heading: 'What the server stores',
            items: [
                'The service stores encrypted secret data, share IDs, management-link verification data, timestamps, and status details needed to run the share lifecycle.',
                'The service does not receive your plaintext secret during normal operation, and it cannot reveal a secret without both the stored encrypted data and the browser-held key.',
            ],
        },
    ],
};

const LEGAL_PAGES = {
    privacy: {
        title: 'Privacy',
        lede: 'SecretLink is a lightweight encrypted secret-sharing service. The service is designed to work without user accounts, marketing trackers, or ad tech.',
        sections: [
            {
                heading: 'What the service handles',
                items: [
                    'The service stores encrypted secrets, share IDs, management-link verification data, timestamps, and basic share status details needed to create, reveal, revoke, and expire shares.',
                    'SecretLink and the companies that help run it may also receive standard service information such as IP address, time of request, browser details, and error information to keep the service running and protect it from abuse.',
                ],
            },
            {
                heading: 'What the service does not do',
                items: [
                    'SecretLink has no user accounts, no saved profiles, no marketing emails, no payment collection, and no third-party analytics or ad trackers in the product UI.',
                    'SecretLink does not use cookies in the application flow.',
                ],
            },
            {
                heading: 'Retention and deletion',
                items: [
                    'Encrypted secrets are deleted when a one-time share is opened, when a share is revoked, or when a share expires.',
                    'Records showing whether a share was expired, opened, or revoked may remain for a limited time, and standard service logs may be kept longer.',
                ],
            },
            {
                heading: 'Hosting and contact',
                items: [
                    'SecretLink uses service providers that help host, secure, and deliver the service.',
                    `For privacy or support questions about this service, contact ${SUPPORT_EMAIL}.`,
                ],
            },
        ],
    },
    terms: {
        title: 'Terms',
        lede: 'These terms apply to the public SecretLink service. The service is offered as a simple, anonymous utility for sharing encrypted secrets.',
        sections: [
            {
                heading: 'Acceptable use',
                items: [
                    'Use the service only for lawful secrets, credentials, notes, and configuration fragments that you are allowed to share.',
                    'Prohibited content includes malware, phishing material, stolen credentials, illegal content, abusive material, and anything intended to harm systems or people.',
                ],
            },
            {
                heading: 'Service behavior',
                items: [
                    'Shares can expire, be revoked, or be consumed after retrieval depending on how the sender configures them.',
                    'The service is provided as an anonymous public tool with no user accounts, no guaranteed history, and no promise that an unread share will remain available for any minimum period.',
                ],
            },
            {
                heading: 'Availability and warranty',
                items: [
                    'The service may be changed, paused, temporarily limited, or removed at any time, with or without notice.',
                    'The service is provided on an "as is" and "as available" basis, with no warranty that delivery, retention, or access will be uninterrupted, error-free, or fit for any particular purpose.',
                ],
            },
            {
                heading: 'Enforcement and liability',
                items: [
                    'HybridCipher may suspend access or remove data when needed to protect the service or respond to abuse, security, or legal issues.',
                    'To the maximum extent allowed by applicable law, HybridCipher disclaims indirect, incidental, special, consequential, and punitive damages, and limits liability arising from use of the service.',
                    `Questions about these terms can be sent to ${SUPPORT_EMAIL}.`,
                ],
            },
        ],
    },
};

export function routeKindFromPath(pathname) {
    const normalizedPath = normalizePath(pathname);
    if (normalizedPath === '/how-it-works') {
        return 'how-it-works';
    }
    if (normalizedPath === '/privacy') {
        return 'privacy';
    }
    if (normalizedPath === '/terms') {
        return 'terms';
    }
    if (normalizedPath.startsWith('/manage/')) {
        return 'manage';
    }
    if (normalizedPath.startsWith('/s/')) {
        return 'reveal';
    }
    return 'create';
}

export function readFragmentToken(hash) {
    const value = String(hash || '').replace(/^#/, '').trim();
    return value.length > 0 ? value : null;
}

export function buildShareLinks({ origin, shareId, contentKey, adminToken }) {
    const normalizedOrigin = String(origin || '').replace(/\/$/, '');
    return {
        recipient: `${normalizedOrigin}/s/${shareId}#${contentKey}`,
        manage: `${normalizedOrigin}/manage/${shareId}#${adminToken}`,
    };
}

export function getLegalPage(kind) {
    return LEGAL_PAGES[kind] || null;
}

export function getSharedNavModel() {
    return SHARED_NAV_MODEL;
}

export function getHomePageContent() {
    return HOME_PAGE_CONTENT;
}

export function getHowItWorksPage() {
    return HOW_IT_WORKS_PAGE;
}

export function renderRoute(root, location) {
    const kind = routeKindFromPath(location.pathname);
    const currentPath = normalizePath(location.pathname);
    setDocumentTitle(APP_TITLE);

    if (kind === 'how-it-works') {
        renderHowItWorksView(root, currentPath);
        return;
    }
    if (kind === 'privacy' || kind === 'terms') {
        renderLegalView(root, kind, currentPath);
        return;
    }
    if (kind === 'manage') {
        renderManageView(root, location, currentPath);
        return;
    }
    if (kind === 'reveal') {
        renderRevealView(root, location, currentPath);
        return;
    }
    renderCreateView(root, location, currentPath);
}

function renderCreateView(root, location, currentPath) {
    const home = getHomePageContent();

    root.innerHTML = renderPageShell({
        currentPath,
        title: home.title,
        lede: home.lede,
        trustBand: `
            <div class="trust-band">
                <p class="trust-band__label">${home.trustLabel}</p>
                <p class="trust-band__body">${home.trustBody}</p>
            </div>
        `,
        content: `
            <form class="form-grid" data-role="create-form">
                <div class="field">
                    <label for="secret-input">Secret</label>
                    <textarea id="secret-input" name="secret" maxlength="${PLAINTEXT_LIMIT}" placeholder="Paste a password, API key, JSON snippet, or config text."></textarea>
                    <p class="helper">Maximum plaintext size: 64 KiB. Plaintext never leaves this browser.</p>
                </div>
                <div class="field">
                    <label for="expiry-select">Expiry</label>
                    <select id="expiry-select" name="expiry">
                        ${Object.entries(EXPIRY_PRESETS)
                            .map(([value, preset]) => `<option value="${value}"${value === '24h' ? ' selected' : ''}>${preset.label}</option>`)
                            .join('')}
                    </select>
                </div>
                <div class="toggle-row">
                    <input id="one-time" name="one_time" type="checkbox" checked>
                    <label class="toggle" for="one-time">One-time retrieval</label>
                </div>
                <p class="warning">One-time retrieval blocks repeated access through the service. It does not prevent screenshots or copying during the first reveal.</p>
                <div class="actions">
                    <button class="button-primary" type="submit">Create share</button>
                </div>
                <p class="status-line" data-role="status-line"></p>
            </form>
            <section class="result-card stack" data-role="result-card" hidden>
                <h2>Share created</h2>
                <div class="output-block">
                    <label for="recipient-link">Recipient link</label>
                    <textarea id="recipient-link" readonly></textarea>
                    <div class="output-actions">
                        <button class="button-secondary" type="button" data-copy-target="recipient-link">Copy recipient link</button>
                    </div>
                </div>
                <div class="output-block">
                    <label for="manage-link">Management link</label>
                    <textarea id="manage-link" readonly></textarea>
                    <div class="output-actions">
                        <button class="button-secondary" type="button" data-copy-target="manage-link">Copy management link</button>
                    </div>
                </div>
                <p class="meta">Keep the management link private. It is the only way to revoke or inspect the share later.</p>
            </section>
        `,
    });

    const form = root.querySelector('[data-role="create-form"]');
    const secretInput = root.querySelector('#secret-input');
    const expirySelect = root.querySelector('#expiry-select');
    const oneTimeInput = root.querySelector('#one-time');
    const statusLine = root.querySelector('[data-role="status-line"]');
    const resultCard = root.querySelector('[data-role="result-card"]');
    const recipientLink = root.querySelector('#recipient-link');
    const manageLink = root.querySelector('#manage-link');

    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        const secret = secretInput.value;
        if (!secret.trim()) {
            setStatus(statusLine, 'Enter a secret before creating a share.', 'error');
            return;
        }
        if (new TextEncoder().encode(secret).length > PLAINTEXT_LIMIT) {
            setStatus(statusLine, 'Secret exceeds the 64 KiB plaintext limit.', 'error');
            return;
        }

        toggleDisabled(form, true);
        setStatus(statusLine, 'Encrypting locally and creating share...');

        try {
            const shareId = crypto.randomUUID();
            const expiresAt = new Date(Date.now() + expiryOffsetMs(expirySelect.value)).toISOString();
            const contentKey = randomSecretBytes(32);
            const adminToken = randomToken(32);
            const encrypted = await encryptSecret(secret, contentKey, {
                shareId,
                expiresAt,
                aadVersion: AAD_VERSION,
            });
            const adminTokenHash = await sha256Hex(adminToken);

            await createShare({
                share_id: shareId,
                ciphertext_b64: bytesToBase64Url(encrypted.ciphertext),
                nonce_b64: bytesToBase64Url(encrypted.iv),
                expires_at: expiresAt,
                one_time: oneTimeInput.checked,
                aad_version: AAD_VERSION,
                admin_token_hash: adminTokenHash,
            });

            const links = buildShareLinks({
                origin: location.origin,
                shareId,
                contentKey: bytesToBase64Url(contentKey),
                adminToken,
            });
            recipientLink.value = links.recipient;
            manageLink.value = links.manage;
            resultCard.hidden = false;
            secretInput.value = '';
            setStatus(statusLine, 'Share created. Send the recipient link and keep the management link private.', 'success');
        } catch (error) {
            setStatus(statusLine, describeError(error), 'error');
        } finally {
            toggleDisabled(form, false);
        }
    });

    root.querySelectorAll('[data-copy-target]').forEach((button) => {
        const originalLabel = button.textContent;
        button.addEventListener('click', async () => {
            const target = root.querySelector(`#${button.getAttribute('data-copy-target')}`);
            if (!target?.value) {
                return;
            }
            try {
                await navigator.clipboard.writeText(target.value);
                button.textContent = 'Copied!';
                button.classList.add('is-copied');
                setStatus(statusLine, 'Copied to clipboard.', 'success');
                setTimeout(() => {
                    button.textContent = originalLabel;
                    button.classList.remove('is-copied');
                }, 1200);
            } catch (error) {
                setStatus(statusLine, 'Could not access the clipboard in this browser.', 'error');
            }
        });
    });
}

function renderRevealView(root, location, currentPath) {
    const shareId = location.pathname.split('/').pop();
    root.innerHTML = renderPageShell({
        currentPath,
        title: 'Reveal secret',
        lede: 'Opening this page does not burn the secret. The share is only claimed when you explicitly reveal it.',
        content: `
            <div class="actions">
                <button class="button-primary" type="button" data-role="reveal-button">Reveal secret</button>
            </div>
            <p class="status-line" data-role="status-line"></p>
            <pre class="secret-output" data-role="secret-output" hidden></pre>
        `,
    });

    const revealButton = root.querySelector('[data-role="reveal-button"]');
    const statusLine = root.querySelector('[data-role="status-line"]');
    const secretOutput = root.querySelector('[data-role="secret-output"]');

    revealButton.addEventListener('click', async () => {
        const fragment = readFragmentToken(location.hash);
        if (!fragment) {
            setStatus(statusLine, 'This link is missing its decryption fragment.', 'error');
            return;
        }

        revealButton.disabled = true;
        setStatus(statusLine, 'Requesting encrypted payload...');
        secretOutput.hidden = true;

        try {
            const response = await claimShare(shareId);
            const plaintext = await decryptSecret(
                base64UrlToBytes(response.ciphertext_b64),
                base64UrlToBytes(response.nonce_b64),
                base64UrlToBytes(fragment),
                {
                    shareId,
                    expiresAt: response.expires_at,
                    aadVersion: response.aad_version,
                }
            );

            secretOutput.textContent = plaintext;
            secretOutput.hidden = false;

            if (response.claim_token) {
                await consumeShare(shareId, response.claim_token);
                setStatus(statusLine, 'Secret revealed. This one-time share is now consumed.', 'success');
            } else {
                setStatus(statusLine, 'Secret revealed. This share remains available until it expires or is revoked.', 'success');
            }
        } catch (error) {
            if (error?.status === 404) {
                setStatus(statusLine, 'This share is unavailable. It may have expired, been revoked, or already been consumed.', 'error');
            } else if (error?.name === 'OperationError') {
                setStatus(statusLine, 'Decryption failed. The link fragment may be incomplete or invalid.', 'error');
            } else {
                setStatus(statusLine, describeError(error), 'error');
            }
        } finally {
            revealButton.disabled = false;
        }
    });
}

function renderManageView(root, location, currentPath) {
    const shareId = location.pathname.split('/').pop();
    root.innerHTML = renderPageShell({
        currentPath,
        title: 'Manage share',
        lede: 'Use this private link to inspect status or revoke future access.',
        content: `
            <div class="actions">
                <button class="button-secondary" type="button" data-role="refresh-button">Refresh status</button>
                <button class="button-danger" type="button" data-role="revoke-button">Revoke share</button>
            </div>
            <p class="status-line" data-role="status-line"></p>
            <section class="info-card stack" data-role="status-card" hidden>
                <span class="pill" data-role="state-pill"></span>
                <div class="meta-grid">
                    <div><strong>Expires</strong><span data-role="expires-at"></span></div>
                    <div><strong>One-time</strong><span data-role="one-time"></span></div>
                    <div><strong>Updated</strong><span data-role="updated-at"></span></div>
                </div>
            </section>
        `,
    });

    const refreshButton = root.querySelector('[data-role="refresh-button"]');
    const revokeButton = root.querySelector('[data-role="revoke-button"]');
    const statusLine = root.querySelector('[data-role="status-line"]');
    const statusCard = root.querySelector('[data-role="status-card"]');
    const statePill = root.querySelector('[data-role="state-pill"]');
    const expiresAt = root.querySelector('[data-role="expires-at"]');
    const oneTime = root.querySelector('[data-role="one-time"]');
    const updatedAt = root.querySelector('[data-role="updated-at"]');
    const adminToken = readFragmentToken(location.hash);

    async function refresh() {
        if (!adminToken) {
            setStatus(statusLine, 'This management link is missing its admin fragment.', 'error');
            revokeButton.disabled = true;
            return;
        }

        refreshButton.disabled = true;
        setStatus(statusLine, 'Loading share status...');

        try {
            const data = await getShareStatus(shareId, adminToken);
            statusCard.hidden = false;
            statePill.textContent = data.status;
            statePill.dataset.status = data.status;
            expiresAt.textContent = formatDateTime(data.expires_at);
            oneTime.textContent = data.one_time ? 'Yes' : 'No';
            updatedAt.textContent = formatDateTime(data.updated_at);
            revokeButton.disabled = !['available', 'claimed'].includes(data.status);
            setStatus(statusLine, 'Management state loaded.', 'success');
        } catch (error) {
            statusCard.hidden = true;
            revokeButton.disabled = true;
            setStatus(statusLine, describeError(error), 'error');
        } finally {
            refreshButton.disabled = false;
        }
    }

    refreshButton.addEventListener('click', refresh);
    revokeButton.addEventListener('click', async () => {
        if (!adminToken) {
            return;
        }
        revokeButton.disabled = true;
        setStatus(statusLine, 'Revoking share...');
        try {
            await revokeShare(shareId, adminToken);
            setStatus(statusLine, 'Share revoked. Future retrievals are blocked.', 'success');
            await refresh();
        } catch (error) {
            setStatus(statusLine, describeError(error), 'error');
            revokeButton.disabled = false;
        }
    });

    refresh();
}

function renderHowItWorksView(root, currentPath) {
    const page = getHowItWorksPage();
    root.innerHTML = renderPageShell({
        currentPath,
        title: page.title,
        lede: page.lede,
        content: renderSectionStack(page.sections, 'how-it-works'),
    });
}

function renderLegalView(root, kind, currentPath) {
    const page = getLegalPage(kind);
    root.innerHTML = renderPageShell({
        currentPath,
        title: page.title,
        lede: page.lede,
        content: renderSectionStack(page.sections, 'legal-copy'),
    });
}

function renderSectionStack(sections, className) {
    return `
        <div class="${className} stack">
            ${sections
                .map(
                    (section) => `
                        <section class="content-section stack">
                            <h2>${section.heading}</h2>
                            ${section.items.map((item) => `<p>${item}</p>`).join('')}
                        </section>
                    `
                )
                .join('')}
        </div>
    `;
}

function renderPageShell({ currentPath, title, lede, trustBand = '', content }) {
    return `
        <div class="site-frame">
            ${renderSiteHeader(currentPath)}
            <main class="site-main">
                <section class="shell stack">
                    <div class="stack">
                        <div class="brand-lockup">
                            <p class="eyebrow">${APP_NAME}</p>
                            <p class="brand-line">${BRAND_LINE}</p>
                        </div>
                        ${trustBand}
                        <div class="stack stack--compact">
                            <h1>${title}</h1>
                            <p class="lede">${lede}</p>
                        </div>
                    </div>
                    ${content}
                    <footer class="site-footer">
                        <span class="footer-brand">${APP_TITLE}</span>
                        <nav class="footer-nav" aria-label="Legal">
                            <a href="/privacy">Privacy</a>
                            <a href="/terms">Terms</a>
                        </nav>
                    </footer>
                </section>
            </main>
        </div>
    `;
}

function renderSiteHeader(currentPath) {
    const nav = getSharedNavModel();
    const homeActive = currentPath === '/';
    const howItWorksActive = currentPath === nav.howItWorks.href;

    return `
        <header class="site-header">
            <div class="site-header__inner">
                <a class="site-brand" href="${nav.home.href}" aria-label="${APP_TITLE}">
                    <span class="site-brand__title">${APP_NAME}</span>
                    <span class="site-brand__subtitle">${BRAND_LINE}</span>
                </a>
                <nav class="site-nav" aria-label="Primary">
                    <a class="site-nav__link${homeActive ? ' is-active' : ''}" href="${nav.home.href}">${nav.home.label}</a>
                    <a class="site-nav__link${howItWorksActive ? ' is-active' : ''}" href="${nav.howItWorks.href}">${nav.howItWorks.label}</a>
                </nav>
                <a class="github-link" href="${nav.github.href}" target="_blank" rel="noreferrer noopener" aria-label="${nav.github.label}">
                    ${renderGitHubIcon()}
                    <span class="github-link__label">${nav.github.label}</span>
                </a>
            </div>
        </header>
    `;
}

function renderGitHubIcon() {
    return `
        <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
            <path fill="currentColor" d="M12 2C6.48 2 2 6.58 2 12.22c0 4.51 2.87 8.34 6.84 9.69.5.1.68-.22.68-.49 0-.24-.01-1.04-.01-1.88-2.78.62-3.37-1.21-3.37-1.21-.45-1.18-1.11-1.49-1.11-1.49-.91-.64.07-.63.07-.63 1 .07 1.53 1.05 1.53 1.05.9 1.56 2.35 1.11 2.92.85.09-.67.35-1.11.64-1.37-2.22-.26-4.55-1.14-4.55-5.08 0-1.12.39-2.04 1.03-2.76-.1-.26-.45-1.3.1-2.72 0 0 .84-.27 2.75 1.05A9.3 9.3 0 0 1 12 6.84c.85 0 1.71.12 2.51.36 1.91-1.32 2.75-1.05 2.75-1.05.55 1.42.2 2.46.1 2.72.64.72 1.03 1.64 1.03 2.76 0 3.95-2.34 4.82-4.57 5.07.36.32.68.94.68 1.9 0 1.37-.01 2.47-.01 2.81 0 .27.18.6.69.49A10.16 10.16 0 0 0 22 12.22C22 6.58 17.52 2 12 2Z"/>
        </svg>
    `;
}

function normalizePath(pathname) {
    const normalized = String(pathname || '/').replace(/\/+$/, '');
    return normalized || '/';
}

function setDocumentTitle(title) {
    if (typeof document !== 'undefined') {
        document.title = title;
    }
}

function toggleDisabled(container, disabled) {
    container.querySelectorAll('button, textarea, select, input').forEach((element) => {
        element.disabled = disabled;
    });
}

function setStatus(element, message, tone = 'idle') {
    element.textContent = message;
    element.dataset.tone = tone;
}

function expiryOffsetMs(preset) {
    const selected = EXPIRY_PRESETS[preset] || EXPIRY_PRESETS['24h'];
    return selected.hours * 60 * 60 * 1000;
}

function formatDateTime(value) {
    return new Date(value).toLocaleString();
}

function describeError(error) {
    if (error?.payload?.message) {
        return error.payload.message;
    }
    if (error?.payload?.error === 'share_unavailable') {
        return 'This share is unavailable.';
    }
    if (error?.payload?.error) {
        return error.payload.error.replace(/_/g, ' ');
    }
    if (error instanceof Error && error.message) {
        return error.message;
    }
    return 'Something went wrong.';
}
