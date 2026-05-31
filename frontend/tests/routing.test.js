import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import * as routerModule from '../src/router.js';
import * as cryptoModule from '../src/crypto.js';

test('buildShareLinks keeps secrets in fragments instead of request paths', () => {
    const links = routerModule.buildShareLinks({
        origin: 'https://secretlink.example',
        shareId: 'share-abc',
        contentKey: 'recipient-fragment',
        adminToken: 'admin-fragment',
    });

    assert.equal(links.recipient, 'https://secretlink.example/s/share-abc#recipient-fragment');
    assert.equal(links.manage, 'https://secretlink.example/manage/share-abc#admin-fragment');
});

test('readFragmentToken strips leading hash and handles empty fragments', () => {
    assert.equal(routerModule.readFragmentToken('#secret-fragment'), 'secret-fragment');
    assert.equal(routerModule.readFragmentToken(''), null);
    assert.equal(routerModule.readFragmentToken('#'), null);
});

test('routeKindFromPath distinguishes create, reveal, and manage surfaces', () => {
    assert.equal(routerModule.routeKindFromPath('/'), 'create');
    assert.equal(routerModule.routeKindFromPath('/s/share-1'), 'reveal');
    assert.equal(routerModule.routeKindFromPath('/manage/share-1'), 'manage');
    assert.equal(routerModule.routeKindFromPath('/how-it-works'), 'how-it-works');
    assert.equal(routerModule.routeKindFromPath('/privacy'), 'privacy');
    assert.equal(routerModule.routeKindFromPath('/terms'), 'terms');
});

test('shared navigation exposes home, how-it-works, and github destinations', () => {
    const nav = routerModule.getSharedNavModel();

    assert.equal(nav.home.href, '/');
    assert.equal(nav.home.label, 'Home');
    assert.equal(nav.howItWorks.href, '/how-it-works');
    assert.equal(nav.howItWorks.label, 'How It Works');
    assert.equal(nav.github.href, 'https://github.com/hcipherdev/HybridCipher-SecretLink');
    assert.equal(nav.github.label, 'GitHub');
});

test('homepage trust copy stays product-first and technically specific', () => {
    const home = routerModule.getHomePageContent();

    assert.match(home.trustLabel, /zero-trust secret sharing/i);
    assert.match(home.trustBody, /encrypted in your browser before it reaches the server/i);
    assert.match(home.lede, /recipient link plus a separate management link/i);
});

test('how-it-works page explains the flow and server trust boundary', () => {
    const explainer = routerModule.getHowItWorksPage();
    const text = explainer.sections.flatMap((section) => section.items).join('\n');

    assert.equal(explainer.title, 'How It Works');
    assert.match(text, /encrypt/i);
    assert.match(text, /send the recipient link/i);
    assert.match(text, /plaintext/i);
    assert.match(text, /revoke/i);
});

test('legal pages expose the public-launch privacy and terms content', () => {
    const privacyPage = routerModule.getLegalPage('privacy');
    const termsPage = routerModule.getLegalPage('terms');
    const privacyText = privacyPage.sections.flatMap((section) => section.items).join('\n');
    const termsText = termsPage.sections.flatMap((section) => section.items).join('\n');

    assert.equal(privacyPage.title, 'Privacy');
    assert.match(privacyText, /encrypted secrets/i);
    assert.match(privacyText, /IP address/i);
    assert.match(privacyText, /Google Analytics/i);
    assert.match(privacyText, /no user accounts/i);
    assert.match(privacyText, /support@hybridcipher\.com/i);
    assert.doesNotMatch(privacyText, /no third-party analytics or ad trackers/i);
    assert.doesNotMatch(privacyText, /replace these addresses/i);
    assert.doesNotMatch(privacyText, /launch/i);
    assert.doesNotMatch(privacyText, /deployment/i);
    assert.doesNotMatch(privacyText, /policy changes/i);
    assert.doesNotMatch(privacyText, /admin-token/i);
    assert.doesNotMatch(privacyText, /hosting stack/i);
    assert.doesNotMatch(privacyText, /tombstones/i);

    assert.equal(termsPage.title, 'Terms');
    assert.match(termsText, /prohibited content/i);
    assert.match(termsText, /no warranty/i);
    assert.match(termsText, /liability/i);
    assert.match(termsText, /support@hybridcipher\.com/i);
    assert.doesNotMatch(termsText, /replace this address/i);
    assert.doesNotMatch(termsText, /launch/i);
    assert.doesNotMatch(termsText, /rate-limited/i);
});

test('public HTML installs the configured Google tag and avoids stale no-tracker metadata', () => {
    const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');

    assert.match(html, /https:\/\/www\.googletagmanager\.com\/gtag\/js\?id=G-JB26CTX23Z/);
    assert.match(html, /gtag\('config', 'G-JB26CTX23Z'\)/);
    assert.doesNotMatch(html, /No accounts, no trackers\./);
});

test('generated admin token can be hashed for the server request body', async () => {
    const tokenBytes = Uint8Array.from({ length: 32 }, (_, index) => index);
    const token = cryptoModule.bytesToBase64Url(tokenBytes);
    const digest = await cryptoModule.sha256Hex(token);

    assert.equal(token.includes('#'), false);
    assert.equal(digest.length, 64);
});
