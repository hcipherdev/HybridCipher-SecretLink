import { defineConfig } from '@playwright/test';

export default defineConfig({
    testDir: './tests',
    testMatch: ['smoke.spec.js'],
    use: {
        baseURL: process.env.SECRETLINK_BASE_URL || 'http://127.0.0.1:8787',
        trace: 'on-first-retry',
    },
    fullyParallel: false,
});
