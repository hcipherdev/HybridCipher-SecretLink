import { test, expect } from '@playwright/test';

async function createShare(page, secret) {
    await page.goto('/');
    await page.getByLabel('Secret').fill(secret);
    await page.getByRole('button', { name: 'Create share' }).click();
    await expect(page.getByText('Share created.')).toBeVisible();

    const recipientLink = await page.locator('#recipient-link').inputValue();
    const manageLink = await page.locator('#manage-link').inputValue();

    return { recipientLink, manageLink };
}

test('create, reveal, consume, and block second reveal for one-time shares', async ({ browser }) => {
    const senderPage = await browser.newPage();
    const { recipientLink } = await createShare(senderPage, 'playwright one-time secret');

    const recipientPage = await browser.newPage();
    await recipientPage.goto(recipientLink);
    await recipientPage.getByRole('button', { name: 'Reveal secret' }).click();
    await expect(recipientPage.getByText('playwright one-time secret')).toBeVisible();
    await expect(recipientPage.getByText('now consumed')).toBeVisible();

    const secondRecipientPage = await browser.newPage();
    await secondRecipientPage.goto(recipientLink);
    await secondRecipientPage.getByRole('button', { name: 'Reveal secret' }).click();
    await expect(
        secondRecipientPage.getByText('This share is unavailable. It may have expired, been revoked, or already been consumed.')
    ).toBeVisible();
});

test('loading a reveal page does not consume the share before explicit reveal', async ({ browser }) => {
    const senderPage = await browser.newPage();
    const { recipientLink, manageLink } = await createShare(senderPage, 'passive open secret');

    const recipientPage = await browser.newPage();
    await recipientPage.goto(recipientLink);
    await expect(recipientPage.getByRole('button', { name: 'Reveal secret' })).toBeVisible();

    const managePage = await browser.newPage();
    await managePage.goto(manageLink);
    await expect(managePage.getByText('Management state loaded.')).toBeVisible();
    await expect(managePage.getByText('available')).toBeVisible();
});
