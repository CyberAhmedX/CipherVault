// End-to-end tests: the whole app in a real browser (Chromium, Firefox and WebKit).
const { test, expect } = require('@playwright/test');

const PASS = 'correct horse battery staple';
const SECRET = 'Wazuh flagged an SQL injection at 02:14. Escalating to TheHive.';

async function createVault(page, pass = PASS) {
  await expect(page.locator('#lock-title')).toHaveText('Create your vault');
  // the app puts the cursor in the passphrase box just after load; wait for it like a person would
  await expect(page.locator('#pass')).toBeFocused();
  await page.fill('#pass', pass);
  await page.fill('#pass2', pass);
  await page.click('#lock-submit');
  await expect(page.locator('#app')).toBeVisible({ timeout: 20000 });
}

async function unlock(page, pass) {
  await expect(page.locator('#pass')).toBeFocused();
  await page.fill('#pass', pass);
  await page.click('#lock-submit');
}

async function pick(page, side, method) {
  await page.locator(`label:has(#${side}-m-${method})`).click();
}

test.beforeEach(async ({ page }) => {
  await page.goto('/index.html');
});

test('encrypts with RSA + AES, saves, locks, unlocks and decrypts', async ({ page }) => {
  await createVault(page);

  await page.fill('#enc-input', SECRET);
  await page.click('#enc-run');
  await expect(page.locator('#enc-output')).toHaveValue(/^CV1:/, { timeout: 30000 });
  const ciphertext = await page.inputValue('#enc-output');
  await page.click('#enc-save');
  await expect(page.locator('#vault-count')).toHaveText('1');

  // The original message is never stored, in any form
  const stored = await page.evaluate(() => JSON.stringify(localStorage));
  expect(stored).not.toContain('SQL injection');
  expect(stored).not.toContain(ciphertext.slice(4, 40));  // even the result is inside the encrypted vault

  await page.click('#lock-btn');
  await expect(page.locator('#lock-title')).toHaveText('Unlock your vault');
  await expect(page.locator('#enc-input')).toHaveValue('');  // decrypted data cleared from the page

  await unlock(page, 'wrong passphrase');
  await expect(page.locator('#lock-err')).toHaveText(/Wrong passphrase/, { timeout: 20000 });
  await expect(page.locator('#app')).toBeHidden();

  await unlock(page, PASS);
  await expect(page.locator('#app')).toBeVisible({ timeout: 20000 });
  await expect(page.locator('#vault-count')).toHaveText('1');

  await page.click('#tab-decrypt');
  await page.fill('#dec-input', ciphertext);
  await page.click('#dec-run');
  await expect(page.locator('#dec-output')).toHaveValue(SECRET, { timeout: 20000 });
});

test('a changed ciphertext is rejected, not decrypted', async ({ page }) => {
  await createVault(page);
  await page.fill('#enc-input', SECRET);
  await page.click('#enc-run');
  await expect(page.locator('#enc-output')).toHaveValue(/^CV1:/, { timeout: 30000 });
  const ct = await page.inputValue('#enc-output');
  const tampered = ct.slice(0, -6) + (ct.slice(-6, -5) === 'A' ? 'B' : 'A') + ct.slice(-5);
  await page.click('#tab-decrypt');
  await page.fill('#dec-input', tampered);
  await page.click('#dec-run');
  await expect(page.locator('#dec-err')).toHaveText(/different key|was changed/);
  await expect(page.locator('#dec-output')).toHaveValue('');
});

test('saved results are shown as text, never run as HTML (stored XSS regression)', async ({ page }) => {
  await createVault(page);
  const payload = '<img src=x id="xss" onerror="window.__xss = 1">';
  await pick(page, 'enc', 'caesar');
  await page.fill('#enc-caesar', '0');   // shift 0 keeps the payload exactly as typed
  await page.fill('#enc-input', payload);
  await page.click('#enc-run');
  await expect(page.locator('#enc-output')).toHaveValue(payload);
  await page.click('#enc-save');
  await page.click('#tab-vault');
  await expect(page.locator('#vault-items .item-body')).toHaveText(payload);
  await expect(page.locator('#vault-items img')).toHaveCount(0);
  expect(await page.evaluate(() => window.__xss)).toBeUndefined();
});

test('plaintext left by the first version is moved into the vault and deleted', async ({ page }) => {
  await page.evaluate(() => {
    localStorage.setItem('ahmed_messages', JSON.stringify([
      { method: 'base64', original: 'my plaintext secret', encrypted: 'bXkgcGxhaW50ZXh0IHNlY3JldA==' },
    ]));
    localStorage.setItem('authToken', 'old-token');
  });
  await page.reload();
  await expect(page.locator('#legacy')).toContainText('1 saved result');
  await createVault(page);

  const keys = await page.evaluate(() => Object.keys(localStorage));
  expect(keys).toEqual(['cipherVault.v1']);
  expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain('my plaintext secret');
  await expect(page.locator('#vault-count')).toHaveText('1');
});

test('classical ciphers, Base64 and SHA-256 work in the page', async ({ page }) => {
  await createVault(page);

  await pick(page, 'enc', 'vigenere');
  await page.fill('#enc-vigenere', 'LEMON');
  await page.fill('#enc-input', 'ATTACKATDAWN');
  await page.click('#enc-run');
  await expect(page.locator('#enc-output')).toHaveValue('LXFOPVEFRNHR');

  await pick(page, 'enc', 'base64');
  await page.fill('#enc-input', 'سلام 🔐');
  await page.click('#enc-run');
  const b64 = await page.inputValue('#enc-output');
  await page.click('#tab-decrypt');
  await pick(page, 'dec', 'base64');
  await page.fill('#dec-input', b64);
  await page.click('#dec-run');
  await expect(page.locator('#dec-output')).toHaveValue('سلام 🔐');

  await pick(page, 'dec', 'sha256');
  await page.fill('#dec-input', 'abc');
  await page.fill('#dec-hash', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  await page.click('#dec-run');
  await expect(page.locator('#dec-verdict')).toContainText('Match');
});

test('makes no network requests outside its own folder', async ({ page, baseURL }) => {
  const outside = [];
  page.on('request', r => { if (!r.url().startsWith(baseURL) && !r.url().startsWith('data:')) outside.push(r.url()); });
  await page.reload();
  await createVault(page);
  await page.fill('#enc-input', 'hello');
  await page.click('#enc-run');
  await expect(page.locator('#enc-output')).toHaveValue(/^CV1:/, { timeout: 30000 });
  expect(outside).toEqual([]);
});
