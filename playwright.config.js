// Browser tests: they open the real page and click through it like a visitor would.
const { defineConfig, devices } = require('@playwright/test');

module.exports = defineConfig({
  testDir: 'tests/browser',
  timeout: 60000,
  retries: 0,
  reporter: [['list']],
  use: { baseURL: 'http://127.0.0.1:4173/' },
  webServer: {
    command: 'python3 -m http.server 4173 --bind 127.0.0.1',
    url: 'http://127.0.0.1:4173/index.html',
    reuseExistingServer: !process.env.CI,
    stdout: 'ignore',
    stderr: 'ignore',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
});
