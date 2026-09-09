import { defineConfig } from '@playwright/test'

const port = Number(process.env.QNTM_UI_TEST_PORT ?? 5173)

export default defineConfig({
  testDir: './tests/e2e',
  timeout: 30_000,
  retries: 0,
  workers: 1, // Bob fixture stubs globals — can't run in parallel
  use: {
    baseURL: `http://localhost:${port}`,
    headless: true,
    viewport: { width: 1280, height: 900 },
  },
  projects: [
    { name: 'chromium', use: { browserName: 'chromium' } },
  ],
  webServer: {
    command: `npm run dev -- --port ${port} --strictPort`,
    port,
    reuseExistingServer: !process.env.QNTM_UI_TEST_PORT,
  },
})
