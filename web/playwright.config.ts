import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  workers: 1,
  retries: 0,
  timeout: 60_000,
  use: {
    baseURL: "http://127.0.0.1:18543",
    browserName: "chromium",
    headless: true,
    trace: "retain-on-failure",
  },
  webServer: {
    command: "../target/debug/naosd",
    url: "http://127.0.0.1:18543/health/live",
    timeout: 90_000,
    reuseExistingServer: false,
    env: {
      NAOS_LISTEN: "127.0.0.1",
      NAOS_PORT: "18543",
      NAOS_DATABASE_URL: "sqlite://naos-playwright-e2e.db?mode=rwc",
    },
  },
});
