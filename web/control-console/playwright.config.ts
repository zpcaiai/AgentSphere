import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  retries: 0,
  reporter: [["list"], ["html", { outputFolder: "playwright-report", open: "never" }]],
  use: { baseURL: "http://127.0.0.1:4199", trace: "retain-on-failure" },
  webServer: {
    command: "npm run dev -- --port 4199",
    url: "http://127.0.0.1:4199",
    reuseExistingServer: false,
    timeout: 60_000,
    env: {
      VITE_CONTROL_API_URL: "https://control.e2e.invalid",
      VITE_AGUI_VERIFY_KEY: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    },
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"], channel: "chrome" } }],
});
