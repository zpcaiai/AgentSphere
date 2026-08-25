import { defineConfig, loadEnv } from "vite";
import vue from "@vitejs/plugin-vue";
import { fileURLToPath } from "node:url";

const serverFileSystemAllowlist = [
  fileURLToPath(new URL(".", import.meta.url)),
  fileURLToPath(new URL("../approval-console/src", import.meta.url)),
  fileURLToPath(new URL("../shared", import.meta.url)),
];

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "VITE_");
  if (mode === "production") {
    let controlApiUrl: URL;
    try {
      controlApiUrl = new URL(env.VITE_CONTROL_API_URL);
    } catch {
      throw new Error("VITE_CONTROL_API_URL must be an absolute HTTPS URL for production builds");
    }
    if (controlApiUrl.protocol !== "https:" || controlApiUrl.username || controlApiUrl.password) {
      throw new Error("VITE_CONTROL_API_URL must use HTTPS and must not contain credentials");
    }
    if (!/^[A-Za-z0-9_-]{43}$/.test(env.VITE_AGUI_VERIFY_KEY ?? "")) {
      throw new Error("VITE_AGUI_VERIFY_KEY must be a base64url Ed25519 public key for production builds");
    }
  }

  return {
    plugins: [vue()],
    build: { sourcemap: false, target: "es2022" },
    server: {
      host: "127.0.0.1",
      strictPort: true,
      fs: { strict: true, allow: serverFileSystemAllowlist },
    },
    test: {
      environment: "jsdom",
      setupFiles: ["./src/test/setup.ts"],
      include: ["src/**/*.test.ts", "../approval-console/src/**/*.test.ts"],
      coverage: { reporter: ["text", "json-summary"] },
    },
  };
});
