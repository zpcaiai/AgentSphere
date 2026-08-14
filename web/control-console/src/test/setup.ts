import { afterEach, vi } from "vitest";
import { config } from "@vue/test-utils";

config.global.stubs = { RouterLink: { template: "<a><slot /></a>" } };

if (!globalThis.crypto?.subtle) {
  Object.defineProperty(globalThis, "crypto", { value: window.crypto, configurable: true });
}

afterEach(() => {
  vi.restoreAllMocks();
  document.cookie = "XSRF-TOKEN=; Max-Age=0; path=/";
});
