import { afterEach, describe, expect, it, vi } from "vitest";

import { getBackendBaseUrl, getServerAdminApiKey } from "./adminProxy";

describe("getBackendBaseUrl", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("prefers BACKEND_URL over NEXT_PUBLIC_BACKEND_URL", () => {
    vi.stubEnv("BACKEND_URL", "http://primary");
    vi.stubEnv("NEXT_PUBLIC_BACKEND_URL", "http://public");
    expect(getBackendBaseUrl()).toBe("http://primary");
  });

  it("strips trailing slash", () => {
    vi.stubEnv("BACKEND_URL", "http://primary/");
    expect(getBackendBaseUrl()).toBe("http://primary");
  });

  it("falls back to localhost when unset", () => {
    vi.stubEnv("BACKEND_URL", "");
    vi.stubEnv("NEXT_PUBLIC_BACKEND_URL", "");
    expect(getBackendBaseUrl()).toBe("http://localhost:8000");
  });
});

describe("getServerAdminApiKey", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("returns null when missing or blank", () => {
    vi.stubEnv("ADMIN_API_KEY", "");
    expect(getServerAdminApiKey()).toBeNull();
  });

  it("returns trimmed key", () => {
    vi.stubEnv("ADMIN_API_KEY", "  abc  ");
    expect(getServerAdminApiKey()).toBe("abc");
  });
});
