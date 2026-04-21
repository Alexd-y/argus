import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  DEFAULT_EXPORT_FORMAT,
  EXPORT_FORMAT_STORAGE_KEY,
  buildFindingsExportUrl,
  downloadFindingsExport,
  isExportFormat,
  parseExportFormat,
  persistExportFormat,
  readPersistedExportFormat,
  suggestExportFilename,
} from "./findingsExport";

describe("findingsExport — closed format taxonomy", () => {
  it("treats only 'sarif' and 'junit' as valid formats", () => {
    expect(isExportFormat("sarif")).toBe(true);
    expect(isExportFormat("junit")).toBe(true);
    expect(isExportFormat("pdf")).toBe(false);
    expect(isExportFormat("")).toBe(false);
    expect(isExportFormat(null)).toBe(false);
    expect(isExportFormat(undefined)).toBe(false);
    expect(isExportFormat(42)).toBe(false);
  });

  it("parseExportFormat normalises whitespace and case", () => {
    expect(parseExportFormat(" SARIF ")).toBe("sarif");
    expect(parseExportFormat("Junit")).toBe("junit");
  });

  it("parseExportFormat returns null for invalid / empty / nullish input", () => {
    expect(parseExportFormat(null)).toBeNull();
    expect(parseExportFormat(undefined)).toBeNull();
    expect(parseExportFormat("")).toBeNull();
    expect(parseExportFormat("   ")).toBeNull();
    expect(parseExportFormat("xml")).toBeNull();
    expect(parseExportFormat("sarif; drop table")).toBeNull();
  });
});

describe("findingsExport — localStorage persistence", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  afterEach(() => {
    window.localStorage.clear();
  });

  it("readPersistedExportFormat falls back to SARIF when key is missing", () => {
    expect(readPersistedExportFormat()).toBe(DEFAULT_EXPORT_FORMAT);
    expect(DEFAULT_EXPORT_FORMAT).toBe("sarif");
  });

  it("readPersistedExportFormat returns the persisted value when valid", () => {
    window.localStorage.setItem(EXPORT_FORMAT_STORAGE_KEY, "junit");
    expect(readPersistedExportFormat()).toBe("junit");
  });

  it("readPersistedExportFormat falls back to SARIF when value is invalid", () => {
    window.localStorage.setItem(EXPORT_FORMAT_STORAGE_KEY, "xml");
    expect(readPersistedExportFormat()).toBe("sarif");
  });

  it("persistExportFormat writes whitelisted values only", () => {
    persistExportFormat("junit");
    expect(window.localStorage.getItem(EXPORT_FORMAT_STORAGE_KEY)).toBe("junit");
    persistExportFormat("sarif");
    expect(window.localStorage.getItem(EXPORT_FORMAT_STORAGE_KEY)).toBe("sarif");
  });

  it("persistExportFormat is a silent no-op when localStorage throws", () => {
    const setItem = vi
      .spyOn(Storage.prototype, "setItem")
      .mockImplementation(() => {
        throw new Error("QuotaExceededError");
      });
    expect(() => persistExportFormat("junit")).not.toThrow();
    expect(setItem).toHaveBeenCalled();
    setItem.mockRestore();
  });
});

describe("findingsExport — URL + filename builders", () => {
  it("buildFindingsExportUrl encodes the scan id and appends the format", () => {
    const url = buildFindingsExportUrl("abc-123", "sarif");
    expect(url).toBe("/api/v1/scans/abc-123/findings/export?format=sarif");

    const tricky = buildFindingsExportUrl("scan/with space", "junit");
    expect(tricky).toBe(
      "/api/v1/scans/scan%2Fwith%20space/findings/export?format=junit",
    );
  });

  it("buildFindingsExportUrl rejects empty scan id and unknown format", () => {
    expect(() => buildFindingsExportUrl("", "sarif")).toThrow(/scanId/i);
    expect(() =>
      buildFindingsExportUrl("abc", "html" as unknown as "sarif"),
    ).toThrow(/format/i);
  });

  it("suggestExportFilename uses the canonical extension per format", () => {
    expect(suggestExportFilename("scan-1", "sarif")).toBe("findings-scan-1.sarif");
    expect(suggestExportFilename("scan-1", "junit")).toBe(
      "findings-scan-1.junit.xml",
    );
  });

  it("suggestExportFilename strips unsafe characters from the scan id", () => {
    expect(suggestExportFilename("../etc/passwd", "sarif")).toBe(
      "findings-..-etc-passwd.sarif",
    );
  });
});

describe("findingsExport — downloadFindingsExport orchestrator", () => {
  // jsdom (v25, currently used) does not implement URL.createObjectURL /
  // revokeObjectURL — we polyfill them per test and capture the calls.
  let createObjectURL: ReturnType<typeof vi.fn>;
  let revokeObjectURL: ReturnType<typeof vi.fn>;
  let click: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    window.localStorage.clear();
    createObjectURL = vi.fn(() => "blob:mock");
    revokeObjectURL = vi.fn();
    click = vi.fn();
    Object.defineProperty(URL, "createObjectURL", {
      configurable: true,
      writable: true,
      value: createObjectURL,
    });
    Object.defineProperty(URL, "revokeObjectURL", {
      configurable: true,
      writable: true,
      value: revokeObjectURL,
    });
    Object.defineProperty(HTMLAnchorElement.prototype, "click", {
      configurable: true,
      writable: true,
      value: click,
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("calls the export URL with the X-Tenant-ID header and triggers a download", async () => {
    const blob = new Blob(["{}"], { type: "application/sarif+json" });
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response(blob, {
        status: 200,
        headers: { "content-type": "application/sarif+json" },
      }),
    );

    await downloadFindingsExport("scan-42", "sarif", {
      tenantId: "tenant-7",
      fetchImpl,
    });

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [calledUrl, calledInit] = fetchImpl.mock.calls[0];
    expect(calledUrl).toBe("/api/v1/scans/scan-42/findings/export?format=sarif");
    expect(calledInit).toMatchObject({
      method: "GET",
      cache: "no-store",
      headers: { "X-Tenant-ID": "tenant-7" },
    });
    expect(createObjectURL).toHaveBeenCalledOnce();
    expect(click).toHaveBeenCalledOnce();
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:mock");
  });

  it("omits the tenant header when no tenantId is provided", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValue(new Response(new Blob([""]), { status: 200 }));

    await downloadFindingsExport("scan-42", "junit", { fetchImpl });

    const [, calledInit] = fetchImpl.mock.calls[0];
    expect((calledInit as RequestInit).headers).toEqual({});
  });

  it("throws a closed-taxonomy error on non-OK responses (no stack leak)", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response("internal", { status: 404 }),
    );
    await expect(
      downloadFindingsExport("scan-x", "sarif", { fetchImpl }),
    ).rejects.toThrow(/not available/i);

    const fetchImpl500 = vi
      .fn()
      .mockResolvedValue(new Response("oops", { status: 500 }));
    await expect(
      downloadFindingsExport("scan-x", "junit", { fetchImpl: fetchImpl500 }),
    ).rejects.toThrow(/failed/i);
  });
});
