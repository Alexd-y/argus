import { describe, it, expect, vi, beforeEach } from "vitest";
import { createScan, getScanStatus } from "./scans";
import type { CreateScanRequest, CreateScanResponse, ScanStatus } from "./types";

const mockCreateScanResponse: CreateScanResponse = {
  scan_id: "scan-123",
  status: "queued",
  message: "Scan created",
};

const mockScanStatus: ScanStatus = {
  id: "scan-123",
  status: "running",
  progress: 50,
  phase: "scanning",
  target: "https://example.com",
  created_at: "2025-03-08T12:00:00Z",
};

const mockCreateScanRequest: CreateScanRequest = {
  target: "https://example.com",
  email: "user@example.com",
  options: {
    scanType: "quick",
    reportFormat: "pdf",
    rateLimit: "normal",
    ports: "80,443",
    followRedirects: true,
    vulnerabilities: {
      xss: true,
      sqli: false,
      csrf: false,
      ssrf: false,
      lfi: false,
      rce: false,
    },
    authentication: {
      enabled: false,
      type: "basic",
      username: "",
      password: "",
      token: "",
    },
    scope: {
      maxDepth: 3,
      includeSubs: true,
      excludePatterns: "",
    },
    advanced: {
      timeout: 30,
      userAgent: "chrome",
      proxy: "",
      customHeaders: "",
    },
  },
};

describe("scans", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        headers: new Headers({ "content-type": "application/json" }),
        json: () => Promise.resolve(mockCreateScanResponse),
      })
    );
  });

  describe("createScan", () => {
    it("POSTs to /scans and returns CreateScanResponse", async () => {
      const fetchMock = vi.mocked(fetch);
      fetchMock.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ "content-type": "application/json" }),
        json: () => Promise.resolve(mockCreateScanResponse),
      } as Response);

      const result = await createScan(mockCreateScanRequest);

      expect(result).toEqual(mockCreateScanResponse);
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining("/scans"),
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify(mockCreateScanRequest),
          headers: expect.objectContaining({
            "Content-Type": "application/json",
          }),
        })
      );
    });

    it("throws when response is not ok", async () => {
      const fetchMock = vi.mocked(fetch);
      fetchMock.mockResolvedValueOnce({
        ok: false,
        status: 400,
        headers: new Headers({ "content-type": "application/json" }),
        json: () => Promise.resolve({ error: "Invalid target URL" }),
      } as Response);

      await expect(createScan(mockCreateScanRequest)).rejects.toThrow(
        "Invalid target URL"
      );
    });
  });

  describe("getScanStatus", () => {
    it("GETs /scans/:id and returns ScanStatus", async () => {
      const fetchMock = vi.mocked(fetch);
      fetchMock.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ "content-type": "application/json" }),
        json: () => Promise.resolve(mockScanStatus),
      } as Response);

      const result = await getScanStatus("scan-123");

      expect(result).toEqual(mockScanStatus);
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining("/scans/scan-123"),
        expect.objectContaining({
          headers: expect.objectContaining({
            "Content-Type": "application/json",
          }),
        })
      );
    });

    it("encodes scanId in URL", async () => {
      const fetchMock = vi.mocked(fetch);
      fetchMock.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ "content-type": "application/json" }),
        json: () => Promise.resolve({ ...mockScanStatus, id: "scan/with/slash" }),
      } as Response);

      await getScanStatus("scan/with/slash");

      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining("/scans/scan%2Fwith%2Fslash"),
        expect.any(Object)
      );
    });

    it("throws when response is not ok", async () => {
      const fetchMock = vi.mocked(fetch);
      fetchMock.mockResolvedValueOnce({
        ok: false,
        status: 404,
        headers: new Headers({ "content-type": "application/json" }),
        json: () => Promise.resolve({ error: "Scan not found" }),
      } as Response);

      await expect(getScanStatus("missing-id")).rejects.toThrow("Scan not found");
    });
  });
});
