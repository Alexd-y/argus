import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  createScan,
  getFindings,
  getScanCoverage,
  getScanStatus,
  listScans,
  mapTierToScanProfile,
  reportDownloadUrl,
} from "./scanClient";
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

  describe("mapTierToScanProfile", () => {
    it("maps free -> quick, standard -> light, premium -> deep", () => {
      expect(mapTierToScanProfile("free")).toBe("quick");
      expect(mapTierToScanProfile("standard")).toBe("light");
      expect(mapTierToScanProfile("premium")).toBe("deep");
    });
  });

  describe("createScan payload", () => {
    it("sends the canonical scan_profile in the request body", async () => {
      const fetchMock = vi.mocked(fetch);
      fetchMock.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ "content-type": "application/json" }),
        json: () => Promise.resolve(mockCreateScanResponse),
      } as Response);

      const req: CreateScanRequest = {
        ...mockCreateScanRequest,
        scan_profile: "deep",
        engagement_id: "eng-1",
        lab_lease_id: "lease-1",
      };
      await createScan(req);

      const [, opts] = fetchMock.mock.calls[0] as [string, RequestInit];
      const body = JSON.parse(String(opts.body));
      expect(body.scan_profile).toBe("deep");
      expect(body.engagement_id).toBe("eng-1");
      expect(body.lab_lease_id).toBe("lease-1");
    });
  });

  describe("listScans", () => {
    it("GETs /scans and returns the list", async () => {
      const fetchMock = vi.mocked(fetch);
      fetchMock.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ "content-type": "application/json" }),
        json: () => Promise.resolve([{ id: "s-1", status: "queued" }]),
      } as Response);
      const rows = await listScans();
      expect(rows).toHaveLength(1);
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining("/scans"),
        expect.objectContaining({ method: "GET" })
      );
    });
  });

  describe("getFindings", () => {
    it("GETs /scans/:id/findings with query filters", async () => {
      const fetchMock = vi.mocked(fetch);
      fetchMock.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ "content-type": "application/json" }),
        json: () => Promise.resolve([]),
      } as Response);
      await getFindings("scan-1", { severity: "high", validatedOnly: true });
      const [url] = fetchMock.mock.calls[0] as [string];
      expect(url).toContain("/scans/scan-1/findings");
      expect(url).toContain("severity=high");
      expect(url).toContain("validated_only=true");
    });
  });

  describe("getScanCoverage", () => {
    it("GETs /scans/:id/coverage", async () => {
      const fetchMock = vi.mocked(fetch);
      fetchMock.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ "content-type": "application/json" }),
        json: () => Promise.resolve({ scan_id: "scan-1", requirements: [], results: [] }),
      } as Response);
      const cov = await getScanCoverage("scan-1");
      expect(cov.scan_id).toBe("scan-1");
    });
  });

  describe("reportDownloadUrl", () => {
    it("builds a download URL with the format query", () => {
      const url = reportDownloadUrl("rep-1", "xml");
      expect(url).toContain("/reports/rep-1/download");
      expect(url).toContain("format=xml");
    });
  });
});
