import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  getReportByTarget,
  getReportsByTarget,
  getReportDownloadUrl,
  getPublicReportUiMessage,
  reportErrorKind,
  isReportGenerationReady,
  resolveValhallaHtmlReportDownloadUrl,
  findValhallaReportRow,
} from "./reports";
import type { Report } from "./types";

const mockReport: Report = {
  report_id: "rpt-456",
  target: "https://example.com",
  summary: {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 5,
    technologies: ["nginx", "React"],
    sslIssues: 0,
    headerIssues: 1,
    leaksFound: false,
  },
  findings: [],
  technologies: ["nginx", "React"],
  tier: "midgard",
  generation_status: "ready",
};

describe("reports", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        headers: new Headers({ "content-type": "application/json" }),
        json: () => Promise.resolve([mockReport]),
      })
    );
  });

  describe("isReportGenerationReady", () => {
    it("treats missing status as ready (backend default)", () => {
      expect(isReportGenerationReady(undefined)).toBe(true);
      expect(isReportGenerationReady(null)).toBe(true);
    });

    it("returns false for non-ready statuses", () => {
      expect(isReportGenerationReady("pending")).toBe(false);
      expect(isReportGenerationReady("processing")).toBe(false);
      expect(isReportGenerationReady("failed")).toBe(false);
    });
  });

  describe("resolveValhallaHtmlReportDownloadUrl", () => {
    it("prefers scan-scoped URL when scanId is set", () => {
      const u = resolveValhallaHtmlReportDownloadUrl({
        scanId: "scan-1",
        valhallaReportId: "rpt-v",
      });
      expect(u).toMatch(/\/scans\/scan-1\/report\?/);
      expect(u).toContain("format=html");
      expect(u).toContain("tier=valhalla");
    });

    it("falls back to reports download when only valhallaReportId is set", () => {
      const u = resolveValhallaHtmlReportDownloadUrl({
        scanId: null,
        valhallaReportId: "rpt-v",
      });
      expect(u).toMatch(/\/reports\/rpt-v\/download\?/);
      expect(u).toContain("format=html");
    });

    it("returns null when neither scan nor report id is usable", () => {
      expect(
        resolveValhallaHtmlReportDownloadUrl({ scanId: "", valhallaReportId: "" }),
      ).toBeNull();
    });
  });

  describe("findValhallaReportRow", () => {
    it("finds Valhalla tier row case-insensitively", () => {
      const v = { ...mockReport, report_id: "v1", tier: "Valhalla" };
      expect(findValhallaReportRow([mockReport, v])).toEqual(v);
    });
  });

  describe("getReportDownloadUrl", () => {
    it("builds /reports/:id/download with format only by default", () => {
      const u = getReportDownloadUrl("rpt-abc", "pdf");
      expect(u).toMatch(/\/reports\/rpt-abc\/download\?/);
      expect(u).toContain("format=pdf");
      expect(u).not.toContain("regenerate");
    });

    it("appends regenerate=true when options.regenerate is set", () => {
      const u = getReportDownloadUrl("rpt-abc", "html", { regenerate: true });
      expect(u).toContain("format=html");
      expect(u).toContain("regenerate=true");
    });

    it("supports valhalla_sections.csv format (Valhalla tier export)", () => {
      const u = getReportDownloadUrl("rpt-abc", "valhalla_sections.csv");
      expect(u).toContain("format=valhalla_sections.csv");
    });

    it("appends redirect=true when options.redirect is set", () => {
      const u = getReportDownloadUrl("rpt-abc", "pdf", { redirect: true });
      expect(u).toContain("format=pdf");
      expect(u).toContain("redirect=true");
    });
  });

  describe("getPublicReportUiMessage", () => {
    it("returns safe generic text for unknown server messages", () => {
      expect(getPublicReportUiMessage("psycopg.OperationalError: connection refused")).toBe(
        "We could not load the report. Try again or return to the scanner.",
      );
    });

    it("maps not-found style errors", () => {
      expect(getPublicReportUiMessage("Report not found")).toBe(
        "This report is missing or the link is no longer valid.",
      );
    });

    it("maps missing query hint from useReport", () => {
      const msg = getPublicReportUiMessage("No target or report ID provided");
      expect(msg).toContain("scanner");
    });
  });

  describe("reportErrorKind", () => {
    it("classifies missing query as missing", () => {
      expect(reportErrorKind("x", false)).toBe("missing");
    });

    it("classifies not found when target param exists", () => {
      expect(reportErrorKind("Report not found", true)).toBe("not_found");
    });
  });

  describe("getReportByTarget", () => {
    it("GETs /reports?target=X and returns first Report from array", async () => {
      const fetchMock = vi.mocked(fetch);
      fetchMock.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ "content-type": "application/json" }),
        json: () => Promise.resolve([mockReport]),
      } as Response);

      const result = await getReportByTarget("https://example.com");

      expect(result).toEqual(mockReport);
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringMatching(/\/reports\?target=https%3A%2F%2Fexample\.com$/),
        expect.objectContaining({
          headers: expect.objectContaining({
            "Content-Type": "application/json",
          }),
        })
      );
    });

    it("encodes target in query params", async () => {
      const fetchMock = vi.mocked(fetch);
      fetchMock.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ "content-type": "application/json" }),
        json: () => Promise.resolve([mockReport]),
      } as Response);

      await getReportByTarget("https://test.com/path?foo=bar");

      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining("target="),
        expect.any(Object)
      );
      const callUrl = (fetchMock.mock.calls[0][0] as string);
      const params = new URLSearchParams(callUrl.split("?")[1]);
      expect(params.get("target")).toBe("https://test.com/path?foo=bar");
    });

    it("throws when array is empty", async () => {
      const fetchMock = vi.mocked(fetch);
      fetchMock.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ "content-type": "application/json" }),
        json: () => Promise.resolve([]),
      } as Response);

      await expect(getReportByTarget("https://unknown.com")).rejects.toThrow(
        "Report not found"
      );
    });

    it("throws when response is not ok", async () => {
      const fetchMock = vi.mocked(fetch);
      fetchMock.mockResolvedValueOnce({
        ok: false,
        status: 404,
        headers: new Headers({ "content-type": "application/json" }),
        json: () => Promise.resolve({ error: "Report not found" }),
      } as Response);

      await expect(getReportByTarget("https://unknown.com")).rejects.toThrow(
        "Report not found"
      );
    });

    it("throws with status when error body is not JSON", async () => {
      const fetchMock = vi.mocked(fetch);
      fetchMock.mockResolvedValueOnce({
        ok: false,
        status: 500,
        headers: new Headers({ "content-type": "text/plain" }),
        json: () => Promise.reject(new Error("Not JSON")),
      } as Response);

      await expect(getReportByTarget("https://example.com")).rejects.toThrow(
        "Request failed (500)"
      );
    });
  });

  describe("getReportsByTarget", () => {
    it("returns full array from GET /reports?target=", async () => {
      const fetchMock = vi.mocked(fetch);
      const second = { ...mockReport, report_id: "rpt-789", tier: "valhalla" };
      fetchMock.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ "content-type": "application/json" }),
        json: () => Promise.resolve([mockReport, second]),
      } as Response);

      const rows = await getReportsByTarget("https://example.com");
      expect(rows).toHaveLength(2);
      expect(rows[1].report_id).toBe("rpt-789");
    });
  });
});
