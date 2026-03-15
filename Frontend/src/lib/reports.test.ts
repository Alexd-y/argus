import { describe, it, expect, vi, beforeEach } from "vitest";
import { getReportByTarget } from "./reports";
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
});
