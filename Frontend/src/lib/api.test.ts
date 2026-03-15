import { describe, it, expect } from "vitest";
import {
  getSafeErrorMessage,
  apiUrl,
  type ApiError,
} from "./api";

describe("api", () => {
  describe("getSafeErrorMessage", () => {
    it("returns Error.message when it is safe (no stack trace)", () => {
      expect(getSafeErrorMessage(new Error("Invalid target"))).toBe(
        "Invalid target"
      );
    });

    it("returns Error.error when present and message contains stack", () => {
      const err = new Error("Internal") as Error & { error?: string };
      err.error = "User-friendly message";
      err.message = "Error: Internal\n    at foo.js:1:1";
      expect(getSafeErrorMessage(err)).toBe("User-friendly message");
    });

    it("returns fallback when Error.message contains 'stack'", () => {
      const err = new Error("stack overflow");
      expect(getSafeErrorMessage(err)).toBe("An error occurred");
    });

    it("returns fallback when Error.message contains 'at '", () => {
      const err = new Error("Error at line 10");
      expect(getSafeErrorMessage(err)).toBe("An error occurred");
    });

    it("returns apiErr.error for ApiError-like object", () => {
      const apiErr: ApiError = { error: "Target not found", code: "NOT_FOUND" };
      expect(getSafeErrorMessage(apiErr)).toBe("Target not found");
    });

    it("returns fallback when apiErr.error contains stack trace", () => {
      const apiErr: ApiError = {
        error: "Internal error\n    at foo.js:1:1\n    at bar.js:2:2",
      };
      expect(getSafeErrorMessage(apiErr)).toBe("An error occurred");
    });

    it("returns safe string when err is string", () => {
      expect(getSafeErrorMessage("Connection refused")).toBe("Connection refused");
    });

    it("returns fallback when err is string with stack trace", () => {
      expect(getSafeErrorMessage("Error at line 10")).toBe("An error occurred");
    });

    it("returns fallback for non-string apiErr.error", () => {
      const obj = { error: 123 };
      expect(getSafeErrorMessage(obj)).toBe("An error occurred");
    });

    it("returns custom fallback when provided", () => {
      expect(getSafeErrorMessage(null, "Custom fallback")).toBe(
        "Custom fallback"
      );
    });

    it("returns fallback for null/undefined", () => {
      expect(getSafeErrorMessage(null)).toBe("An error occurred");
      expect(getSafeErrorMessage(undefined)).toBe("An error occurred");
    });

    it("returns fallback for non-string primitives", () => {
      expect(getSafeErrorMessage(42)).toBe("An error occurred");
    });
  });

  describe("apiUrl", () => {
    it("builds URL with path starting with slash", () => {
      expect(apiUrl("/scans")).toMatch(/\/api\/v1\/scans$/);
    });

    it("builds URL with path without leading slash", () => {
      expect(apiUrl("scans")).toMatch(/\/api\/v1\/scans$/);
    });

    it("builds URL for nested path", () => {
      expect(apiUrl("/scans/abc-123/events")).toMatch(
        /\/api\/v1\/scans\/abc-123\/events$/
      );
    });

    it("builds URL for path with query params", () => {
      const url = apiUrl("/reports?target=example.com");
      expect(url).toMatch(/\/api\/v1\/reports\?target=example\.com$/);
    });
  });
});
