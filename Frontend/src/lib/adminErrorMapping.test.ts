import { describe, expect, it } from "vitest";

import { normalizeAdminDetailError } from "./adminErrorMapping";

describe("normalizeAdminDetailError", () => {
  it("returns trimmed string detail", () => {
    expect(normalizeAdminDetailError("  Not found  ")).toBe("Not found");
  });

  it("rejects stack-like strings", () => {
    expect(normalizeAdminDetailError("Error at foo.py line 12")).toBeNull();
  });

  it("extracts msg from validation array", () => {
    expect(
      normalizeAdminDetailError([{ type: "missing", msg: "field required" }]),
    ).toBe("field required");
  });

  it("returns null for overly long strings", () => {
    expect(normalizeAdminDetailError("x".repeat(300))).toBeNull();
  });

  it("returns null for empty array detail", () => {
    expect(normalizeAdminDetailError([])).toBeNull();
  });

  it("returns null when first validation item has no msg", () => {
    expect(normalizeAdminDetailError([{ type: "missing" }])).toBeNull();
  });

  it("uses first array item only when multiple validation errors", () => {
    expect(
      normalizeAdminDetailError([
        { msg: "first issue" },
        { msg: "second issue" },
      ]),
    ).toBe("first issue");
  });

  it("recursively normalizes nested msg string (trim + reject internalish)", () => {
    expect(
      normalizeAdminDetailError([{ loc: ["body", "x"], msg: "  bad  " }]),
    ).toBe("bad");
    expect(
      normalizeAdminDetailError([
        { msg: "internal exception at line 9" },
      ]),
    ).toBeNull();
  });

  it("returns null when msg is nested object or array", () => {
    expect(normalizeAdminDetailError([{ msg: { code: "x" } }])).toBeNull();
    expect(normalizeAdminDetailError([{ msg: ["nested"] }])).toBeNull();
  });
});
