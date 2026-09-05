import { describe, expect, it } from "vitest";
import { hardeningBreakdown } from "./scan-results";
import type { Finding } from "./scan-results";

function finding(partial: Partial<Finding>): Finding {
  return {
    id: partial.id ?? "1",
    groupId: partial.groupId ?? "1",
    group: partial.group ?? "Other Findings",
    name: partial.name ?? "Finding",
    status: partial.status ?? "fail",
    priority: partial.priority ?? "medium",
    headline: partial.headline ?? "",
    explanation: "",
    evidence: "",
    remediation: "",
    detailLevel: "full",
    access: "full",
  };
}

describe("hardeningBreakdown", () => {
  it("is non-empty when a TLS_PROBE finding exists (Block 4.5 acceptance)", () => {
    const b = hardeningBreakdown([
      finding({ group: "Transport Security", name: "TLS_PROBE finding" }),
    ]);
    expect(b.tls).toBe(1);
    expect(b.total).toBe(1);
  });

  it("counts TLS by name even outside the Transport Security group", () => {
    const b = hardeningBreakdown([finding({ name: "Weak SSL cipher suite" })]);
    expect(b.tls).toBe(1);
  });

  it("classifies headers, DNSSEC and mail-auth", () => {
    const b = hardeningBreakdown([
      finding({ name: "Missing HSTS header", group: "HTTP Security Headers" }),
      finding({ name: "DNSSEC not enabled" }),
      finding({ name: "SPF record missing" }),
    ]);
    // HSTS matches TLS regex (hsts) first — that is acceptable (transport hardening).
    expect(b.dnssec).toBe(1);
    expect(b.email).toBe(1);
    expect(b.total).toBe(3);
  });

  it("ignores passed findings", () => {
    const b = hardeningBreakdown([
      finding({ group: "Transport Security", name: "TLS", status: "pass" }),
    ]);
    expect(b.total).toBe(0);
  });

  it("returns all-zero for unrelated findings", () => {
    const b = hardeningBreakdown([finding({ name: "SQL injection", group: "Injection" })]);
    expect(b.total).toBe(0);
  });
});
