import { describe, expect, it } from "vitest";
import { mapBackendFindingsToResults } from "./backendClient";

function bf(over: Record<string, unknown>) {
  return {
    finding_id: String(over.finding_id ?? Math.random()),
    severity: over.severity ?? "medium",
    title: over.title ?? "",
    description: over.description ?? "",
    cwe: over.cwe ?? null,
    owasp_category: over.owasp_category ?? "A02",
    ...over,
  };
}

function groupsOf(findings: { group: string }[]): Set<string> {
  return new Set(findings.map((f) => f.group));
}

describe("recon dedicated sections (Block 4d)", () => {
  it("routes DNS/DNSSEC/Email/Data Exposure findings into their own groups", () => {
    const raw = [
      bf({ title: "SPF record missing — alleksy.com", cwe: "CWE-16", severity: "medium" }),
      bf({ title: "DNSSEC not enabled — alleksy.com", cwe: "CWE-350", severity: "low" }),
      bf({ title: "DNS zone transfer (AXFR) allowed — alleksy.com", cwe: "CWE-538", severity: "high" }),
      bf({ title: "No CAA record — alleksy.com", cwe: "CWE-295", severity: "low" }),
      bf({
        title: "Exposed credentials / email in known breaches — alleksy.com",
        cwe: "CWE-359",
        severity: "medium",
      }),
      bf({ title: "TLS configuration weakness", cwe: "CWE-326", severity: "medium" }),
    ];
    const res = mapBackendFindingsToResults(raw, "premium");
    const groups = groupsOf(res.findings);
    expect(groups.has("Email Security")).toBe(true);
    expect(groups.has("DNSSEC")).toBe(true);
    expect(groups.has("DNS")).toBe(true); // AXFR + CAA
    expect(groups.has("Data Exposure")).toBe(true);
    expect(groups.has("Transport Security")).toBe(true);
  });

  it("keeps CAA in DNS, not Transport Security (mentions 'certificates')", () => {
    const res = mapBackendFindingsToResults(
      [bf({ title: "No CAA record — alleksy.com", description: "any public CA may issue certificates", cwe: "CWE-295" })],
      "premium"
    );
    expect(res.findings[0].group).toBe("DNS");
  });

  it("does not misroute a plain web finding", () => {
    const res = mapBackendFindingsToResults(
      [bf({ title: "Reflected XSS in q", cwe: "CWE-79", owasp_category: "A05" })],
      "premium"
    );
    const groups = groupsOf(res.findings);
    expect(groups.has("DNS")).toBe(false);
    expect(groups.has("Email Security")).toBe(false);
  });
});
