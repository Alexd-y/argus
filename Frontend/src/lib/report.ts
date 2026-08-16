import type { ScanRecord } from "./scans";
import { getTierConfig } from "./scan-tiers";

export function buildReportText(scan: ScanRecord): string {
  const tier = getTierConfig(scan.tier);
  const results = scan.results;
  const lines: string[] = [
    "RAGNAROK SECURITY SCAN REPORT",
    "==============================",
    "",
    `Target:     ${scan.target}`,
    `Report:     ${tier.name}`,
    `Scan ID:    ${scan.id}`,
    `Email:      ${scan.email}`,
    `Completed:  ${scan.completedAt ?? "—"}`,
    "",
    "SECURITY ALERTS",
    "---------------",
  ];

  if (results) {
    lines.push(
      `Critical:   ${results.critical}`,
      `High:       ${results.high}`,
      `Medium:     ${results.medium}`,
      `Low:        ${results.low}`,
      `Info:       ${results.info}`,
      "",
      "FINDINGS",
      "--------",
      "",
      "Technologies:",
      ...results.technologies.map((t) => `  - ${t}`),
      "",
      `SSL/TLS issues:    ${results.sslIssues ?? "N/A"}`,
      `HTTP header issues: ${results.headerIssues ?? "N/A"}`,
      `Data breaches:     ${results.leaksFound ? "Detected" : "None found"}`,
    );

    if (results.leakEmails?.length) {
      lines.push("", "Leaked emails (masked):", ...results.leakEmails.map((e) => `  - ${e}`));
    }

    if (results.remediationNotes?.length) {
      lines.push("", "REMEDIATION", "-----------", ...results.remediationNotes.map((n) => `  • ${n}`));
    }
  }

  lines.push(
    "",
    "---",
    "Svalbard Security Inc. — https://svalbard.ca",
    "Authorized testing only.",
  );

  return lines.join("\n");
}
