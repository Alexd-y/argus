import type { ScanTier } from "./scan-tiers";

export interface ScanResults {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  technologies: string[];
  sslIssues: number | null;
  headerIssues: number | null;
  leaksFound: boolean;
  leakEmails?: string[];
  remediationNotes?: string[];
}

const BASE_RESULTS: ScanResults = {
  critical: 0,
  high: 2,
  medium: 1,
  low: 0,
  info: 32,
  technologies: ["Apache/2.4.52", "PHP/8.1.2", "WordPress 6.4.2", "MySQL"],
  sslIssues: 2,
  headerIssues: 5,
  leaksFound: true,
};

export function getResultsForTier(tier: ScanTier): ScanResults {
  if (tier === "free") {
    return {
      ...BASE_RESULTS,
      sslIssues: null,
      headerIssues: null,
    };
  }

  if (tier === "standard") {
    return {
      ...BASE_RESULTS,
      low: 3,
      leakEmails: ["a***@example.com", "b***@example.com"],
      remediationNotes: [
        "Upgrade WordPress to the latest stable version",
        "Enable HSTS and review TLS cipher configuration",
      ],
    };
  }

  return {
    ...BASE_RESULTS,
    critical: 1,
    low: 8,
    leakEmails: ["a***@example.com", "b***@example.com", "c***@example.com"],
    remediationNotes: [
      "Patch CVE-2024-XXXX in WordPress core immediately",
      "Rotate exposed API keys and enforce MFA for admin accounts",
      "Harden Apache configuration and disable unnecessary modules",
      "Schedule follow-up scan in 30 days to verify remediation",
    ],
  };
}

/** Generic preview shown before paid report unlock — not tied to any target */
export const PLACEHOLDER_FINDINGS: ScanResults = {
  critical: 0,
  high: 2,
  medium: 3,
  low: 1,
  info: 28,
  technologies: ["nginx/1.24", "Node.js 20.x", "React 18", "PostgreSQL 15"],
  sslIssues: 3,
  headerIssues: 4,
  leaksFound: true,
  leakEmails: ["u***@domain.com", "a***@domain.com"],
  remediationNotes: [
    "Update outdated framework dependencies to patched versions",
    "Enable HSTS and configure Content-Security-Policy headers",
    "Review and restrict exposed administrative endpoints",
    "Rotate credentials found in public configuration files",
  ],
};
