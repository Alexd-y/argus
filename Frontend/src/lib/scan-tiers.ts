export type ScanTier = "free" | "standard" | "premium";

export interface TierConfig {
  id: ScanTier;
  name: string;
  tagline: string;
  priceLabel: string;
  priceCents: number | null;
  currency: string | null;
  description: string;
  popular?: boolean;
  features: { text: string; included: boolean }[];
}

export const SCAN_TIERS: TierConfig[] = [
  {
    id: "free",
    name: "Midgard",
    tagline: "Surface-level overview",
    priceLabel: "Free",
    priceCents: null,
    currency: null,
    description:
      "Basic vulnerability overview. See what was found, not how to fix it.",
    features: [
      { text: "Issue count by severity", included: true },
      { text: "Web server, CMS, and framework detection", included: true },
      { text: "1–2 critical vulnerabilities (summary only)", included: true },
      { text: "Data breach check (yes/no)", included: true },
      { text: "Detailed vulnerability descriptions", included: false },
      { text: "Remediation recommendations", included: false },
      { text: "SSL/TLS and headers analysis", included: false },
      { text: "Leaked email addresses", included: false },
    ],
  },
  {
    id: "standard",
    name: "Asgard",
    tagline: "Deep insights & guidance",
    priceLabel: "CA$1,891/month",
    priceCents: 189100,
    currency: "cad",
    description:
      "Deep scan with remediation guidance, SSL/headers analysis, masked leak data.",
    popular: true,
    features: [
      { text: "Everything in Midgard", included: true },
      { text: "Full outdated technology and version list", included: true },
      { text: "Detailed medium & high severity vulnerabilities", included: true },
      { text: "Leaked email addresses (partially masked)", included: true },
      { text: "Basic remediation recommendations", included: true },
      { text: "SSL/TLS configuration analysis", included: true },
      { text: "HTTP security headers analysis", included: true },
      { text: "Step-by-step remediation instructions", included: false },
      { text: "30-day follow-up scan", included: false },
    ],
  },
  {
    id: "premium",
    name: "Valhalla",
    tagline: "Elite full protection",
    priceLabel: "CA$2,947/month",
    priceCents: 294700,
    currency: "cad",
    description:
      "Full audit with step-by-step fixes, prioritization roadmap, 30-day follow-up scan.",
    features: [
      { text: "Everything in Asgard", included: true },
      { text: "All vulnerabilities including low severity", included: true },
      { text: "Step-by-step remediation for each issue", included: true },
      { text: "Fix prioritization roadmap", included: true },
      { text: "Password leak information (hashed)", included: true },
      { text: "Server configuration and hardening review", included: true },
      { text: "Dark web monitoring results", included: true },
      { text: "Follow-up scan after 30 days", included: true },
    ],
  },
];

export const SCAN_STAGES = [
  "Initializing",
  "Port scanning",
  "Service detection",
  "Vulnerability assessment",
  "Generating report",
] as const;

export function getTierConfig(tier: ScanTier): TierConfig {
  const config = SCAN_TIERS.find((t) => t.id === tier);
  if (!config) throw new Error(`Unknown tier: ${tier}`);
  return config;
}

export function isPaidTier(tier: ScanTier): boolean {
  return tier !== "free";
}

export function getUpgradeTiers(currentTier: ScanTier): TierConfig[] {
  if (currentTier === "free") {
    return SCAN_TIERS.filter((t) => t.id !== "free");
  }
  if (currentTier === "standard") {
    return SCAN_TIERS.filter((t) => t.id === "premium");
  }
  return [];
}

export function getScanCtaLabel(tier: ScanTier): string {
  if (tier === "free") return "Start Free Scan";
  if (tier === "standard") return "Start Deep Scan";
  return "Start Full Audit";
}
