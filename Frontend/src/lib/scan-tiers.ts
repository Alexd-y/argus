export type ScanTier = "free" | "standard" | "premium";

export interface TierConfig {
  id: ScanTier;
  name: string;
  /** Filename-safe form of `name`, used for downloads. */
  slug: string;
  priceLabel: string;
  priceCents: number | null;
  extraScanPriceLabel: string | null;
  extraScanPriceCents: number | null;
  currency: string | null;
  /** Scans of the same target included each billing period. Free is a single one-off scan. */
  scansPerPeriod: number;
  description: string;
  /** Shown under the report title to set expectations for the tier's depth. */
  reportSummary: string;
  popular?: boolean;
  features: { text: string; included: boolean }[];
}

export const MAX_EXTRA_SCANS = 3;
/** How every scan is performed, at every level. Humans come in later, for remediation. */
export const SCAN_METHOD_LABEL = "Automated external black box scanning";

/** A cell is either a yes/no mark or a short qualifier shown in place of the mark. */
export type ComparisonValue = boolean | string;

export interface ComparisonRow {
  label: string;
  hint?: string;
  values: Record<ScanTier, ComparisonValue>;
}

export interface ComparisonGroup {
  title: string;
  rows: ComparisonRow[];
}

export const SCAN_TIERS: TierConfig[] = [
  {
    id: "free",
    name: "Overview",
    slug: "overview",
    priceLabel: "Free",
    priceCents: null,
    extraScanPriceLabel: null,
    extraScanPriceCents: null,
    currency: null,
    scansPerPeriod: 1,
    description:
      "A free scan of the domain you own: severity counts, every finding title, and one complete writeup with evidence and a fix. No card required.",
    reportSummary:
      "A free overview of your external exposure. Every finding title plus one complete writeup, so you can judge the depth before you subscribe.",
    features: [
      { text: "Issue count by severity", included: true },
      { text: "Web server, CMS, and framework detection", included: true },
      { text: "All finding titles", included: true },
      { text: "One complete writeup (evidence and fix)", included: true },
      { text: "Downloadable PDF report", included: true },
      { text: "Optional dark web monitoring", included: true },
      { text: "What to fix for remaining findings", included: false },
      { text: "SSL/TLS and headers analysis", included: false },
      { text: "Subdomain discovery and testing", included: false },
    ],
  },
  {
    id: "standard",
    name: "Continuous",
    slug: "continuous",
    priceLabel: "CA$1,891/month",
    priceCents: 189100,
    extraScanPriceLabel: "CA$499",
    extraScanPriceCents: 49900,
    currency: "cad",
    scansPerPeriod: 4,
    description:
      "Unlocks every critical and important finding with evidence and what to fix, adds TLS and header analysis, and watches the dark web for leaked credentials. Rescans this target four times a month.",
    reportSummary:
      "Every critical and important finding unlocked with evidence and what to fix, plus TLS and header analysis and dark web monitoring. This target is rescanned monthly.",
    features: [
      { text: "Everything in Overview", included: true },
      { text: "This report unlocked", included: true },
      { text: "What to fix for critical and important findings", included: true },
      { text: "SSL/TLS and HTTP headers analysis", included: true },
      { text: "Dark web monitoring for this target", included: true },
      { text: "Password leak information (hashed)", included: true },
      { text: "Up to 4 scans per month of the same target", included: true },
      { text: "Buy up to 3 additional scans this period", included: true },
      { text: "How to fix, step by step", included: false },
      { text: "Subdomain discovery and testing", included: false },
    ],
  },
  {
    id: "premium",
    name: "Full Surface",
    slug: "full-surface",
    priceLabel: "CA$2,947/month",
    priceCents: 294700,
    extraScanPriceLabel: "CA$749",
    extraScanPriceCents: 74900,
    currency: "cad",
    scansPerPeriod: 6,
    description:
      "Everything in Continuous plus subdomain discovery and testing, low-severity findings, step-by-step fixes, a prioritized roadmap, and a server hardening review. Rescans this target six times a month.",
    reportSummary:
      "Our widest scan. We discover and test subdomains, unlock every finding down to low severity, and include step-by-step remediation with a prioritized fix roadmap.",
    popular: true,
    features: [
      { text: "Everything in Continuous", included: true },
      { text: "Subdomain discovery and testing", included: true },
      { text: "All findings, including low severity", included: true },
      { text: "How to fix each issue, step by step", included: true },
      { text: "Fix prioritization roadmap", included: true },
      { text: "Server configuration and hardening review", included: true },
      { text: "Up to 6 scans per month of the same target", included: true },
      { text: "Buy up to 3 additional scans this period", included: true },
    ],
  },
];

const extraScanValue = (tier: ScanTier): ComparisonValue => {
  const label = getTierConfig(tier).extraScanPriceLabel;
  return label ? `Up to ${MAX_EXTRA_SCANS} at ${label} each` : false;
};

const scanCadenceValue = (tier: ScanTier): ComparisonValue => {
  const { scansPerPeriod } = getTierConfig(tier);
  return scansPerPeriod > 1 ? `${scansPerPeriod} per month` : "One-off";
};

export const TIER_COMPARISON: ComparisonGroup[] = [
  {
    title: "What the scan covers",
    rows: [
      {
        label: "Issue count by severity",
        values: { free: true, standard: true, premium: true },
      },
      {
        label: "Web server, CMS, and framework detection",
        values: { free: true, standard: true, premium: true },
      },
      {
        label: "Scan scope",
        hint: `${SCAN_METHOD_LABEL}. Every level runs the same scanner — scope is what we point it at.`,
        values: {
          free: "Apex host",
          standard: "Apex host, TLS and headers",
          premium: "Apex host and subdomains",
        },
      },
      {
        label: "Findings included in the report",
        values: {
          free: "Titles only",
          standard: "Critical and important",
          premium: "All, including low",
        },
      },
      {
        label: "SSL/TLS and HTTP headers analysis",
        values: { free: false, standard: true, premium: true },
      },
      {
        label: "Server configuration and hardening review",
        values: { free: false, standard: false, premium: true },
      },
      {
        label: "Subdomain discovery and testing",
        values: { free: false, standard: false, premium: true },
      },
    ],
  },
  {
    title: "What you get per finding",
    rows: [
      {
        label: "Complete writeup with evidence",
        values: { free: "One sample finding", standard: true, premium: true },
      },
      {
        label: "What to fix",
        values: { free: false, standard: true, premium: true },
      },
      {
        label: "How to fix, step by step",
        values: { free: false, standard: false, premium: true },
      },
      {
        label: "Fix prioritization roadmap",
        values: { free: false, standard: false, premium: true },
      },
      {
        label: "Downloadable PDF report",
        values: { free: true, standard: true, premium: true },
      },
    ],
  },
  {
    title: "Monitoring",
    rows: [
      {
        label: "Dark web monitoring",
        values: { free: "Optional add-on", standard: true, premium: true },
      },
      {
        label: "Password leak information (hashed)",
        values: { free: false, standard: true, premium: true },
      },
    ],
  },
  {
    title: "Cadence and billing",
    rows: [
      {
        label: "Scans of the same target",
        values: {
          free: scanCadenceValue("free"),
          standard: scanCadenceValue("standard"),
          premium: scanCadenceValue("premium"),
        },
      },
      {
        label: "Additional scans if you run out",
        values: {
          free: false,
          standard: extraScanValue("standard"),
          premium: extraScanValue("premium"),
        },
      },
      {
        label: "Commitment",
        values: {
          free: "None",
          standard: "Monthly, cancel anytime",
          premium: "Monthly, cancel anytime",
        },
      },
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

export function getScansPerPeriod(tier: ScanTier): number {
  return getTierConfig(tier).scansPerPeriod;
}

export function includesDarkWebMonitoring(tier: ScanTier, optedIn?: boolean): boolean {
  return isPaidTier(tier) || Boolean(optedIn);
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

export function isScanUnlocked(scan: { tier: ScanTier; paid: boolean }): boolean {
  return scan.tier === "free" || scan.paid;
}

export function getScanCtaLabel(tier: ScanTier): string {
  if (tier === "free") return "Start free scan";
  if (tier === "standard") return "Start Continuous scan";
  return "Start Full Surface scan";
}

export function getUnlockCtaLabel(tier: ScanTier): string {
  const config = getTierConfig(tier);
  return `Unlock ${config.name} — ${config.priceLabel}`;
}

export function getUnlockBody(tier: ScanTier, target: string): string {
  const scans = getScansPerPeriod(tier);
  if (tier === "standard") {
    return `Counts and titles above are from this scan of ${target}. Continuous unlocks every critical and important finding in this report with evidence and what to fix, adds dark web monitoring, and rescans this target up to ${scans} times a month so you can confirm fixes landed. You can buy up to ${MAX_EXTRA_SCANS} additional scans if those run out.`;
  }
  return `Counts and titles above are from this scan of ${target}. Full Surface unlocks every finding in this report down to low severity with step-by-step fixes, adds subdomain discovery and testing plus dark web monitoring, and rescans this target up to ${scans} times a month so you can confirm fixes landed. You can buy up to ${MAX_EXTRA_SCANS} additional scans if those run out.`;
}

export function includesSubdomainDiscovery(tier: ScanTier): boolean {
  return tier === "premium";
}

export function getExtraScanCtaLabel(tier: ScanTier, extraBought = 0): string {
  const config = getTierConfig(tier);
  const next = extraBought + 1;
  return `Buy extra ${next} of ${MAX_EXTRA_SCANS} — ${config.extraScanPriceLabel}`;
}
