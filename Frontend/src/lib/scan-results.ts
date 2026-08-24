import type { ScanTier } from "./scan-tiers";

export type CheckStatus = "fail" | "pass" | "warning";
export type CheckPriority = "critical" | "important" | "medium" | "optional";

export interface FindingProbe {
  port: number;
  templatePath: string;
  templateId: string;
  matcher: string;
  matchedAt: string;
  ipAddress: string;
  tags: string[];
  extractedResults: string[];
}

export interface Finding {
  id: string;
  groupId: string;
  group: string;
  name: string;
  status: CheckStatus;
  priority: CheckPriority;
  headline: string;
  explanation: string;
  evidence: string;
  remediation: string;
  detailLevel: "summary" | "full";
  access: "title" | "summary" | "basic" | "full";
  probe?: FindingProbe;
  riskScore?: number | null;
}

export type LeakSecretKind = "plaintext" | "hash";
export type LeakIdentityKind = "email" | "username";
export type LeakAccess = "locked" | "summary" | "full";

export interface CredentialLeak {
  id: string;
  /** Email address or bare username, depending on what the dump stored. */
  identity: string;
  identityKind: LeakIdentityKind;
  source: string;
  breachedAt: string;
  exposed: string[];
  secretKind: LeakSecretKind;
  /** Hashing algorithm when the dump stored hashes, null when the password was stored in the clear. */
  algorithm: string | null;
  /** Redacted password or hash prefix. Never the full secret. */
  secret: string;
  access: LeakAccess;
}

export type LeakSeed = Omit<CredentialLeak, "access">;

export interface ScanResults {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  passed: number;
  technologies: string[];
  sslIssues: number | null;
  headerIssues: number | null;
  /** Discovered hosts under the target. Null when the tier does not include subdomain discovery. */
  subdomains: string[] | null;
  leaksFound: boolean;
  leaks?: CredentialLeak[];
  findings: Finding[];
  totalFindings: number;
}

const ALLEKSY_IP = "172.67.204.159";
type AlleksyCheck = Omit<Finding, "detailLevel" | "probe" | "access"> & {
  probe: FindingProbe;
};

function dnsProbe(templateId: string, matcher: string, matchedAt: string, tags: string[], extracted: string): FindingProbe {
  return {
    port: 53,
    templatePath: `/user/data/nuclei-templates/dns/${templateId}.yaml`,
    templateId,
    matcher,
    matchedAt,
    ipAddress: ALLEKSY_IP,
    tags,
    extractedResults: [extracted],
  };
}

function httpsProbe(
  folder: string,
  templateId: string,
  matcher: string,
  tags: string[],
  extracted: string[],
  matchedAt = "alleksy.com:443"
): FindingProbe {
  return {
    port: 443,
    templatePath: `/user/data/nuclei-templates/${folder}/${templateId}.yaml`,
    templateId,
    matcher,
    matchedAt,
    ipAddress: ALLEKSY_IP,
    tags,
    extractedResults: extracted,
  };
}

function missingHeader(
  id: string,
  header: string,
  matcher: string,
  priority: CheckPriority,
  headline: string,
  remediation: string
): AlleksyCheck {
  return {
    id,
    groupId: "3",
    group: "HTTP Security Headers",
    name: header,
    status: "fail",
    priority,
    headline,
    explanation: `Browsers use the ${header} response header to lock down how alleksy.com can be framed, loaded, or referred. It is not present on https://alleksy.com/.`,
    evidence: `GET https://alleksy.com/\nHTTP/2 200\n;; ${header} header not present.`,
    remediation,
    probe: httpsProbe(
      "http/misconfiguration",
      "http-missing-security-headers",
      matcher,
      ["misc", "misconfig", "headers"],
      [`[${header} missing]`]
    ),
  };
}

const ALLEKSY_CHECKS: AlleksyCheck[] = [
  {
    id: "1.1",
    groupId: "1",
    group: "Email Authentication",
    name: "SPF Record Check",
    status: "fail",
    priority: "critical",
    headline: "We haven't found a single SPF record for your domain.",
    explanation:
      "SPF lists which servers may send mail for this domain. Without it, anyone can spoof mail from alleksy.com.",
    evidence: "DIG TXT alleksy.com\n;; no SPF record (v=spf1) present at the apex.",
    remediation: "Publish TXT at alleksy.com, for example: v=spf1 include:_spf.google.com -all",
    probe: dnsProbe("missing-spf", "no-spf", "alleksy.com:53", ["dns", "spf", "email", "misconfig"], "[no SPF record (v=spf1) at apex]"),
  },
  {
    id: "1.2",
    groupId: "1",
    group: "Email Authentication",
    name: "DKIM (DomainKeys Identified Mail)",
    status: "fail",
    priority: "important",
    headline: "No DKIM record found.",
    explanation:
      "DKIM signs outbound mail so receivers can verify it was not altered. No selector is published for alleksy.com.",
    evidence: "DIG TXT default._domainkey.alleksy.com\n;; NXDOMAIN — no selector published.",
    remediation: "Enable DKIM at your mail provider and publish the selector TXT they give you.",
    probe: dnsProbe("missing-dkim", "nxdomain", "default._domainkey.alleksy.com:53", ["dns", "dkim", "email", "misconfig"], "[NXDOMAIN — no DKIM selector published]"),
  },
  {
    id: "1.3",
    groupId: "1",
    group: "Email Authentication",
    name: "DMARC",
    status: "fail",
    priority: "critical",
    headline: "DMARC record is not found.",
    explanation:
      "DMARC tells receivers what to do when SPF or DKIM fails. Without a policy, spoofed mail is not quarantined or rejected.",
    evidence: "DIG TXT _dmarc.alleksy.com\n;; NXDOMAIN — no v=DMARC1 record.",
    remediation: "Publish TXT at _dmarc.alleksy.com starting with v=DMARC1; p=none; rua=mailto:dmarc@alleksy.com",
    probe: dnsProbe("missing-dmarc", "nxdomain", "_dmarc.alleksy.com:53", ["dns", "dmarc", "email", "vuln"], "[NXDOMAIN — no v=DMARC1 record]"),
  },
  {
    id: "1.4",
    groupId: "1",
    group: "Email Authentication",
    name: "BIMI",
    status: "fail",
    priority: "optional",
    headline: "No BIMI record found.",
    explanation:
      "BIMI can show a brand logo in supporting inboxes. It needs DMARC at quarantine or reject first. Optional for deliverability.",
    evidence: "DIG TXT default._bimi.alleksy.com\n;; NXDOMAIN.",
    remediation: "After DMARC is enforced, publish a BIMI TXT and host an SVG logo.",
    probe: dnsProbe("missing-bimi", "nxdomain", "default._bimi.alleksy.com:53", ["dns", "bimi", "email"], "[NXDOMAIN]"),
  },
  {
    id: "2.1",
    groupId: "2",
    group: "Domain & Encryption",
    name: "TLS (Transport Layer Security)",
    status: "pass",
    priority: "important",
    headline: "TLS 1.2 and TLS 1.3 are supported. Certificate is valid.",
    explanation:
      "HTTPS on alleksy.com negotiates modern TLS. Certificate CN=alleksy.com, issued by Let's Encrypt.",
    evidence: "CN=alleksy.com\nIssuer=Let's Encrypt R3\nProtocols=TLS 1.2, TLS 1.3",
    remediation: "Keep TLS 1.2/1.3. Disable leftover TLS 1.1 ciphers (see 2.5) and consider HSTS.",
    probe: httpsProbe("ssl", "tls-version", "tls-1-2-1-3", ["ssl", "tls", "cert"], [
      "[tls12 TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256]",
      "[tls13 TLS_AES_256_GCM_SHA384]",
    ]),
  },
  {
    id: "2.2",
    groupId: "2",
    group: "Domain & Encryption",
    name: "DNSSEC",
    status: "fail",
    priority: "important",
    headline: "DNSSEC is not enabled.",
    explanation: "The zone is unsigned: no DS record at the parent, so resolvers cannot detect spoofed DNS.",
    evidence: "DIG DS alleksy.com +dnssec\n;; no DS at parent. AD flag not set.",
    remediation: "Enable DNSSEC at the DNS host, then add the DS record at the registrar.",
    probe: dnsProbe("dnssec-disabled", "no-ds", "alleksy.com:53", ["dns", "dnssec", "misconfig"], "[no DS at parent; AD flag not set]"),
  },
  {
    id: "2.3",
    groupId: "2",
    group: "Domain & Encryption",
    name: "MTA-STS",
    status: "fail",
    priority: "optional",
    headline: "MTA-STS is not found.",
    explanation: "MTA-STS tells senders that inbound SMTP must use TLS. Optional; complements SPF/DKIM/DMARC.",
    evidence: "DIG TXT _mta-sts.alleksy.com\n;; record and policy file not found.",
    remediation: "Publish _mta-sts.alleksy.com TXT and serve https://mta-sts.alleksy.com/.well-known/mta-sts.txt",
    probe: httpsProbe("dns", "missing-mta-sts", "policy-missing", ["dns", "smtp", "mta-sts"], [
      "[TXT _mta-sts.alleksy.com NXDOMAIN]",
    ], "mta-sts.alleksy.com:443"),
  },
  {
    id: "2.4",
    groupId: "2",
    group: "Domain & Encryption",
    name: "TLS-RPT",
    status: "fail",
    priority: "optional",
    headline: "TLS-RPT is not found.",
    explanation: "SMTP TLS Reporting tells senders where to report TLS failures. Useful once MTA-STS is in place.",
    evidence: "DIG TXT _smtp._tls.alleksy.com\n;; NXDOMAIN.",
    remediation: "Publish TXT _smtp._tls.alleksy.com with v=TLSRPTv1; rua=mailto:tlsrpt@alleksy.com",
    probe: dnsProbe("missing-tls-rpt", "nxdomain", "_smtp._tls.alleksy.com:53", ["dns", "smtp", "tls-rpt"], "[NXDOMAIN]"),
  },
  {
    id: "2.5",
    groupId: "2",
    group: "Domain & Encryption",
    name: "Weak Cipher Suites",
    status: "fail",
    priority: "important",
    headline: "TLS 1.1 is still offered with a CBC cipher suite.",
    explanation:
      "Modern browsers prefer TLS 1.2/1.3, but the edge still accepts TLS 1.1 with TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA. CBC suites on TLS 1.1 are considered weak.",
    evidence: "Matched at alleksy.com:443\n[tls11 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA]",
    remediation: "Disable TLS 1.0/1.1 and CBC ciphers on the Cloudflare SSL/TLS edge settings. Allow TLS 1.2+ only.",
    probe: httpsProbe("ssl", "weak-cipher-suites", "tls-1.1", ["ssl", "tls", "misconfig", "vuln"], [
      "[tls11 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA]",
    ]),
  },
  {
    id: "2.6",
    groupId: "2",
    group: "Domain & Encryption",
    name: "CAA Record",
    status: "fail",
    priority: "optional",
    headline: "No CAA record found.",
    explanation: "CAA (Certification Authority Authorization) limits which CAs may issue certificates for alleksy.com.",
    evidence: "DIG CAA alleksy.com\n;; no CAA records.",
    remediation: "Publish CAA at the apex, e.g. 0 issue \"letsencrypt.org\"",
    probe: dnsProbe("missing-caa", "no-caa", "alleksy.com:53", ["dns", "caa", "ssl"], "[no CAA records]"),
  },
  missingHeader(
    "3.1",
    "Strict-Transport-Security",
    "strict-transport-security",
    "important",
    "HSTS header is not set.",
    "Add Strict-Transport-Security: max-age=63072000; includeSubDomains; preload"
  ),
  missingHeader(
    "3.2",
    "Content-Security-Policy",
    "content-security-policy",
    "important",
    "Content-Security-Policy header is not set.",
    "Add a CSP that defaults to self and explicitly allows required scripts, styles, and connections."
  ),
  missingHeader(
    "3.3",
    "X-Frame-Options",
    "x-frame-options",
    "important",
    "X-Frame-Options header is not set.",
    "Add X-Frame-Options: DENY (or SAMEORIGIN) and a matching CSP frame-ancestors directive."
  ),
  missingHeader(
    "3.4",
    "X-Content-Type-Options",
    "x-content-type-options",
    "important",
    "X-Content-Type-Options header is not set.",
    "Add X-Content-Type-Options: nosniff"
  ),
  missingHeader(
    "3.5",
    "Referrer-Policy",
    "referrer-policy",
    "optional",
    "Referrer-Policy header is not set.",
    "Add Referrer-Policy: strict-origin-when-cross-origin"
  ),
  missingHeader(
    "3.6",
    "Permissions-Policy",
    "permissions-policy",
    "optional",
    "Permissions-Policy header is not set.",
    "Add Permissions-Policy to disable unused browser features (camera, microphone, geolocation)."
  ),
  missingHeader(
    "3.7",
    "Cross-Origin-Opener-Policy",
    "cross-origin-opener-policy",
    "optional",
    "Cross-Origin-Opener-Policy header is not set.",
    "Add Cross-Origin-Opener-Policy: same-origin if the site does not need window.opener."
  ),
  missingHeader(
    "3.8",
    "Cross-Origin-Resource-Policy",
    "cross-origin-resource-policy",
    "optional",
    "Cross-Origin-Resource-Policy header is not set.",
    "Add Cross-Origin-Resource-Policy: same-origin or same-site as appropriate."
  ),
  missingHeader(
    "3.9",
    "Cross-Origin-Embedder-Policy",
    "cross-origin-embedder-policy",
    "optional",
    "Cross-Origin-Embedder-Policy header is not set.",
    "Add Cross-Origin-Embedder-Policy: require-corp only if you intend to enable cross-origin isolation."
  ),
  missingHeader(
    "3.10",
    "X-Permitted-Cross-Domain-Policies",
    "x-permitted-cross-domain-policies",
    "optional",
    "X-Permitted-Cross-Domain-Policies header is not set.",
    "Add X-Permitted-Cross-Domain-Policies: none"
  ),
  {
    id: "4.1",
    groupId: "4",
    group: "Exposure & Fingerprints",
    name: "WAF Detection",
    status: "pass",
    priority: "optional",
    headline: "Cloudflare WAF is in front of the origin.",
    explanation: "Responses include Cloudflare fingerprints (cf-ray, server: cloudflare). This is informational.",
    evidence: "GET https://alleksy.com/\nserver: cloudflare\ncf-ray: present",
    remediation: "No action required. Keep WAF rules current and avoid bypassing Cloudflare to the origin IP.",
    probe: httpsProbe("http/technologies", "waf-detect", "cloudflare", ["tech", "waf", "cloudflare"], ["[cloudflare]"]),
  },
  {
    id: "4.2",
    groupId: "4",
    group: "Exposure & Fingerprints",
    name: "robots.txt",
    status: "fail",
    priority: "optional",
    headline: "robots.txt is publicly reachable.",
    explanation: "https://alleksy.com/robots.txt is served. That is normal, but it can hint at paths you would rather not advertise.",
    evidence: "GET https://alleksy.com/robots.txt\nHTTP/2 200",
    remediation: "Keep robots.txt if you need it. Do not list sensitive admin paths; protect those with auth instead.",
    probe: httpsProbe("http/exposures", "robots-txt", "robots", ["exposure", "misc"], ["[User-agent: *]"], "https://alleksy.com/robots.txt"),
  },
  {
    id: "4.3",
    groupId: "4",
    group: "Exposure & Fingerprints",
    name: "HTTP/2 Rapid Reset (CVE-2023-44487)",
    status: "fail",
    priority: "important",
    headline: "HTTP/2 is enabled; Rapid Reset mitigations should be confirmed on the edge.",
    explanation:
      "HTTP/2 Rapid Reset (CVE-2023-44487) can flood a server with RST_STREAM frames. Cloudflare generally mitigates this, but it still appears as a finding on HTTP/2 hosts.",
    evidence: "ALPN=h2 on alleksy.com:443\nCVE-2023-44487",
    remediation: "Stay on a current Cloudflare plan/proxy. Do not expose an unpatched origin HTTP/2 listener directly.",
    probe: httpsProbe("http/cves/2023", "CVE-2023-44487", "http2", ["cve", "http2", "dos"], ["[HTTP/2 enabled]"]),
  },
  {
    id: "4.4",
    groupId: "4",
    group: "Exposure & Fingerprints",
    name: "security.txt",
    status: "fail",
    priority: "optional",
    headline: "RFC 9116 security.txt is not published.",
    explanation: "There is no /.well-known/security.txt, so researchers have no stated way to report issues.",
    evidence: "GET https://alleksy.com/.well-known/security.txt\nHTTP/2 404",
    remediation: "Publish security.txt with a contact email and preferred language.",
    probe: httpsProbe("http/misconfiguration", "missing-security-txt", "404", ["misc", "securitytxt"], ["[404]"], "https://alleksy.com/.well-known/security.txt"),
  },
  {
    id: "4.5",
    groupId: "4",
    group: "Exposure & Fingerprints",
    name: "Server Fingerprint",
    status: "fail",
    priority: "optional",
    headline: "Server header discloses Cloudflare.",
    explanation: "The Server response header is set to cloudflare, which fingerprints the edge vendor.",
    evidence: "GET https://alleksy.com/\nserver: cloudflare",
    remediation: "Optional. Cloudflare sets this by default; removing it has limited security value behind a WAF.",
    probe: httpsProbe("http/misconfiguration", "server-fingerprint", "server-header", ["misc", "fingerprint"], ["[server: cloudflare]"]),
  },
  {
    id: "4.6",
    groupId: "4",
    group: "Exposure & Fingerprints",
    name: "Subresource Integrity",
    status: "fail",
    priority: "optional",
    headline: "Third-party scripts are loaded without SRI.",
    explanation: "If the homepage loads CDN scripts without integrity attributes, a compromised CDN could run code in your origin's context.",
    evidence: "GET https://alleksy.com/\n;; script tags without integrity= observed.",
    remediation: "Add integrity and crossorigin attributes on third-party <script> and <link> tags, or self-host them.",
    probe: httpsProbe("http/misconfiguration", "missing-sri", "no-integrity", ["misc", "sri"], ["[script without integrity]"]),
  },
  {
    id: "4.7",
    groupId: "4",
    group: "Exposure & Fingerprints",
    name: "X-XSS-Protection (deprecated)",
    status: "fail",
    priority: "optional",
    headline: "Deprecated X-XSS-Protection header is not set — and should stay unset.",
    explanation:
      "X-XSS-Protection is obsolete and can introduce XSS in old IE. The scanner still flags its absence; the fix is CSP, not restoring this header.",
    evidence: "GET https://alleksy.com/\n;; X-XSS-Protection not present (expected).",
    remediation: "Do not add X-XSS-Protection. Rely on Content-Security-Policy instead.",
    probe: httpsProbe("http/misconfiguration", "http-missing-security-headers", "x-xss-protection", ["misc", "headers", "deprecated"], ["[X-XSS-Protection missing]"]),
  },
];

const STACK = ["HTTPS", "Let's Encrypt", "TLS 1.2 / 1.3", "Cloudflare"];

/** Sample hosts discovered under the apex for Full Surface demo / sample reports. */
const SAMPLE_SUBDOMAINS = ["www", "mail", "api", "staging", "cdn"];

export function apexHostname(target: string): string {
  return target
    .replace(/^https?:\/\//, "")
    .split("/")[0]
    .split(":")[0]
    .toLowerCase()
    .replace(/^www\./, "");
}

/** Hosts under the apex that are not the apex itself (www counts as a subdomain). */
export function collectSubdomains(hosts: string[], target: string): string[] {
  const apex = apexHostname(target);
  if (!apex) return [];
  const found = new Set<string>();
  for (const raw of hosts) {
    const host = raw
      .replace(/^https?:\/\//, "")
      .split("/")[0]
      .split(":")[0]
      .toLowerCase();
    if (!host || host === apex) continue;
    if (host.endsWith(`.${apex}`)) found.add(host);
  }
  return [...found].sort((a, b) => a.localeCompare(b));
}

export function sampleSubdomainsFor(target: string): string[] {
  const apex = apexHostname(target);
  return SAMPLE_SUBDOMAINS.map((label) => `${label}.${apex}`);
}

export function subdomainsForTier(tier: ScanTier, hosts: string[], target: string): string[] | null {
  if (tier !== "premium") return null;
  return collectSubdomains(hosts, target);
}

const ALLEKSY_LEAKS: LeakSeed[] = [
  {
    id: "L1",
    identity: "admin@alleksy.com",
    identityKind: "email",
    source: "Collection #1 combo list",
    breachedAt: "January 2019",
    exposed: ["Email", "Password hash", "Username"],
    secretKind: "hash",
    algorithm: "SHA-1 (unsalted)",
    secret: "5baa61e4c9b93f3f…",
  },
  {
    id: "L2",
    identity: "billing@alleksy.com",
    identityKind: "email",
    source: "Marketing SaaS dump",
    breachedAt: "June 2021",
    exposed: ["Email", "Password", "Full name", "IP address"],
    secretKind: "plaintext",
    algorithm: null,
    secret: "Sp••••••••23",
  },
  {
    id: "L3",
    identity: "wp_admin",
    identityKind: "username",
    source: "CMS plugin marketplace breach",
    breachedAt: "August 2022",
    exposed: ["Username", "Password hash", "Site URL"],
    secretKind: "hash",
    algorithm: "MD5 (WordPress portable)",
    secret: "$P$Bp.ZDNMM98…",
  },
  {
    id: "L4",
    identity: "support@alleksy.com",
    identityKind: "email",
    source: "Helpdesk vendor breach",
    breachedAt: "March 2022",
    exposed: ["Email", "Password hash", "Phone"],
    secretKind: "hash",
    algorithm: "bcrypt (cost 10)",
    secret: "$2y$10$N9qo8uIO…",
  },
  {
    id: "L5",
    identity: "svc_backup",
    identityKind: "username",
    source: "VPN appliance credential dump",
    breachedAt: "May 2023",
    exposed: ["Username", "Password", "Host"],
    secretKind: "plaintext",
    algorithm: null,
    secret: "Ba••••••2019",
  },
  {
    id: "L6",
    identity: "j.hansen@alleksy.com",
    identityKind: "email",
    source: "Fitness app breach",
    breachedAt: "February 2018",
    exposed: ["Email", "Password hash", "Username", "Date of birth"],
    secretKind: "hash",
    algorithm: "SHA-1 (unsalted)",
    secret: "b1b3773a05c0ed01…",
  },
  {
    id: "L7",
    identity: "dev@alleksy.com",
    identityKind: "email",
    source: "Git hosting credential stuffing list",
    breachedAt: "November 2023",
    exposed: ["Email", "Password", "API token"],
    secretKind: "plaintext",
    algorithm: null,
    secret: "de••••••!",
  },
];

function maskIdentity(identity: string): string {
  const [local, domain] = identity.split("@");
  const dots = "•".repeat(Math.max(local.length - 2, 3));
  const masked = `${local.slice(0, 2)}${dots}`;
  return domain ? `${masked}@${domain}` : masked;
}

export function withLeakAccess(leaks: LeakSeed[], tier: ScanTier): CredentialLeak[] {
  return leaks.map((leak) => {
    if (tier === "premium") {
      return { ...leak, access: "full" as const };
    }
    if (tier === "standard") {
      return { ...leak, secret: "", algorithm: null, access: "summary" as const };
    }
    return {
      ...leak,
      identity: maskIdentity(leak.identity),
      source: "",
      exposed: [],
      secret: "",
      algorithm: null,
      access: "locked" as const,
    };
  });
}

export interface LeakSummary {
  accounts: number;
  sources: number;
  plaintext: number;
  hashed: number;
}

export function summarizeLeaks(leaks: CredentialLeak[]): LeakSummary {
  return {
    accounts: leaks.length,
    sources: new Set(leaks.map((leak) => leak.source).filter(Boolean)).size,
    plaintext: leaks.filter((leak) => leak.secretKind === "plaintext").length,
    hashed: leaks.filter((leak) => leak.secretKind === "hash").length,
  };
}

const PRIORITY_RANK: Record<CheckPriority, number> = {
  critical: 0,
  important: 1,
  medium: 2,
  optional: 3,
};

export function midgardWriteupId(findings: Array<{ id: string; status: CheckStatus; priority: CheckPriority; riskScore?: number | null }>): string | null {
  const failed = findings.filter((item) => item.status === "fail");
  const pool = failed.length > 0 ? failed : findings;
  if (pool.length === 0) return null;
  const ranked = [...pool].sort((a, b) => {
    const byPriority = PRIORITY_RANK[a.priority] - PRIORITY_RANK[b.priority];
    if (byPriority !== 0) return byPriority;
    return (b.riskScore ?? 0) - (a.riskScore ?? 0);
  });
  return ranked[0]?.id ?? null;
}

export type FindingAccess = Finding["access"];

export function accessForPriority(
  tier: ScanTier,
  priority: CheckPriority,
  id: string,
  writeupId: string | null
): Finding["access"] {
  if (tier === "premium") return "full";
  if (tier === "standard") {
    return priority === "critical" || priority === "important" ? "basic" : "title";
  }
  return writeupId && id === writeupId ? "basic" : "title";
}

export function withTierAccess(findings: Finding[], tier: ScanTier, writeupId: string | null): Finding[] {
  return findings.map((check) => {
    const access = accessForPriority(tier, check.priority, check.id, writeupId);
    const includeWriteup = access === "basic" || access === "full";
    return {
      ...check,
      access,
      detailLevel: includeWriteup ? "full" : "summary",
      explanation: access === "title" ? "" : access === "summary" ? check.headline : check.explanation,
      evidence: includeWriteup ? check.evidence : "",
      remediation: includeWriteup ? check.remediation : "",
      probe: access === "full" ? check.probe : undefined,
    };
  });
}

export function censusFromFindings(
  findings: Array<{ status: CheckStatus; priority: CheckPriority }>
): Pick<ScanResults, "critical" | "high" | "medium" | "low" | "passed" | "totalFindings"> {
  const failed = findings.filter((item) => item.status === "fail");
  return {
    critical: failed.filter((item) => item.priority === "critical").length,
    high: failed.filter((item) => item.priority === "important").length,
    medium: failed.filter((item) => item.priority === "medium").length,
    low: failed.filter((item) => item.priority === "optional").length,
    passed: findings.filter((item) => item.status === "pass").length,
    totalFindings: findings.length,
  };
}

function findingsForTier(tier: ScanTier): Finding[] {
  const full: Finding[] = ALLEKSY_CHECKS.map((check) => ({
    ...check,
    access: "full",
    detailLevel: "full",
  }));
  return withTierAccess(full, tier, midgardWriteupId(full));
}

function census() {
  return censusFromFindings(ALLEKSY_CHECKS);
}

function counts(
  findings: Finding[],
  extras: Pick<
    ScanResults,
    "technologies" | "sslIssues" | "headerIssues" | "subdomains" | "leaksFound" | "leaks" | "info"
  >
): ScanResults {
  return {
    ...census(),
    info: extras.info,
    technologies: extras.technologies,
    sslIssues: extras.sslIssues,
    headerIssues: extras.headerIssues,
    subdomains: extras.subdomains,
    leaksFound: extras.leaksFound,
    leaks: extras.leaks,
    findings,
  };
}

export function getResultsForTier(tier: ScanTier): ScanResults {
  const findings = findingsForTier(tier);
  const leaks = withLeakAccess(ALLEKSY_LEAKS, tier);
  const headerFails = ALLEKSY_CHECKS.filter((item) => item.groupId === "3" && item.status === "fail").length;
  const sslFails = ALLEKSY_CHECKS.filter((item) => item.groupId === "2" && item.status === "fail").length;
  const subdomains = tier === "premium" ? sampleSubdomainsFor("alleksy.com") : null;

  if (tier === "free") {
    return counts(findings, {
      technologies: ["HTTPS", "Cloudflare"],
      sslIssues: null,
      headerIssues: null,
      subdomains,
      leaksFound: leaks.length > 0,
      leaks,
      info: 0,
    });
  }

  return counts(findings, {
    technologies: STACK,
    sslIssues: sslFails,
    headerIssues: headerFails,
    subdomains,
    leaksFound: leaks.length > 0,
    leaks,
    info: 0,
  });
}

export function lockFindings(results: ScanResults): ScanResults {
  return {
    ...results,
    technologies: [],
    sslIssues: null,
    headerIssues: null,
    subdomains: null,
    leaks: results.leaks ? withLeakAccess(results.leaks, "free") : undefined,
    findings: results.findings.map((item) => ({
      ...item,
      evidence: "",
      remediation: "",
      explanation: item.headline,
      detailLevel: "summary",
      access: "title" as const,
      probe: undefined,
    })),
  };
}

export function localizeFindings(findings: Finding[], domain: string): Finding[] {
  const replace = (value: string) => value.replaceAll("alleksy.com", domain);
  return findings.map((item) => ({
    ...item,
    headline: replace(item.headline),
    explanation: replace(item.explanation),
    evidence: replace(item.evidence),
    remediation: replace(item.remediation),
    probe: item.probe
      ? {
          ...item.probe,
          matchedAt: replace(item.probe.matchedAt),
          extractedResults: item.probe.extractedResults.map(replace),
        }
      : undefined,
  }));
}

export function localizeResults(results: ScanResults, domain: string): ScanResults {
  return {
    ...results,
    subdomains: results.subdomains
      ? results.subdomains.map((host) => host.replaceAll("alleksy.com", domain))
      : results.subdomains,
    leaks: results.leaks?.map((leak) => ({
      ...leak,
      identity: leak.identity.replaceAll("alleksy.com", domain),
    })),
    findings: localizeFindings(results.findings, domain),
  };
}

export function groupFindings(findings: Finding[]): { groupId: string; group: string; findings: Finding[] }[] {
  const groups: { groupId: string; group: string; findings: Finding[] }[] = [];
  for (const finding of findings) {
    const existing = groups.find((group) => group.groupId === finding.groupId);
    if (existing) {
      existing.findings.push(finding);
    } else {
      groups.push({ groupId: finding.groupId, group: finding.group, findings: [finding] });
    }
  }
  return groups;
}
