"use client";

import React, { useState, useMemo, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { useScanProgress } from "@/hooks/useScanProgress";

type ScanType = "quick" | "light" | "deep" | "lab";
type ReportFormat = "pdf" | "html" | "json" | "xml";
type RateLimit = "slow" | "normal" | "fast" | "aggressive";
type UserAgentOption = "chrome" | "firefox" | "mobile" | "bot";

const USER_AGENTS: Record<UserAgentOption, { label: string; value: string }> = {
  chrome: {
    label: "Chrome",
    value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  },
  firefox: {
    label: "Firefox",
    value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
  },
  mobile: {
    label: "Mobile",
    value: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
  },
  bot: {
    label: "Bot",
    value: "RagnarokBot/4.2.11 (+https://svalbard.ca/ragnarok)",
  },
};

interface ScanOptions {
  scanType: ScanType;
  reportFormat: ReportFormat;
  rateLimit: RateLimit;
  ports: string;
  followRedirects: boolean;
  vulnerabilities: {
    xss: boolean;
    sqli: boolean;
    csrf: boolean;
    ssrf: boolean;
    lfi: boolean;
    rce: boolean;
    idor: boolean;
    ssti: boolean;
    xxe: boolean;
    headers: boolean;
  };
  authentication: {
    enabled: boolean;
    type: "basic" | "bearer" | "cookie";
    username: string;
    password: string;
    token: string;
  };
  scope: {
    maxDepth: number;
    includeSubs: boolean;
    excludePatterns: string;
  };
  advanced: {
    timeout: number;
    userAgent: UserAgentOption;
    proxy: string;
    customHeaders: string;
  };
  active_injection_mode?: "quick" | "standard" | "deep" | "maximum" | "lab";
  intentional_vulnerable_lab?: boolean;
  lab_profile?: string;
  lab_allowed_targets?: string[];
  argus_lab_allowed_targets?: string;
  scan_approval_flags?: Record<string, boolean>;
}

const DEFAULT_OPTIONS: ScanOptions = {
  scanType: "lab",
  reportFormat: "pdf",
  rateLimit: "aggressive",
  ports: "80,443,8080,8443",
  followRedirects: true,
  vulnerabilities: {
    xss: true,
    sqli: true,
    csrf: true,
    ssrf: true,
    lfi: true,
    rce: true,
    idor: true,
    ssti: true,
    xxe: true,
    headers: true,
  },
  authentication: {
    enabled: false,
    type: "basic",
    username: "",
    password: "",
    token: "",
  },
  scope: {
    maxDepth: 10,
    includeSubs: false,
    excludePatterns: "",
  },
  advanced: {
    timeout: 120,
    userAgent: "chrome",
    proxy: "",
    customHeaders: "",
  },
  active_injection_mode: "lab",
  intentional_vulnerable_lab: true,
  lab_profile: "intentional_vulnerable_lab",
  scan_approval_flags: {
    sqlmap: true,
    commix: true,
    dalfox: true,
    xsstrike: true,
    ffuf: true,
    nuclei: true,
    testssl: true,
    sslscan: true,
  },
};

type ValidationResult = {
  valid: boolean;
  type: "url" | "ip" | "invalid" | "empty";
  message: string;
};

function isLocalIP(octets: number[]): boolean {
  if (octets[0] === 10) return true;
  if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true;
  if (octets[0] === 192 && octets[1] === 168) return true;
  if (octets[0] === 127) return true;
  if (octets.every(o => o === 0)) return true;
  if (octets[0] === 169 && octets[1] === 254) return true;
  return false;
}

function validateTarget(value: string): ValidationResult {
  if (!value.trim()) {
    return { valid: false, type: "empty", message: "" };
  }

  const urlPattern = /^https?:\/\/([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(\/.*)?$/;
  const ipPattern = /^https?:\/\/(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?(\/.*)?$/;
  const bareIpPattern = /^(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?$/;
  const bareDomainPattern = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(\/.*)?$/;

  if (urlPattern.test(value)) {
    return { valid: true, type: "url", message: "Valid URL" };
  }

  if (ipPattern.test(value)) {
    const ipMatch = value.match(/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/);
    if (ipMatch) {
      const octets = [ipMatch[1], ipMatch[2], ipMatch[3], ipMatch[4]].map(Number);
      if (octets.every(o => o >= 0 && o <= 255)) {
        if (isLocalIP(octets)) {
          return { valid: false, type: "invalid", message: "Local/private IPs not allowed" };
        }
        return { valid: true, type: "ip", message: "Valid IP" };
      }
    }
    return { valid: false, type: "invalid", message: "Invalid IP octets (0-255)" };
  }

  if (bareIpPattern.test(value)) {
    const ipMatch = value.match(/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/);
    if (ipMatch) {
      const octets = [ipMatch[1], ipMatch[2], ipMatch[3], ipMatch[4]].map(Number);
      if (octets.every(o => o >= 0 && o <= 255)) {
        if (isLocalIP(octets)) {
          return { valid: false, type: "invalid", message: "Local/private IPs not allowed" };
        }
        return { valid: true, type: "ip", message: "Valid IP" };
      }
    }
    return { valid: false, type: "invalid", message: "Invalid IP address" };
  }

  if (bareDomainPattern.test(value)) {
    return { valid: true, type: "url", message: "Valid domain" };
  }

  if (value.startsWith("http://") || value.startsWith("https://")) {
    return { valid: false, type: "invalid", message: "Invalid URL format" };
  }

  return { valid: false, type: "invalid", message: "Enter a valid URL or IP address" };
}

function normalizeTarget(value: string, selectedProtocol: string = "https"): string {
  const protocols = ["http://", "https://"];
  if (protocols.some(p => value.startsWith(p))) {
    return value;
  }
  return selectedProtocol + "://" + value;
}

function buildLabAllowedTargets(normalizedTarget: string): string[] {
  const allowed: string[] = [];
  const add = (value: string) => {
    const clean = value.trim().replace(/\/+$/, "");
    if (clean && !allowed.includes(clean)) {
      allowed.push(clean);
    }
  };

  try {
    const parsed = new URL(normalizedTarget);
    add(parsed.origin);
  } catch {
    add(normalizedTarget);
  }
  add("localhost");
  add("127.0.0.1");
  return allowed;
}

function Tooltip({ children }: { children: React.ReactNode }) {
  const [isOpen, setIsOpen] = useState(false);
  const [position, setPosition] = useState({ top: 0, left: 0 });
  const buttonRef = React.useRef<HTMLButtonElement>(null);

  const handleClick = () => {
    if (buttonRef.current) {
      const rect = buttonRef.current.getBoundingClientRect();
      setPosition({
        top: rect.bottom + 8,
        left: Math.min(rect.left, window.innerWidth - 280),
      });
    }
    setIsOpen(!isOpen);
  };

  return (
    <div className="inline-flex items-center">
      <button
        ref={buttonRef}
        type="button"
        onClick={handleClick}
        onBlur={() => setIsOpen(false)}
        className="ml-1.5 inline-flex h-3.5 w-3.5 cursor-pointer items-center justify-center rounded-full border border-neutral-600 text-[9px] leading-none text-neutral-500 hover:border-[#A655F7] hover:text-[#A655F7]"
      >
        ?
      </button>
      {isOpen && (
        <div
          className="fixed z-[100] w-72 rounded-lg border border-neutral-700 bg-neutral-900 p-4 text-xs shadow-2xl"
          style={{ top: position.top, left: position.left }}
        >
          {children}
        </div>
      )}
    </div>
  );
}

function TooltipItem({ label, desc }: { label: string; desc: string }) {
  return (
    <div className="flex gap-2">
      <span className="text-[#A655F7] font-medium shrink-0">{label}:</span>
      <span className="text-neutral-400">{desc}</span>
    </div>
  );
}

function HeaderInfoTooltip() {
  const [isOpen, setIsOpen] = useState(false);
  const [position, setPosition] = useState({ top: 0, left: 0 });
  const buttonRef = React.useRef<HTMLButtonElement>(null);

  const handleClick = () => {
    if (buttonRef.current) {
      const rect = buttonRef.current.getBoundingClientRect();
      const tooltipWidth = 288;
      const padding = 12;
      let leftPos = rect.right - tooltipWidth;
      if (leftPos < padding) {
        leftPos = padding;
      }
      if (leftPos + tooltipWidth > window.innerWidth - padding) {
        leftPos = window.innerWidth - tooltipWidth - padding;
      }
      setPosition({
        top: rect.bottom + 8,
        left: leftPos,
      });
    }
    setIsOpen(!isOpen);
  };

  return (
    <div className="inline-flex items-center">
      <button
        ref={buttonRef}
        type="button"
        onClick={handleClick}
        onBlur={() => setIsOpen(false)}
        className="ml-1 inline-flex h-4 w-4 cursor-pointer items-center justify-center rounded-full border border-neutral-600 text-[10px] leading-none text-neutral-500 hover:border-[#A655F7] hover:text-[#A655F7] transition-colors"
      >
        ?
      </button>
      {isOpen && (
        <div
          className="fixed z-[100] w-72 rounded-lg border border-neutral-700 bg-neutral-900 p-4 shadow-2xl"
          style={{ top: position.top, left: position.left }}
        >
          <div className="mb-3">
            <h4 className="text-sm font-medium text-white mb-1">Ragnarok Security Scanner</h4>
            <p className="text-xs text-neutral-400 leading-relaxed">
              Free vulnerability scanner for websites and web applications. Identify security issues before attackers do.
            </p>
          </div>
          <div className="border-t border-neutral-800 pt-3">
            <h5 className="text-xs text-neutral-500 uppercase tracking-wider mb-2">Report Tiers</h5>
            <div className="space-y-2 text-xs">
              <div className="flex justify-between items-start">
                <div>
                  <span className="text-neutral-300">Midgard</span>
                  <p className="text-[10px] text-neutral-500">Surface-level overview</p>
                </div>
                <span className="text-emerald-400 font-medium">Free</span>
              </div>
              <div className="flex justify-between items-start">
                <div>
                  <span className="text-neutral-300">Asgard</span>
                  <p className="text-[10px] text-neutral-500">Deep insights & guidance</p>
                </div>
                <span className="text-white font-medium">$154</span>
              </div>
              <div className="flex justify-between items-start">
                <div>
                  <span className="text-neutral-300">Valhalla</span>
                  <p className="text-[10px] text-neutral-500">Elite full protection</p>
                </div>
                <span className="text-white font-medium">$273</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

const SCAN_STAGES = [
  { id: 1, name: "Initializing" },
  { id: 2, name: "Port scanning" },
  { id: 3, name: "Service detection" },
  { id: 4, name: "Vulnerability assessment" },
  { id: 5, name: "Generating report" },
];

function CompleteRedirect({
  target,
  protocol,
  onViewNow,
}: {
  target: string;
  protocol: "https" | "http";
  onViewNow: () => void;
}) {
  const router = useRouter();
  const [redirectCountdown, setRedirectCountdown] = useState(15);
  const didRedirectRef = useRef(false);

  useEffect(() => {
    const interval = setInterval(() => {
      setRedirectCountdown((prev) => (prev <= 1 ? 0 : prev - 1));
    }, 1000);
    return () => clearInterval(interval);
  }, [target, protocol]);

  // Never call router.push inside setState updater — it updates Router during render phase.
  useEffect(() => {
    if (redirectCountdown !== 0 || didRedirectRef.current) return;
    didRedirectRef.current = true;
    const normalizedTarget = normalizeTarget(target, protocol);
    router.push(`/report?target=${encodeURIComponent(normalizedTarget)}`);
  }, [redirectCountdown, target, protocol, router]);

  return (
    <div className="text-center py-8">
      <div className="mb-6">
        <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-emerald-500/10 border border-emerald-500/30">
          <svg className="w-8 h-8 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
        </div>
      </div>

      <h2 className="text-xl text-white font-medium mb-2">Your Report is Ready</h2>
      <p className="text-neutral-400 text-sm mb-6">
        Scan completed for {normalizeTarget(target, protocol).replace(/^https?:\/\//, "").split("/")[0]}
      </p>

      <div className="mb-6">
        <div className="inline-flex items-center gap-2 text-neutral-500 text-sm">
          <span>Redirecting in</span>
          <span className="inline-flex items-center justify-center w-8 h-8 rounded-full bg-[#A655F7]/10 border border-[#A655F7]/30 text-[#A655F7] font-mono font-medium">
            {redirectCountdown}
          </span>
          <span>seconds</span>
        </div>
      </div>

      <button
        onClick={onViewNow}
        className="cursor-pointer bg-[#A655F7] px-6 py-2.5 text-white font-medium hover:bg-[#b875f8] rounded-sm glitch-hover"
      >
        View Report Now
      </button>
    </div>
  );
}

export default function Home() {
  const router = useRouter();
  const [target, setTarget] = useState("");
  const [protocol, setProtocol] = useState<"https" | "http">("https");
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState<"idle" | "email_input" | "scanning" | "complete" | "error">("idle");
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<"general" | "vulnerabilities" | "auth" | "advanced">("general");
  const [options, setOptions] = useState<ScanOptions>(DEFAULT_OPTIONS);

  const { state: scanState, startScan, reset: resetScan } = useScanProgress();

  const validation = useMemo(() => validateTarget(target), [target]);

  const isComplete = scanState.status === "complete";
  const isError = scanState.status === "error";

  const handleStartScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (validation.valid) {
      setStatus("email_input");
    }
  };

  const handleSubmitEmail = (e: React.FormEvent) => {
    e.preventDefault();
    if (email.trim() && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      const normalizedTarget = normalizeTarget(target, protocol);
      const labAllowedTargets = buildLabAllowedTargets(normalizedTarget);
      const submitOptions: ScanOptions = options.scanType === "lab"
        ? {
            ...options,
            lab_allowed_targets: labAllowedTargets,
            argus_lab_allowed_targets: labAllowedTargets.join(","),
          }
        : options;
      startScan({
        target: normalizedTarget,
        email: email.trim(),
        scan_mode: submitOptions.scanType === "light" ? "standard" : submitOptions.scanType,
        options: submitOptions,
      });
      setStatus("scanning");
    }
  };

  const handleReset = () => {
    setTarget("");
    setEmail("");
    setStatus("idle");
    setOptions(DEFAULT_OPTIONS);
    resetScan();
  };

  const enabledVulnCount = Object.values(options.vulnerabilities).filter(Boolean).length;

  const scanTypeInfo: Record<ScanType, { description: string; time: string }> = {
    quick: { description: "Basic OWASP Top 10 checks. Minimal footprint.", time: "~2-5 min" },
    light: { description: "Extended vulnerability scan with fuzzing.", time: "~10-20 min" },
    deep: { description: "Full security audit. All modules enabled.", time: "~1-2 hours" },
    lab: { description: "Owned-lab maximum profile with explicit active injection approvals.", time: "hours" },
  };

  return (
    <div className="flex min-h-screen flex-col bg-neutral-950 font-mono text-sm">
      <header className="border-b border-neutral-800 bg-neutral-900">
        <div className="mx-auto flex h-12 max-w-3xl items-center justify-between px-4 sm:px-6">
          <div className="flex items-center gap-2">
            <span className="glitch-text text-white font-semibold tracking-wide" data-text="RAGNAROK">RAGNAROK</span>
            <span className="text-neutral-500 text-xs hidden sm:inline">by</span>
            <a href="https://svalbard.ca" className="text-neutral-400 text-xs hover:text-[#E3CAFE] cursor-pointer hidden sm:inline">Svalbard Security</a>
          </div>
          <nav className="flex items-center gap-1 text-xs">
            <a href="https://svalbard.ca/docs" className="cursor-pointer px-2 sm:px-3 py-1.5 text-neutral-400 hover:text-[#E3CAFE] hover:bg-[#393A84]/20 rounded">
              Docs
            </a>
            <a href="https://svalbard.ca/support" className="cursor-pointer px-2 sm:px-3 py-1.5 text-neutral-400 hover:text-[#E3CAFE] hover:bg-[#393A84]/20 rounded">
              Support
            </a>
            <HeaderInfoTooltip />
          </nav>
        </div>
      </header>

      <main className="flex flex-1 items-center justify-center px-4 sm:px-6 py-8 sm:py-12">
        <div className="w-full max-w-xl">
          <div className="border border-neutral-800 bg-neutral-900 rounded">
            <div className="flex items-center justify-between border-b border-neutral-800 px-4 py-3">
              <div className="flex items-center gap-2">
                <div className="h-2 w-2 rounded-full bg-[#A655F7] pulse-glow" />
                <span className="text-white">Ragnarok Testing System</span>
              </div>
              <span className="text-xs text-neutral-600 flicker">v1.0.7</span>
            </div>

            <div className="p-5">
              {status === "idle" && (
                <form onSubmit={handleStartScan}>
                  <div className="mb-5">
                    <div className="mb-2 flex items-center justify-between">
                      <div className="flex items-center">
                        <label className="text-xs text-neutral-400 uppercase tracking-wider">Target</label>
                        <Tooltip>
                          <p className="text-neutral-300 mb-2">Enter the URL or IP address of the target system.</p>
                          <p className="text-neutral-500 text-[11px]">Example: <span className="text-neutral-300 font-mono">example.com</span> or <span className="text-neutral-300 font-mono">192.168.1.1:8080</span></p>
                        </Tooltip>
                      </div>
                      {validation.type !== "empty" && (
                        <span className={`text-xs ${validation.valid ? "text-emerald-400" : "text-amber-400"}`}>
                          {validation.message}
                        </span>
                      )}
                    </div>
                    <div className="flex">
                      <div className="relative">
                        <select
                          value={protocol}
                          onChange={(e) => setProtocol(e.target.value as "https" | "http")}
                          className="h-full cursor-pointer appearance-none bg-neutral-800 border border-r-0 border-neutral-700 pl-2 pr-6 py-2.5 text-xs text-neutral-300 focus:outline-none focus:border-[#A655F7] rounded-l-sm hover:bg-neutral-700/50 min-w-[72px] sm:min-w-[72px]"
                        >
                          <option value="https">https://</option>
                          <option value="http">http://</option>
                        </select>
                        <div className="pointer-events-none absolute inset-y-0 right-2 flex items-center">
                          <svg className="h-3 w-3 text-neutral-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                          </svg>
                        </div>
                      </div>
                      <input
                        type="text"
                        value={target}
                        onChange={(e) => setTarget(e.target.value)}
                        placeholder="example.com"
                        spellCheck={false}
                        className={`flex-1 min-w-0 cursor-text bg-neutral-950 border px-3 py-2.5 text-white placeholder:text-neutral-600 focus:outline-none rounded-r-sm ${
                          validation.type === "empty"
                            ? "border-neutral-700 focus:border-[#A655F7]"
                            : validation.valid
                            ? "border-emerald-500/50 focus:border-emerald-500"
                            : "border-amber-500/50 focus:border-amber-500"
                        }`}
                      />
                    </div>
                  </div>

                  <div className="mb-5">
                    <button
                      type="button"
                      onClick={() => setIsModalOpen(true)}
                      className="w-full cursor-pointer text-left"
                    >
                      <div className="flex items-center justify-between border border-neutral-700 bg-neutral-950 px-3 py-2.5 hover:border-[#A655F7]/50 rounded-sm">
                        <span className="text-xs text-neutral-400 uppercase tracking-wider">Options</span>
                        <div className="flex items-center gap-2 sm:gap-4 text-xs">
                          <span className="text-neutral-300">
                            <span className="text-neutral-500 hidden sm:inline">scan:</span> {options.scanType}
                          </span>
                          <span className="text-neutral-300 hidden sm:inline">
                            <span className="text-neutral-500">vulns:</span> {enabledVulnCount}
                          </span>
                          <span className="text-neutral-300 hidden sm:inline">
                            <span className="text-neutral-500">rate:</span> {options.rateLimit}
                          </span>
                          <span className="text-neutral-500">→</span>
                        </div>
                      </div>
                    </button>
                  </div>

                  <div className="flex items-center gap-3">
                    <button
                      type="submit"
                      disabled={!validation.valid}
                      className="flex-1 cursor-pointer bg-[#A655F7] px-4 py-2.5 text-white font-medium hover:bg-[#b875f8] disabled:bg-neutral-800 disabled:text-neutral-500 disabled:cursor-not-allowed rounded-sm glitch-hover"
                    >
                      Run Scan
                    </button>
                    <button
                      type="button"
                      onClick={handleReset}
                      className="cursor-pointer px-4 py-2.5 text-neutral-400 border border-neutral-700 hover:border-[#A655F7]/50 hover:text-white rounded-sm"
                    >
                      Reset
                    </button>
                  </div>
                </form>
              )}

              {status === "email_input" && (
                <form onSubmit={handleSubmitEmail}>
                  <div className="mb-5">
                    <div className="mb-4 text-center">
                      <div className="inline-flex items-center gap-2 text-emerald-400 mb-2">
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        <span className="font-medium">Target Validated</span>
                      </div>
                      <p className="text-xs text-neutral-500">
                        Scanning: {normalizeTarget(target, protocol)}
                      </p>
                    </div>

                    <div className="mb-2 flex items-center">
                      <label className="text-xs text-neutral-400 uppercase tracking-wider">Email for Report</label>
                      <Tooltip>
                          <p className="text-neutral-300">We&apos;ll send the scan report to this email address once complete.</p>
                        </Tooltip>
                    </div>
                    <input
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="your@email.com"
                      autoFocus
                      spellCheck={false}
                      className="w-full cursor-text bg-neutral-950 border border-neutral-700 px-3 py-2.5 text-white placeholder:text-neutral-600 focus:outline-none focus:border-[#A655F7] rounded-sm"
                    />
                  </div>

                  <div className="flex items-center gap-3">
                    <button
                      type="submit"
                      disabled={!email.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)}
                      className="flex-1 cursor-pointer bg-[#A655F7] px-4 py-2.5 text-white font-medium hover:bg-[#b875f8] disabled:bg-neutral-800 disabled:text-neutral-500 disabled:cursor-not-allowed rounded-sm glitch-hover"
                    >
                      Start Scan
                    </button>
                    <button
                      type="button"
                      onClick={() => setStatus("idle")}
                      className="cursor-pointer px-4 py-2.5 text-neutral-400 border border-neutral-700 hover:border-[#A655F7]/50 hover:text-white rounded-sm"
                    >
                      Back
                    </button>
                  </div>
                </form>
              )}

              {status === "scanning" && (
                <div className="space-y-4">
                  <div className="text-center mb-6">
                    <div className="inline-flex items-center gap-2 text-amber-400 mb-2">
                      <div className="h-3 w-3 rounded-full bg-amber-400 pulse-glow glow-amber" />
                      <span className="font-medium">Scan in Progress</span>
                    </div>
                    <p className="text-xs text-neutral-500 mb-3">
                      Report will be sent to: {email}
                    </p>

                    <div className="border border-blue-500/30 bg-blue-500/5 rounded p-3 text-left">
                      <div className="flex items-start gap-2">
                        <svg className="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        <div className="flex-1 text-xs space-y-1.5">
                          <p className="text-blue-300">You can safely close this window.</p>
                          <p className="text-neutral-400">
                            The report will be sent to <span className="text-white">{email}</span> when the scan completes.
                          </p>
                          <p className="text-neutral-400">
                            Report will also be available at:{" "}
                            <a
                              href={`/report?target=${encodeURIComponent(normalizeTarget(target, protocol))}`}
                              className="text-[#A655F7] hover:text-[#b875f8] underline break-all"
                            >
                              {`${window.location.origin}/report?target=${encodeURIComponent(normalizeTarget(target, protocol))}`}
                            </a>
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="mb-6">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs text-neutral-400">Progress</span>
                      <span className="text-xs text-neutral-400">{Math.round(scanState.progress)}%</span>
                    </div>
                    <div className="h-2 bg-neutral-950 rounded-full overflow-hidden border border-neutral-700">
                      <div
                        className="h-full bg-gradient-to-r from-[#A655F7] to-[#E3CAFE] transition-all duration-300"
                        style={{ width: `${scanState.progress}%` }}
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    {SCAN_STAGES.map((stage, index) => {
                      const stageProgress = (index + 1) / SCAN_STAGES.length * 100;
                      const isComplete = scanState.progress >= stageProgress;
                      const isActive = scanState.progress >= index / SCAN_STAGES.length * 100 && !isComplete;
                      const displayName = isActive && scanState.phase ? scanState.phase : stage.name;
                      return (
                        <div
                          key={stage.id}
                          className={`flex items-center gap-3 px-3 py-2 rounded ${
                            isComplete
                              ? "bg-emerald-500/10 border border-emerald-500/30"
                              : isActive
                              ? "bg-amber-500/10 border border-amber-500/30"
                              : "bg-neutral-950 border border-neutral-700"
                          }`}
                        >
                          {isComplete ? (
                            <svg className="w-4 h-4 text-emerald-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                            </svg>
                          ) : isActive ? (
                            <div className="w-4 h-4 border-2 border-amber-400 border-t-transparent rounded-full animate-spin flex-shrink-0" />
                          ) : (
                            <div className="w-4 h-4 border-2 border-neutral-600 rounded-full flex-shrink-0" />
                          )}
                          <span className={`text-xs ${
                            isComplete
                              ? "text-emerald-400"
                              : isActive
                              ? "text-amber-400"
                              : "text-neutral-500"
                          }`}>
                            {displayName}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {isComplete && (
                <CompleteRedirect
                  key={`${protocol}:${target}`}
                  target={target}
                  protocol={protocol}
                  onViewNow={() => {
                    const normalizedTarget = normalizeTarget(target, protocol);
                    router.push(`/report?target=${encodeURIComponent(normalizedTarget)}`);
                  }}
                />
              )}

              {isError && (
                <div className="text-center py-8">
                  <div className="mb-6">
                    <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-red-500/10 border border-red-500/30">
                      <svg className="w-8 h-8 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                    </div>
                  </div>
                  <h2 className="text-xl text-white font-medium mb-2">Scan Failed</h2>
                  <p className="text-neutral-400 text-sm mb-6 max-w-sm mx-auto">
                    {scanState.error ?? "An error occurred while starting or running the scan."}
                  </p>
                  <button
                    onClick={() => { setStatus("idle"); resetScan(); }}
                    className="cursor-pointer bg-[#A655F7] px-6 py-2.5 text-white font-medium hover:bg-[#b875f8] rounded-sm glitch-hover"
                  >
                    Try Again
                  </button>
                </div>
              )}
            </div>

          </div>

          {status === "idle" && (
            <div className="mt-4 grid grid-cols-2 sm:grid-cols-4 gap-2 sm:gap-3">
              <div className="border border-neutral-800 bg-neutral-900 p-3 rounded">
                <div className="text-xs text-neutral-500 uppercase tracking-wider mb-1">Type</div>
                <div className="text-white capitalize">{options.scanType}</div>
              </div>
              <div className="border border-neutral-800 bg-neutral-900 p-3 rounded">
                <div className="text-xs text-neutral-500 uppercase tracking-wider mb-1">Vulns</div>
                <div className="text-white">{enabledVulnCount} active</div>
              </div>
              <div className="border border-neutral-800 bg-neutral-900 p-3 rounded">
                <div className="text-xs text-neutral-500 uppercase tracking-wider mb-1">Auth</div>
                <div className="text-white">{options.authentication.enabled ? options.authentication.type : "Off"}</div>
              </div>
              <div className="border border-neutral-800 bg-neutral-900 p-3 rounded">
                <div className="text-xs text-neutral-500 uppercase tracking-wider mb-1">Depth</div>
                <div className="text-white">{options.scope.maxDepth}</div>
              </div>
            </div>
          )}
        </div>
      </main>

      <footer className="border-t border-neutral-800 bg-neutral-900">
        <div className="mx-auto max-w-3xl px-4 sm:px-6 py-4">
          <div className="flex flex-col sm:flex-row sm:flex-wrap items-center justify-between gap-2 sm:gap-4 text-xs">
            <div className="flex items-center gap-2 sm:gap-4">
              <span className="text-neutral-400">Svalbard Security Inc.</span>
              <span className="text-neutral-700 hidden sm:inline">|</span>
              <a href="mailto:info@svalbard.ca" className="cursor-pointer text-neutral-500 hover:text-[#E3CAFE]">
                info@svalbard.ca
              </a>
            </div>
            <div className="flex items-center gap-3 sm:gap-4 text-neutral-500">
              <a href="https://svalbard.ca/terms" target="_blank" rel="noopener noreferrer" className="cursor-pointer hover:text-[#E3CAFE]">Terms</a>
              <a href="https://svalbard.ca/privacy" target="_blank" rel="noopener noreferrer" className="cursor-pointer hover:text-[#E3CAFE]">Privacy</a>
              <span>© {new Date().getFullYear()}</span>
            </div>
          </div>
          <p className="mt-3 text-xs text-neutral-600 leading-relaxed text-center sm:text-left">
            Authorized testing only. Unauthorized access to computer systems is illegal.
          </p>
        </div>
      </footer>

      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center bg-black/80 backdrop-blur-sm p-0 sm:p-6">
          <div className="w-full sm:max-w-lg border border-neutral-800 bg-neutral-900 rounded-t-2xl sm:rounded-lg max-h-[85vh] sm:max-h-[85vh] flex flex-col shadow-2xl">
            <div className="flex items-center justify-between border-b border-neutral-800 px-5 py-4 sm:px-4 sm:py-3">
              <span className="text-white font-medium glitch-text" data-text="Scan Options">Scan Options</span>
              <button
                onClick={() => setIsModalOpen(false)}
                className="cursor-pointer text-neutral-400 hover:text-white w-8 h-8 flex items-center justify-center rounded-full hover:bg-neutral-800 transition-colors"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            <div className="flex border-b border-neutral-800 bg-neutral-950/50">
              {(["general", "vulnerabilities", "auth", "advanced"] as const).map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`flex-1 cursor-pointer px-2 py-3.5 sm:py-2.5 text-[11px] sm:text-xs uppercase tracking-wider whitespace-nowrap transition-colors ${
                    activeTab === tab
                      ? "text-[#A655F7] border-b-2 border-[#A655F7] -mb-[1px] bg-[#A655F7]/5"
                      : "text-neutral-500 hover:text-neutral-300 active:bg-neutral-800/50"
                  }`}
                >
                  {tab === "vulnerabilities" ? <span className="sm:hidden">Vulns</span> : null}
                  {tab === "vulnerabilities" ? <span className="hidden sm:inline">{tab}</span> : tab}
                </button>
              ))}
            </div>

            <div className="flex-1 overflow-y-auto p-5 sm:p-4">
              {activeTab === "general" && (
                <div className="space-y-5">
                  <div>
                    <div className="flex items-center mb-2">
                      <label className="text-xs text-neutral-400 uppercase tracking-wider">Scan Type</label>
                      <Tooltip>
                          <div className="space-y-2">
                            <TooltipItem label="Quick" desc="Fast surface-level scan" />
                            <TooltipItem label="Light" desc="Moderate depth with fuzzing" />
                            <TooltipItem label="Deep" desc="Comprehensive security audit" />
                            <TooltipItem label="Lab" desc="Maximum owned-lab active testing" />
                          </div>
                        </Tooltip>
                    </div>
                    <div className="grid grid-cols-3 gap-2">
                      {(["quick", "light", "deep", "lab"] as ScanType[]).map((type) => (
                        <button
                          key={type}
                          type="button"
                          onClick={() => setOptions({ ...options, scanType: type })}
                          className={`cursor-pointer px-3 py-2.5 text-xs border rounded-sm capitalize ${
                            options.scanType === type
                              ? "border-[#A655F7] text-[#A655F7] bg-[#A655F7]/10"
                              : "border-neutral-700 text-neutral-400 hover:border-[#A655F7]/50 hover:text-white"
                          }`}
                        >
                          {type}
                        </button>
                      ))}
                    </div>
                    <p className="mt-2 text-xs text-neutral-500">
                      {scanTypeInfo[options.scanType].description}
                      <span className="text-neutral-600 ml-2">({scanTypeInfo[options.scanType].time})</span>
                    </p>
                  </div>

                  <div>
                    <div className="flex items-center mb-2">
                      <label className="text-xs text-neutral-400 uppercase tracking-wider">Rate Limit</label>
                      <Tooltip>
                          <p className="text-neutral-300 mb-2">Controls request speed</p>
                          <div className="space-y-1.5">
                            <TooltipItem label="Slow" desc="1 req/sec, stealthy" />
                            <TooltipItem label="Normal" desc="5 req/sec" />
                            <TooltipItem label="Fast" desc="20 req/sec" />
                            <TooltipItem label="Aggressive" desc="No limit, may trigger WAF" />
                          </div>
                        </Tooltip>
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                      {(["slow", "normal", "fast", "aggressive"] as RateLimit[]).map((rate) => (
                        <button
                          key={rate}
                          type="button"
                          onClick={() => setOptions({ ...options, rateLimit: rate })}
                          className={`cursor-pointer px-3 py-2.5 text-xs border rounded-sm capitalize ${
                            options.rateLimit === rate
                              ? "border-[#A655F7] text-[#A655F7] bg-[#A655F7]/10"
                              : "border-neutral-700 text-neutral-400 hover:border-[#A655F7]/50 hover:text-white"
                          }`}
                        >
                          {rate}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div>
                    <div className="flex items-center mb-2">
                      <label className="text-xs text-neutral-400 uppercase tracking-wider">Report Format</label>
                      <Tooltip>
                          <div className="space-y-1.5">
                            <TooltipItem label="PDF" desc="Executive summary with charts" />
                            <TooltipItem label="HTML" desc="Interactive web report" />
                            <TooltipItem label="JSON" desc="Machine-readable for CI/CD" />
                            <TooltipItem label="XML" desc="Compatible with vuln scanners" />
                          </div>
                        </Tooltip>
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                      {(["pdf", "html", "json", "xml"] as ReportFormat[]).map((format) => (
                        <button
                          key={format}
                          type="button"
                          onClick={() => setOptions({ ...options, reportFormat: format })}
                          className={`cursor-pointer px-3 py-2.5 text-xs border rounded-sm uppercase ${
                            options.reportFormat === format
                              ? "border-[#A655F7] text-[#A655F7] bg-[#A655F7]/10"
                              : "border-neutral-700 text-neutral-400 hover:border-[#A655F7]/50 hover:text-white"
                          }`}
                        >
                          {format}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div>
                    <div className="flex items-center mb-2">
                      <label className="text-xs text-neutral-400 uppercase tracking-wider">Ports</label>
                      <Tooltip>
                          <p className="text-neutral-300 mb-2">Specify which ports to scan</p>
                          <div className="space-y-1.5 text-[11px]">
                            <p className="text-neutral-400">Use comma-separated: <span className="text-neutral-300 font-mono">80,443</span></p>
                            <p className="text-neutral-400">Or ranges: <span className="text-neutral-300 font-mono">8000-8100</span></p>
                          </div>
                        </Tooltip>
                    </div>
                    <input
                      type="text"
                      value={options.ports}
                      onChange={(e) => setOptions({ ...options, ports: e.target.value })}
                      placeholder="80,443,8080"
                      className="w-full cursor-text bg-neutral-950 border border-neutral-700 px-3 py-2.5 text-white text-xs placeholder:text-neutral-600 focus:border-[#A655F7] focus:outline-none rounded-sm"
                    />
                  </div>

                  <div>
                    <div className="flex items-center mb-2">
                      <label className="text-xs text-neutral-400 uppercase tracking-wider">Scope</label>
                      <Tooltip>
                          <div className="space-y-1.5">
                            <TooltipItem label="Max depth" desc="How many links deep to crawl (1-10)" />
                            <TooltipItem label="Subdomains" desc="Also scan *.target.com" />
                            <TooltipItem label="Redirects" desc="Follow HTTP redirects" />
                          </div>
                        </Tooltip>
                    </div>
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-xs text-neutral-400">Max crawl depth</span>
                        <input
                          type="number"
                          min={1}
                          max={10}
                          value={options.scope.maxDepth}
                          onChange={(e) =>
                            setOptions({
                              ...options,
                              scope: { ...options.scope, maxDepth: parseInt(e.target.value) || 3 },
                            })
                          }
                          className="w-16 cursor-text bg-neutral-950 border border-neutral-700 px-2 py-1.5 text-white text-xs text-center focus:border-[#A655F7] focus:outline-none rounded-sm"
                        />
                      </div>

                      <Checkbox
                        checked={options.scope.includeSubs}
                        onChange={(v) => setOptions({ ...options, scope: { ...options.scope, includeSubs: v } })}
                        label="Include subdomains"
                      />

                      <Checkbox
                        checked={options.followRedirects}
                        onChange={(v) => setOptions({ ...options, followRedirects: v })}
                        label="Follow redirects"
                      />
                    </div>
                  </div>

                  <div>
                    <div className="flex items-center mb-2">
                      <label className="text-xs text-neutral-400 uppercase tracking-wider">Exclude Patterns</label>
                      <Tooltip>
                          <p className="text-neutral-300 mb-2">URLs matching these patterns will be skipped</p>
                          <p className="text-neutral-400 text-[11px]">
                            Examples: <span className="text-neutral-300 font-mono">/logout</span>, <span className="text-neutral-300 font-mono">/admin/*</span>, <span className="text-neutral-300 font-mono">*.pdf</span>
                          </p>
                        </Tooltip>
                    </div>
                    <input
                      type="text"
                      value={options.scope.excludePatterns}
                      onChange={(e) =>
                        setOptions({
                          ...options,
                          scope: { ...options.scope, excludePatterns: e.target.value },
                        })
                      }
                      placeholder="/logout, /admin/*, *.pdf"
                      className="w-full cursor-text bg-neutral-950 border border-neutral-700 px-3 py-2.5 text-white text-xs placeholder:text-neutral-600 focus:border-[#A655F7] focus:outline-none rounded-sm"
                    />
                  </div>
                </div>
              )}

              {activeTab === "vulnerabilities" && (
                <div className="space-y-4">
                  <p className="text-xs text-neutral-500 mb-4">
                    Select vulnerability categories to test. More categories = longer scan time.
                  </p>

                  <div className="grid grid-cols-2 gap-3">
                    <VulnCheckbox
                      checked={options.vulnerabilities.xss}
                      onChange={(v) => setOptions({ ...options, vulnerabilities: { ...options.vulnerabilities, xss: v } })}
                      label="XSS"
                      description="Cross-Site Scripting"
                      severity="high"
                    />
                    <VulnCheckbox
                      checked={options.vulnerabilities.sqli}
                      onChange={(v) => setOptions({ ...options, vulnerabilities: { ...options.vulnerabilities, sqli: v } })}
                      label="SQLi"
                      description="SQL Injection"
                      severity="critical"
                    />
                    <VulnCheckbox
                      checked={options.vulnerabilities.csrf}
                      onChange={(v) => setOptions({ ...options, vulnerabilities: { ...options.vulnerabilities, csrf: v } })}
                      label="CSRF"
                      description="Cross-Site Request Forgery"
                      severity="medium"
                    />
                    <VulnCheckbox
                      checked={options.vulnerabilities.ssrf}
                      onChange={(v) => setOptions({ ...options, vulnerabilities: { ...options.vulnerabilities, ssrf: v } })}
                      label="SSRF"
                      description="Server-Side Request Forgery"
                      severity="high"
                    />
                    <VulnCheckbox
                      checked={options.vulnerabilities.lfi}
                      onChange={(v) => setOptions({ ...options, vulnerabilities: { ...options.vulnerabilities, lfi: v } })}
                      label="LFI/RFI"
                      description="File Inclusion"
                      severity="high"
                    />
                    <VulnCheckbox
                      checked={options.vulnerabilities.rce}
                      onChange={(v) => setOptions({ ...options, vulnerabilities: { ...options.vulnerabilities, rce: v } })}
                      label="RCE"
                      description="Remote Code Execution"
                      severity="critical"
                    />
                    <VulnCheckbox
                      checked={options.vulnerabilities.idor}
                      onChange={(v) => setOptions({ ...options, vulnerabilities: { ...options.vulnerabilities, idor: v } })}
                      label="IDOR"
                      description="Object-level access control"
                      severity="high"
                    />
                    <VulnCheckbox
                      checked={options.vulnerabilities.ssti}
                      onChange={(v) => setOptions({ ...options, vulnerabilities: { ...options.vulnerabilities, ssti: v } })}
                      label="SSTI"
                      description="Template injection"
                      severity="critical"
                    />
                    <VulnCheckbox
                      checked={options.vulnerabilities.xxe}
                      onChange={(v) => setOptions({ ...options, vulnerabilities: { ...options.vulnerabilities, xxe: v } })}
                      label="XXE"
                      description="XML external entity"
                      severity="high"
                    />
                    <VulnCheckbox
                      checked={options.vulnerabilities.headers}
                      onChange={(v) => setOptions({ ...options, vulnerabilities: { ...options.vulnerabilities, headers: v } })}
                      label="Headers"
                      description="HTTP browser policy"
                      severity="medium"
                    />
                  </div>

                  <div className="mt-4 pt-4 border-t border-neutral-800 flex gap-2">
                    <button
                      type="button"
                      onClick={() => setOptions({
                        ...options,
                        vulnerabilities: {
                          xss: true, sqli: true, csrf: true, ssrf: true, lfi: true, rce: true,
                          idor: true, ssti: true, xxe: true, headers: true,
                        }
                      })}
                      className="cursor-pointer text-xs text-[#A655F7] hover:text-[#b875f8]"
                    >
                      Select All
                    </button>
                    <span className="text-neutral-700">|</span>
                    <button
                      type="button"
                      onClick={() => setOptions({
                        ...options,
                        vulnerabilities: {
                          xss: false, sqli: false, csrf: false, ssrf: false, lfi: false, rce: false,
                          idor: false, ssti: false, xxe: false, headers: false,
                        }
                      })}
                      className="cursor-pointer text-xs text-neutral-500 hover:text-neutral-300"
                    >
                      Clear All
                    </button>
                  </div>
                </div>
              )}

              {activeTab === "auth" && (
                <div className="space-y-5">
                  <div className="flex items-center gap-2">
                    <Checkbox
                      checked={options.authentication.enabled}
                      onChange={(v) => setOptions({ ...options, authentication: { ...options.authentication, enabled: v } })}
                      label="Enable authentication"
                    />
                    <Tooltip>
                          <p className="text-neutral-300 mb-2">Authenticate requests to test protected areas</p>
                          <div className="space-y-1.5">
                            <TooltipItem label="Basic" desc="HTTP Basic Auth" />
                            <TooltipItem label="Bearer" desc="JWT/OAuth token" />
                            <TooltipItem label="Cookie" desc="Session cookie value" />
                          </div>
                        </Tooltip>
                  </div>

                  {options.authentication.enabled && (
                    <div className="space-y-4 pl-7">
                      <div>
                        <label className="block text-xs text-neutral-400 uppercase tracking-wider mb-2">
                          Type
                        </label>
                        <div className="grid grid-cols-3 gap-2">
                          {(["basic", "bearer", "cookie"] as const).map((type) => (
                            <button
                              key={type}
                              type="button"
                              onClick={() => setOptions({ ...options, authentication: { ...options.authentication, type } })}
                              className={`cursor-pointer px-3 py-2 text-xs border rounded-sm capitalize ${
                                options.authentication.type === type
                                  ? "border-[#A655F7] text-[#A655F7] bg-[#A655F7]/10"
                                  : "border-neutral-700 text-neutral-400 hover:border-[#A655F7]/50"
                              }`}
                            >
                              {type}
                            </button>
                          ))}
                        </div>
                      </div>

                      {options.authentication.type === "basic" && (
                        <>
                          <div>
                            <label className="block text-xs text-neutral-500 mb-1">Username</label>
                            <input
                              type="text"
                              value={options.authentication.username}
                              onChange={(e) =>
                                setOptions({
                                  ...options,
                                  authentication: { ...options.authentication, username: e.target.value },
                                })
                              }
                              className="w-full cursor-text bg-neutral-950 border border-neutral-700 px-3 py-2 text-white text-xs focus:border-[#A655F7] focus:outline-none rounded-sm"
                            />
                          </div>
                          <div>
                            <label className="block text-xs text-neutral-500 mb-1">Password</label>
                            <input
                              type="password"
                              value={options.authentication.password}
                              onChange={(e) =>
                                setOptions({
                                  ...options,
                                  authentication: { ...options.authentication, password: e.target.value },
                                })
                              }
                              className="w-full cursor-text bg-neutral-950 border border-neutral-700 px-3 py-2 text-white text-xs focus:border-[#A655F7] focus:outline-none rounded-sm"
                            />
                          </div>
                        </>
                      )}

                      {options.authentication.type === "bearer" && (
                        <div>
                          <label className="block text-xs text-neutral-500 mb-1">Bearer Token</label>
                          <input
                            type="text"
                            value={options.authentication.token}
                            onChange={(e) =>
                              setOptions({
                                ...options,
                                authentication: { ...options.authentication, token: e.target.value },
                              })
                            }
                            placeholder="eyJhbGciOiJIUzI1NiIs..."
                            className="w-full cursor-text bg-neutral-950 border border-neutral-700 px-3 py-2 text-white text-xs placeholder:text-neutral-600 focus:border-[#A655F7] focus:outline-none rounded-sm font-mono"
                          />
                        </div>
                      )}

                      {options.authentication.type === "cookie" && (
                        <div>
                          <label className="block text-xs text-neutral-500 mb-1">Cookie Value</label>
                          <input
                            type="text"
                            value={options.authentication.token}
                            onChange={(e) =>
                              setOptions({
                                ...options,
                                authentication: { ...options.authentication, token: e.target.value },
                              })
                            }
                            placeholder="session=abc123; token=xyz"
                            className="w-full cursor-text bg-neutral-950 border border-neutral-700 px-3 py-2 text-white text-xs placeholder:text-neutral-600 focus:border-[#A655F7] focus:outline-none rounded-sm font-mono"
                          />
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {activeTab === "advanced" && (
                <div className="space-y-5">
                  <div>
                    <div className="flex items-center mb-2">
                      <label className="text-xs text-neutral-400 uppercase tracking-wider">Request Timeout</label>
                      <Tooltip>
                          <p className="text-neutral-300">Time to wait for server response before timing out.</p>
                          <p className="text-neutral-500 text-[11px] mt-1">Increase for slow servers or high-latency connections.</p>
                        </Tooltip>
                    </div>
                    <div className="flex items-center gap-2">
                      <input
                        type="number"
                        min={5}
                        max={120}
                        value={options.advanced.timeout}
                        onChange={(e) =>
                          setOptions({
                            ...options,
                            advanced: { ...options.advanced, timeout: parseInt(e.target.value) || 30 },
                          })
                        }
                        className="w-20 cursor-text bg-neutral-950 border border-neutral-700 px-3 py-2 text-white text-xs text-center focus:border-[#A655F7] focus:outline-none rounded-sm"
                      />
                      <span className="text-xs text-neutral-500">seconds</span>
                    </div>
                  </div>

                  <div>
                    <div className="flex items-center mb-2">
                      <label className="text-xs text-neutral-400 uppercase tracking-wider">User-Agent</label>
                      <Tooltip>
                          <p className="text-neutral-300">Browser identity sent with requests.</p>
                          <p className="text-neutral-500 text-[11px] mt-1">Some WAFs block bot-like agents. Use Chrome/Firefox for stealthy scanning.</p>
                        </Tooltip>
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                      {(Object.keys(USER_AGENTS) as UserAgentOption[]).map((ua) => (
                        <button
                          key={ua}
                          type="button"
                          onClick={() => setOptions({ ...options, advanced: { ...options.advanced, userAgent: ua } })}
                          className={`cursor-pointer px-3 py-2 text-xs border rounded-sm ${
                            options.advanced.userAgent === ua
                              ? "border-[#A655F7] text-[#A655F7] bg-[#A655F7]/10"
                              : "border-neutral-700 text-neutral-400 hover:border-[#A655F7]/50 hover:text-white"
                          }`}
                        >
                          {USER_AGENTS[ua].label}
                        </button>
                      ))}
                    </div>
                    <p className="mt-2 text-[10px] text-neutral-600 font-mono truncate">
                      {USER_AGENTS[options.advanced.userAgent].value}
                    </p>
                  </div>

                  <div>
                    <div className="flex items-center mb-2">
                      <label className="text-xs text-neutral-400 uppercase tracking-wider">Proxy</label>
                      <Tooltip>
                          <p className="text-neutral-300">Route all requests through a proxy.</p>
                          <p className="text-neutral-500 text-[11px] mt-1">
                            Useful for Burp Suite (<span className="text-neutral-400 font-mono">127.0.0.1:8080</span>) or SOCKS proxies.
                          </p>
                        </Tooltip>
                    </div>
                    <input
                      type="text"
                      value={options.advanced.proxy}
                      onChange={(e) =>
                        setOptions({
                          ...options,
                          advanced: { ...options.advanced, proxy: e.target.value },
                        })
                      }
                      placeholder="http://127.0.0.1:8080"
                      className="w-full cursor-text bg-neutral-950 border border-neutral-700 px-3 py-2 text-white text-xs placeholder:text-neutral-600 focus:border-[#A655F7] focus:outline-none rounded-sm font-mono"
                    />
                  </div>

                  <div>
                    <div className="flex items-center mb-2">
                      <label className="text-xs text-neutral-400 uppercase tracking-wider">Custom Headers</label>
                      <Tooltip>
                          <p className="text-neutral-300 mb-2">Additional HTTP headers sent with every request.</p>
                          <p className="text-neutral-400 text-[11px]">
                            One per line: <span className="text-neutral-300 font-mono">Header-Name: value</span>
                          </p>
                          <p className="text-neutral-500 text-[11px] mt-1">Useful for API keys, custom auth, etc.</p>
                        </Tooltip>
                    </div>
                    <textarea
                      value={options.advanced.customHeaders}
                      onChange={(e) =>
                        setOptions({
                          ...options,
                          advanced: { ...options.advanced, customHeaders: e.target.value },
                        })
                      }
                      placeholder={"X-API-Key: your-key-here\nX-Custom-Header: value"}
                      rows={3}
                      className="w-full cursor-text bg-neutral-950 border border-neutral-700 px-3 py-2 text-white text-xs placeholder:text-neutral-600 focus:border-[#A655F7] focus:outline-none rounded-sm font-mono resize-none"
                    />
                  </div>
                </div>
              )}
            </div>

            <div className="flex items-center justify-end gap-3 border-t border-neutral-800 px-5 py-4 sm:px-4 sm:py-3 bg-neutral-950/50">
              <button
                type="button"
                onClick={() => setIsModalOpen(false)}
                className="cursor-pointer px-5 py-2.5 sm:py-2 text-sm sm:text-xs text-neutral-400 hover:text-white active:bg-neutral-800 rounded-lg sm:rounded-sm transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => setIsModalOpen(false)}
                className="cursor-pointer px-6 py-2.5 sm:py-2 text-sm sm:text-xs bg-[#A655F7] text-white hover:bg-[#b875f8] active:bg-[#9645e7] rounded-lg sm:rounded-sm font-medium transition-colors"
              >
                Save Options
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function Checkbox({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <button
      type="button"
      onClick={() => onChange(!checked)}
      className="flex cursor-pointer items-center gap-3 w-full text-left group"
    >
      <div
        className={`h-4 w-4 rounded-sm border flex items-center justify-center flex-shrink-0 ${
          checked ? "border-[#A655F7] bg-[#A655F7]" : "border-neutral-600 group-hover:border-[#A655F7]/50"
        }`}
      >
        {checked && <span className="text-white text-xs leading-none">✓</span>}
      </div>
      <span className="text-xs text-neutral-400 group-hover:text-white">{label}</span>
    </button>
  );
}

function VulnCheckbox({
  checked,
  onChange,
  label,
  description,
  severity,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
}) {
  const severityColors = {
    low: "text-neutral-400",
    medium: "text-amber-400",
    high: "text-orange-400",
    critical: "text-red-400",
  };

  return (
    <button
      type="button"
      onClick={() => onChange(!checked)}
      className={`flex cursor-pointer items-start gap-3 p-3 border rounded-sm text-left ${
        checked
          ? "border-[#A655F7]/50 bg-[#A655F7]/5"
          : "border-neutral-700 hover:border-[#A655F7]/30"
      }`}
    >
      <div
        className={`h-4 w-4 rounded-sm border flex items-center justify-center flex-shrink-0 mt-0.5 ${
          checked ? "border-[#A655F7] bg-[#A655F7]" : "border-neutral-600"
        }`}
      >
        {checked && <span className="text-white text-xs leading-none">✓</span>}
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-xs text-white font-medium">{label}</span>
          <span className={`text-[10px] uppercase ${severityColors[severity]}`}>{severity}</span>
        </div>
        <span className="text-xs text-neutral-500">{description}</span>
      </div>
    </button>
  );
}
