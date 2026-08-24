import type { ScanTier } from "./scan-tiers";

const SESSION_KEY = "ragnarok-scan-session:v1";

export interface VerificationChallenge {
  verificationId: string;
  recordHost: string;
  recordValue: string;
  target: string;
}

export interface ScanSession {
  target: string;
  protocol: "https" | "http";
  email: string;
  tier: ScanTier;
  darkWebMonitoring: boolean;
  verification: VerificationChallenge | null;
  challenge: VerificationChallenge | null;
  verifiedId: string | null;
}

const VALID_TIERS: ScanTier[] = ["free", "standard", "premium"];

function isChallenge(value: unknown): value is VerificationChallenge {
  if (!value || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  return (
    typeof record.verificationId === "string" &&
    typeof record.recordHost === "string" &&
    typeof record.recordValue === "string" &&
    typeof record.target === "string"
  );
}

function parseSession(raw: string): ScanSession | null {
  const data = JSON.parse(raw) as Partial<ScanSession>;
  if (typeof data.target !== "string" || typeof data.email !== "string") {
    return null;
  }
  if (data.protocol !== "https" && data.protocol !== "http") return null;
  if (!data.tier || !VALID_TIERS.includes(data.tier)) return null;

  return {
    target: data.target,
    protocol: data.protocol,
    email: data.email,
    tier: data.tier,
    darkWebMonitoring: Boolean(data.darkWebMonitoring),
    verification: isChallenge(data.verification) ? data.verification : null,
    challenge: isChallenge(data.challenge) ? data.challenge : null,
    verifiedId: typeof data.verifiedId === "string" ? data.verifiedId : null,
  };
}

export function isEmptySession(session: ScanSession): boolean {
  return (
    !session.target &&
    !session.email &&
    !session.verification &&
    !session.challenge &&
    !session.verifiedId &&
    session.tier === "free" &&
    !session.darkWebMonitoring &&
    session.protocol === "https"
  );
}

function readRaw(): string | null {
  try {
    const fromLocal = localStorage.getItem(SESSION_KEY);
    if (fromLocal) return fromLocal;
    const fromSession = sessionStorage.getItem(SESSION_KEY);
    if (fromSession) {
      localStorage.setItem(SESSION_KEY, fromSession);
      sessionStorage.removeItem(SESSION_KEY);
      return fromSession;
    }
    return null;
  } catch {
    return null;
  }
}

export function loadScanSession(): ScanSession | null {
  try {
    const raw = readRaw();
    if (!raw) return null;
    return parseSession(raw);
  } catch {
    return null;
  }
}

export function saveScanSession(session: ScanSession): void {
  try {
    if (isEmptySession(session)) {
      localStorage.removeItem(SESSION_KEY);
      sessionStorage.removeItem(SESSION_KEY);
      return;
    }
    localStorage.setItem(SESSION_KEY, JSON.stringify(session));
  } catch {
    // localStorage can throw in private browsing or when quota is exceeded
  }
}

export function clearScanSession(): void {
  try {
    localStorage.removeItem(SESSION_KEY);
    sessionStorage.removeItem(SESSION_KEY);
  } catch {
    // ignore
  }
}
