import { createHash, randomUUID } from "crypto";
import {
  normalizeHostname,
  VERIFICATION_TXT_PREFIX,
  verificationRecordHost,
} from "./domain-verification";

export function expectedVerificationToken(target: string, email: string): string {
  const hostname = normalizeHostname(target);
  const normalizedEmail = email.trim().toLowerCase();
  const digest = createHash("sha256")
    .update(`ragnarok-verify:${hostname}:${normalizedEmail}`)
    .digest("hex")
    .slice(0, 32);
  return `${VERIFICATION_TXT_PREFIX}${digest}`;
}

export interface DomainVerificationRecord {
  id: string;
  target: string;
  email: string;
  token: string;
  recordHost: string;
  verified: boolean;
  createdAt: string;
  verifiedAt: string | null;
}

const VERIFICATION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

const globalForVerification = globalThis as unknown as {
  verificationStore?: Map<string, DomainVerificationRecord>;
};

function getStore(): Map<string, DomainVerificationRecord> {
  if (!globalForVerification.verificationStore) {
    globalForVerification.verificationStore = new Map();
  }
  return globalForVerification.verificationStore;
}

function isExpired(record: DomainVerificationRecord): boolean {
  return Date.now() - new Date(record.createdAt).getTime() > VERIFICATION_TTL_MS;
}

export function findVerification(target: string, email: string): DomainVerificationRecord | null {
  const hostname = normalizeHostname(target);
  const normalizedEmail = email.trim().toLowerCase();
  for (const record of getStore().values()) {
    if (record.target === hostname && record.email === normalizedEmail && !isExpired(record)) {
      return record;
    }
  }
  return null;
}

export function createVerification(
  target: string,
  email: string,
  existing?: { id: string; token: string }
): DomainVerificationRecord {
  const hostname = normalizeHostname(target);
  const normalizedEmail = email.trim().toLowerCase();
  const token = expectedVerificationToken(hostname, normalizedEmail);

  const current = findVerification(hostname, normalizedEmail);
  if (current) {
    if (current.token === token) return current;
    const updated = {
      ...current,
      token,
      verified: false,
      verifiedAt: null,
    };
    getStore().set(current.id, updated);
    return updated;
  }

  if (existing?.id) {
    const restored: DomainVerificationRecord = {
      id: existing.id,
      target: hostname,
      email: normalizedEmail,
      token,
      recordHost: verificationRecordHost(hostname),
      verified: false,
      createdAt: new Date().toISOString(),
      verifiedAt: null,
    };
    getStore().set(restored.id, restored);
    return restored;
  }

  const record: DomainVerificationRecord = {
    id: randomUUID(),
    target: hostname,
    email: normalizedEmail,
    token,
    recordHost: verificationRecordHost(hostname),
    verified: false,
    createdAt: new Date().toISOString(),
    verifiedAt: null,
  };
  getStore().set(record.id, record);
  return record;
}

export function getVerification(id: string): DomainVerificationRecord | null {
  const record = getStore().get(id);
  if (!record || isExpired(record)) return null;
  return record;
}

export function markVerificationVerified(id: string): DomainVerificationRecord | null {
  const record = getStore().get(id);
  if (!record || isExpired(record)) return null;
  const updated = { ...record, verified: true, verifiedAt: new Date().toISOString() };
  getStore().set(id, updated);
  return updated;
}

export function isVerificationValid(
  id: string,
  target: string,
  email: string
): boolean {
  const record = getVerification(id);
  if (!record || !record.verified) return false;
  if (record.token !== expectedVerificationToken(target, email)) return false;
  return (
    record.target === normalizeHostname(target) &&
    record.email === email.trim().toLowerCase()
  );
}
