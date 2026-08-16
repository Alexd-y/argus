import { randomUUID } from "crypto";
import { normalizeHostname } from "./domain-verification";

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

const globalForVerification = globalThis as unknown as {
  verificationStore?: Map<string, DomainVerificationRecord>;
};

function getStore(): Map<string, DomainVerificationRecord> {
  if (!globalForVerification.verificationStore) {
    globalForVerification.verificationStore = new Map();
  }
  return globalForVerification.verificationStore;
}

export function createVerification(target: string, email: string): DomainVerificationRecord {
  const hostname = normalizeHostname(target);
  const token = `ragnarok-verify=${randomUUID()}`;
  const record: DomainVerificationRecord = {
    id: randomUUID(),
    target: hostname,
    email: email.trim().toLowerCase(),
    token,
    recordHost: `_ragnarok-verify.${hostname}`,
    verified: false,
    createdAt: new Date().toISOString(),
    verifiedAt: null,
  };
  getStore().set(record.id, record);
  return record;
}

export function getVerification(id: string): DomainVerificationRecord | null {
  return getStore().get(id) ?? null;
}

export function markVerificationVerified(id: string): DomainVerificationRecord | null {
  const record = getStore().get(id);
  if (!record) return null;
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
  return (
    record.target === normalizeHostname(target) &&
    record.email === email.trim().toLowerCase()
  );
}
