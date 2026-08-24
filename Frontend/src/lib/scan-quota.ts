import type { ScanTier } from "./scan-tiers";
import { MAX_EXTRA_SCANS, getScansPerPeriod, isPaidTier } from "./scan-tiers";

export type QuotaSource = "included" | "bonus";

export interface ScanQuota {
  included: number;
  extra: number;
  extraCap: number;
  used: number;
  remaining: number;
  capacity: number;
  periodEnd: string;
  canRetest: boolean;
  canBuyExtra: boolean;
}

export interface QuotaSlot {
  index: number;
  extra: boolean;
  used: boolean;
}

export function quotaSlots(quota: ScanQuota): QuotaSlot[] {
  return Array.from({ length: quota.capacity }, (_, index) => ({
    index,
    extra: index >= quota.included,
    used: index < quota.used,
  }));
}

interface Entitlement {
  email: string;
  target: string;
  tier: ScanTier;
  usedThisPeriod: number;
  bonusCredits: number;
  bonusUsedThisPeriod: number;
  periodStart: string;
  periodEnd: string;
  stripeSubscriptionId: string | null;
}

const globalForQuota = globalThis as unknown as {
  quotaStore?: Map<string, Entitlement>;
  processedCheckouts?: Set<string>;
};

function getStore(): Map<string, Entitlement> {
  if (!globalForQuota.quotaStore) {
    globalForQuota.quotaStore = new Map();
  }
  return globalForQuota.quotaStore;
}

function getProcessedCheckouts(): Set<string> {
  if (!globalForQuota.processedCheckouts) {
    globalForQuota.processedCheckouts = new Set();
  }
  return globalForQuota.processedCheckouts;
}

function entitlementKey(email: string, target: string): string {
  return `${email.trim().toLowerCase()}::${target.trim().toLowerCase()}`;
}

function addOneMonth(from: Date): Date {
  const next = new Date(from);
  next.setMonth(next.getMonth() + 1);
  return next;
}

function refreshPeriod(entitlement: Entitlement): Entitlement {
  const now = Date.now();
  let periodStart = new Date(entitlement.periodStart);
  let periodEnd = new Date(entitlement.periodEnd);
  let usedThisPeriod = entitlement.usedThisPeriod;
  let rolled = false;

  while (now >= periodEnd.getTime()) {
    periodStart = periodEnd;
    periodEnd = addOneMonth(periodStart);
    usedThisPeriod = 0;
    rolled = true;
  }

  if (!rolled) return entitlement;

  const updated: Entitlement = {
    ...entitlement,
    usedThisPeriod,
    bonusUsedThisPeriod: 0,
    periodStart: periodStart.toISOString(),
    periodEnd: periodEnd.toISOString(),
  };
  getStore().set(entitlementKey(entitlement.email, entitlement.target), updated);
  return updated;
}

function snapshot(entitlement: Entitlement): ScanQuota {
  const current = refreshPeriod(entitlement);
  const included = getScansPerPeriod(current.tier);
  const includedRemaining = Math.max(0, included - current.usedThisPeriod);
  const extra = current.bonusCredits + current.bonusUsedThisPeriod;
  const used = current.usedThisPeriod + current.bonusUsedThisPeriod;
  const remaining = includedRemaining + current.bonusCredits;
  return {
    included,
    extra,
    extraCap: MAX_EXTRA_SCANS,
    used,
    remaining,
    capacity: included + extra,
    periodEnd: current.periodEnd,
    canRetest: remaining > 0,
    canBuyExtra: remaining === 0 && extra < MAX_EXTRA_SCANS,
  };
}

function createEntitlement(input: {
  email: string;
  target: string;
  tier: ScanTier;
  usedThisPeriod?: number;
  stripeSubscriptionId?: string | null;
}): Entitlement {
  const now = new Date();
  const entitlement: Entitlement = {
    email: input.email.trim().toLowerCase(),
    target: input.target.trim().toLowerCase(),
    tier: input.tier,
    usedThisPeriod: input.usedThisPeriod ?? 1,
    bonusCredits: 0,
    bonusUsedThisPeriod: 0,
    periodStart: now.toISOString(),
    periodEnd: addOneMonth(now).toISOString(),
    stripeSubscriptionId: input.stripeSubscriptionId ?? null,
  };
  getStore().set(entitlementKey(entitlement.email, entitlement.target), entitlement);
  return entitlement;
}

function getEntitlement(email: string, target: string): Entitlement | null {
  const found = getStore().get(entitlementKey(email, target));
  if (!found) return null;
  return refreshPeriod(found);
}

export function getScanQuota(scan: {
  email: string;
  target: string;
  tier: ScanTier;
  paid: boolean;
}): ScanQuota | null {
  if (!isPaidTier(scan.tier) || !scan.paid) return null;
  const existing = getEntitlement(scan.email, scan.target);
  if (existing) return snapshot(existing);
  return snapshot(createEntitlement({ email: scan.email, target: scan.target, tier: scan.tier }));
}

export function activateSubscription(scan: {
  email: string;
  target: string;
  tier: ScanTier;
  stripeSubscriptionId?: string | null;
}): ScanQuota {
  const existing = getEntitlement(scan.email, scan.target);
  if (existing) {
    if (scan.stripeSubscriptionId && !existing.stripeSubscriptionId) {
      existing.stripeSubscriptionId = scan.stripeSubscriptionId;
      getStore().set(entitlementKey(existing.email, existing.target), existing);
    }
    return snapshot(existing);
  }
  return snapshot(
    createEntitlement({
      email: scan.email,
      target: scan.target,
      tier: scan.tier,
      usedThisPeriod: 1,
      stripeSubscriptionId: scan.stripeSubscriptionId,
    })
  );
}

export function consumeCredit(scan: {
  email: string;
  target: string;
  tier: ScanTier;
}): { ok: true; source: QuotaSource } | { ok: false } {
  const existing =
    getEntitlement(scan.email, scan.target) ??
    createEntitlement({
      email: scan.email,
      target: scan.target,
      tier: scan.tier,
      usedThisPeriod: 0,
    });

  const includedRemaining = Math.max(0, getScansPerPeriod(existing.tier) - existing.usedThisPeriod);
  if (includedRemaining > 0) {
    existing.usedThisPeriod += 1;
    getStore().set(entitlementKey(existing.email, existing.target), existing);
    return { ok: true, source: "included" };
  }
  if (existing.bonusCredits > 0) {
    existing.bonusCredits -= 1;
    existing.bonusUsedThisPeriod += 1;
    getStore().set(entitlementKey(existing.email, existing.target), existing);
    return { ok: true, source: "bonus" };
  }
  return { ok: false };
}

export function refundCredit(scan: {
  email: string;
  target: string;
  quotaSource: QuotaSource | null;
}): void {
  if (!scan.quotaSource) return;
  const existing = getEntitlement(scan.email, scan.target);
  if (!existing) return;
  if (scan.quotaSource === "included") {
    existing.usedThisPeriod = Math.max(0, existing.usedThisPeriod - 1);
  } else {
    existing.bonusUsedThisPeriod = Math.max(0, existing.bonusUsedThisPeriod - 1);
    existing.bonusCredits += 1;
  }
  getStore().set(entitlementKey(existing.email, existing.target), existing);
}

export function addBonusCredits(
  scan: { email: string; target: string; tier: ScanTier },
  quantity: number,
  checkoutSessionId?: string
): ScanQuota {
  if (checkoutSessionId) {
    const processed = getProcessedCheckouts();
    if (processed.has(checkoutSessionId)) {
      const existing = getEntitlement(scan.email, scan.target);
      if (existing) return snapshot(existing);
    }
    processed.add(checkoutSessionId);
  }

  const existing =
    getEntitlement(scan.email, scan.target) ??
    createEntitlement({
      email: scan.email,
      target: scan.target,
      tier: scan.tier,
      usedThisPeriod: getScansPerPeriod(scan.tier),
    });
  const extraInPlay = existing.bonusCredits + existing.bonusUsedThisPeriod;
  const room = Math.max(0, MAX_EXTRA_SCANS - extraInPlay);
  const grant = Math.min(Math.max(1, quantity), room);
  if (grant <= 0) {
    return snapshot(existing);
  }
  existing.bonusCredits += grant;
  getStore().set(entitlementKey(existing.email, existing.target), existing);
  return snapshot(existing);
}

export function attachSubscriptionId(email: string, target: string, subscriptionId: string): void {
  const existing = getEntitlement(email, target);
  if (!existing) return;
  existing.stripeSubscriptionId = subscriptionId;
  getStore().set(entitlementKey(existing.email, existing.target), existing);
}

export function resetPeriodBySubscriptionId(subscriptionId: string): void {
  for (const entitlement of getStore().values()) {
    if (entitlement.stripeSubscriptionId !== subscriptionId) continue;
    const now = new Date();
    entitlement.usedThisPeriod = 0;
    entitlement.bonusUsedThisPeriod = 0;
    entitlement.periodStart = now.toISOString();
    entitlement.periodEnd = addOneMonth(now).toISOString();
    getStore().set(entitlementKey(entitlement.email, entitlement.target), entitlement);
  }
}
