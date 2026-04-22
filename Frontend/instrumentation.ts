/**
 * Next.js instrumentation hook (B6-T09 / ISS-T20-003 follow-up).
 *
 * `register()` is called exactly once per server start by Next.js (Node
 * + Edge runtimes), before the first request lands. It is the canonical
 * place for boot-time invariants whose violation should abort the process.
 *
 * What we enforce here
 * --------------------
 * In production (`NODE_ENV=production`), `NEXT_PUBLIC_ADMIN_AUTH_MODE`
 * MUST be set to `session`. The other two modes (`cookie`, `auto`) fall
 * back to the legacy client-writable cookies for role/tenant — that is
 * fine in dev where the operator is already trusted, but in production
 * any visitor could mint themselves an admin role cookie and bypass the
 * backend's bcrypt session.
 *
 * Threat model
 * ------------
 * `NEXT_PUBLIC_*` envs are browser-visible and chosen at build time, so a
 * misconfigured deploy survives until a request actually exercises the
 * admin surface. By throwing in `register()` we surface the mistake at
 * boot — Next.js logs the stack and refuses to serve traffic.
 *
 * Belt-and-suspenders
 * -------------------
 * `serverSession.ts` ALSO performs a lazy assertion on first use, in case
 * `instrumentation.ts` is disabled (older Next or operator override).
 * Both paths use the same canonical error message so the remediation is
 * identical regardless of which one fires first.
 */

const REQUIRED_PROD_MODE = "session" as const;

export async function register(): Promise<void> {
  if (process.env.NODE_ENV !== "production") return;

  const raw = process.env.NEXT_PUBLIC_ADMIN_AUTH_MODE ?? "";
  const normalised = raw.trim().toLowerCase();
  if (normalised === REQUIRED_PROD_MODE) return;

  const reported = raw.trim().length > 0 ? raw : "<unset>";
  throw new Error(
    `ADMIN_AUTH_MODE must be 'session' in production (got: ${reported}). ` +
      `Cookie shim is dev-only — see B6-T09 / ISS-T20-003.`,
  );
}
