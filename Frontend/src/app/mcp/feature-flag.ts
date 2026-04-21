/**
 * Tri-state parser for `NEXT_PUBLIC_MCP_ENABLED`.
 *
 * Accepts: `"true"`, `"1"`, `"yes"` → enabled.
 * Anything else (including unset) → disabled. We intentionally default
 * to disabled so the flag is opt-in and existing tenants see no change.
 *
 * Lives outside the layout so it can be unit-tested in isolation and
 * reused by the page server component.
 */
export function isMcpEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = env.NEXT_PUBLIC_MCP_ENABLED;
  if (typeof raw !== "string") {
    return false;
  }
  const normalised = raw.trim().toLowerCase();
  return normalised === "true" || normalised === "1" || normalised === "yes";
}
