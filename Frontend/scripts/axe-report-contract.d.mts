/**
 * axe-report-contract.d.mts — Cycle 7 / C7-T09 follow-up (DEBUG-1)
 *
 * TypeScript declaration shim for the sibling `axe-report-contract.mjs`
 * runtime module. Required because:
 *   - `Frontend/tsconfig.json` `include` lists `**/*.mts` (which matches
 *     this file) but NOT `**/*.mjs`, so the runtime `.mjs` is not part
 *     of the TS program.
 *   - `Frontend/tests/e2e/admin-axe.spec.ts` (TypeScript) imports
 *     `VIOLATION_MARKER` from `"../../scripts/axe-report-contract.mjs"`.
 *   - With `moduleResolution: "bundler"`, TypeScript looks up
 *     `<sibling>.d.mts` for `.mjs` import targets. This file IS that
 *     sibling — keeping the spec strictly typed without enabling JS
 *     type-inference.
 *
 * Keep these declarations exactly in sync with the `.mjs` exports.
 * The contract test in `parse-axe-report.test.mjs` enforces value-level
 * sync between the spec source and the runtime constant; this file
 * enforces compile-time sync for TS consumers.
 */

export const VIOLATION_MARKER: "axe violations:";
export const SUMMARY_TOTAL_LINE_PREFIX: "**Total violations:**";
export const ISSUE_TITLE_PREFIX: "[axe-core] Nightly admin a11y scan:";
export const ISSUE_LABELS: readonly ["a11y", "regression", "cycle-followup"];
