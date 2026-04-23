/**
 * axe-report-contract.mjs — Cycle 7 / C7-T09 follow-up (DEBUG-1)
 *
 * Shared, single-source-of-truth contract between three call sites that
 * MUST agree byte-for-byte on a handful of magic strings — historically
 * each one hardcoded its own copy and a silent drift in any one of them
 * would make the nightly cron either miss real violations or fail to
 * dedupe its regression issues:
 *
 *   1. Frontend/tests/e2e/admin-axe.spec.ts          — PRODUCER
 *      Emits `[<scenario>] axe violations:\n<JSON>` inside the
 *      `expectNoAxeViolations` helper's assertion message.
 *
 *   2. Frontend/scripts/parse-axe-report.mjs         — CONSUMER
 *      Greps each failing test's assertion message for the marker and
 *      extracts the embedded JSON violation payload.
 *
 *   3. .github/workflows/admin-axe-cron.yml          — WORKFLOW CONSUMER
 *      `awk` extracts the violation count from the parser's summary
 *      using `^**Total violations:**` as the line anchor, then dedupes
 *      open issues by the `[axe-core] Nightly admin a11y scan:` title
 *      prefix. Labels are applied in a fixed set.
 *
 * If you change ANY constant here, update ALL of:
 *   - this file
 *   - Frontend/scripts/parse-axe-report.mjs
 *   - Frontend/tests/e2e/admin-axe.spec.ts
 *   - Frontend/scripts/axe-report-contract.d.mts (declaration shim)
 *   - Frontend/scripts/__tests__/parse-axe-report.test.mjs
 *   - .github/workflows/admin-axe-cron.yml
 *
 * Keeping the constants string-literal (no template parts) is intentional:
 * the workflow's `awk` and `gh issue list --jq` expressions need a plain
 * literal anchor, and the contract test in `parse-axe-report.test.mjs`
 * asserts the spec source contains the marker as an interpolation token.
 *
 * Stdlib-only — no imports, no side effects. Importable from both `.mjs`
 * (parser, tests) and `.ts` (Playwright spec, via the sibling
 * `axe-report-contract.d.mts` declaration file).
 */

/**
 * Substring the parser searches for inside Playwright assertion-failure
 * messages to locate the embedded JSON violation array. The producing
 * spec emits the marker as `${VIOLATION_MARKER}\n${JSON.stringify(...)}`.
 */
export const VIOLATION_MARKER = "axe violations:";

/**
 * Markdown line prefix the parser writes to `axe-summary.md`. The
 * workflow's awk extractor (see `.github/workflows/admin-axe-cron.yml`,
 * step "File / update axe regression issue") anchors on this exact
 * prefix, so the asterisks are part of the literal — do not strip them.
 */
export const SUMMARY_TOTAL_LINE_PREFIX = "**Total violations:**";

/**
 * Title prefix the workflow uses to dedupe rolling regression issues.
 * `gh issue list ... --jq 'select(.title | startswith(<this>))'` matches
 * on this exact prefix.
 */
export const ISSUE_TITLE_PREFIX = "[axe-core] Nightly admin a11y scan:";

/**
 * Labels applied to the rolling regression issue. Created idempotently
 * by the workflow's `Ensure issue labels exist` step.
 */
export const ISSUE_LABELS = ["a11y", "regression", "cycle-followup"];
