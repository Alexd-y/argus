#!/usr/bin/env node
/**
 * parse-axe-report.mjs — Cycle 7 / C7-T09
 *
 * Reads a Playwright JSON report produced by `tests/e2e/admin-axe.spec.ts`,
 * extracts the embedded axe-core violation payloads from each failing
 * test's assertion message, and writes a Markdown summary plus an exit
 * code indicating whether ANY violation was found.
 *
 * Why parse error messages instead of raw axe output?
 *   The existing spec calls `expect(violations, msg).toEqual([])`. Per the
 *   wave-09 hard rules, we MUST NOT modify that spec, so we also can't
 *   add a `testInfo.attach('axe-violations.json', …)` hook. The spec's
 *   assertion message is deterministically formatted as
 *   `[<scenario>] axe violations:\n<JSON.stringify(violations, null, 2)>`
 *   — a stable contract this parser relies on.
 *
 * Stdlib-only: `node:fs`, `node:path`. No npm deps, no network, no
 * filesystem writes outside the `--summary` argument path.
 *
 * CLI:
 *   node scripts/parse-axe-report.mjs [REPORT_JSON] [SUMMARY_MD]
 *
 * Defaults: `./axe-report/results.json` and `./axe-summary.md`.
 *
 * Exit codes:
 *   0 — no violations across all admin routes scanned.
 *   1 — at least one violation, OR a malformed/missing report (the
 *       latter is escalated because a missing report after a CI run
 *       likely means the test runner crashed before producing output).
 *
 * Error reporting:
 *   On malformed/missing input we write a SHORT human-readable line to
 *   stderr — never a stack trace (project rule: no stack-trace leaks
 *   to operators). The stderr line is the message the GitHub Action
 *   surfaces in the workflow log.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const VIOLATION_MARKER = "axe violations:";
const DEFAULT_REPORT = "./axe-report/results.json";
const DEFAULT_SUMMARY = "./axe-summary.md";

const reportPath = resolve(process.argv[2] ?? DEFAULT_REPORT);
const summaryPath = resolve(process.argv[3] ?? DEFAULT_SUMMARY);

/**
 * Walk Playwright's nested suite tree and yield each test's FINAL
 * result (latest retry attempt). We deliberately skip earlier retries
 * to avoid double-counting violations on flaky-pass tests.
 *
 * @param {object} node — A Playwright JsonSuite (has `specs` and/or
 *                        nested `suites`).
 * @yields {{spec: object, test: object, result: object}}
 */
function* walkTests(node) {
  for (const suite of node.suites ?? []) {
    yield* walkTests(suite);
  }
  for (const spec of node.specs ?? []) {
    for (const test of spec.tests ?? []) {
      const results = test.results ?? [];
      const finalResult = results.length > 0 ? results[results.length - 1] : null;
      if (!finalResult) continue;
      yield { spec, test, result: finalResult };
    }
  }
}

/**
 * Extract all error message strings from a single test result.
 * Playwright sets either `result.error.message` (single error) or
 * `result.errors[]` (multi-error mode); we coalesce both.
 */
function collectErrorMessages(result) {
  const messages = [];
  if (result.error?.message) messages.push(result.error.message);
  for (const e of result.errors ?? []) {
    if (e?.message) messages.push(e.message);
  }
  return messages;
}

/**
 * Find the JSON array that follows the `axe violations:` marker in an
 * assertion message and parse it. Returns `null` if the marker is
 * absent (test failed for a non-axe reason) or the slice is invalid.
 *
 * The slice is bounded by balanced `[` / `]` brackets — robust to
 * trailing assertion footers like `\n\nExpected: []\nReceived: [...]`.
 */
function extractViolationArray(message) {
  const markerIdx = message.indexOf(VIOLATION_MARKER);
  if (markerIdx === -1) return null;

  const tail = message.slice(markerIdx + VIOLATION_MARKER.length);
  const startBracket = tail.indexOf("[");
  if (startBracket === -1) return null;

  let depth = 0;
  let endBracket = -1;
  for (let i = startBracket; i < tail.length; i++) {
    const ch = tail[i];
    if (ch === "[") depth++;
    else if (ch === "]") {
      depth--;
      if (depth === 0) {
        endBracket = i;
        break;
      }
    }
  }
  if (endBracket === -1) return null;

  const jsonSlice = tail.slice(startBracket, endBracket + 1);
  try {
    const parsed = JSON.parse(jsonSlice);
    return Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * Normalise one axe violation entry into our flat aggregation shape.
 * Tolerates the spec's compact projection (`nodes: <number>`) AND the
 * raw axe-core shape (`nodes: Array<{...}>`), so future spec changes
 * that pass through more axe metadata don't break the parser.
 */
function normaliseViolation(rawViolation, route) {
  let nodeCount = 0;
  if (typeof rawViolation.nodes === "number") {
    nodeCount = rawViolation.nodes;
  } else if (Array.isArray(rawViolation.nodes)) {
    nodeCount = rawViolation.nodes.length;
  }

  return {
    id: typeof rawViolation.id === "string" ? rawViolation.id : "<unknown>",
    impact: typeof rawViolation.impact === "string" ? rawViolation.impact : "unknown",
    help: typeof rawViolation.help === "string" ? rawViolation.help : "",
    helpUrl: typeof rawViolation.helpUrl === "string" ? rawViolation.helpUrl : "",
    nodes: nodeCount,
    route,
  };
}

function main() {
  let raw;
  try {
    raw = readFileSync(reportPath, "utf8");
  } catch {
    process.stderr.write(
      `parse-axe-report: cannot read report file at ${reportPath}\n`,
    );
    process.exit(1);
  }

  let report;
  try {
    report = JSON.parse(raw);
  } catch {
    process.stderr.write(
      `parse-axe-report: malformed JSON in ${reportPath}\n`,
    );
    process.exit(1);
  }

  if (!report || typeof report !== "object") {
    process.stderr.write(
      `parse-axe-report: report root is not an object in ${reportPath}\n`,
    );
    process.exit(1);
  }

  const allViolations = [];
  const failedWithoutPayload = [];

  for (const suite of report.suites ?? []) {
    for (const item of walkTests(suite)) {
      const status = item.result.status;
      if (status === "passed" || status === "skipped") continue;

      const messages = collectErrorMessages(item.result);
      let extracted = 0;
      for (const message of messages) {
        const arr = extractViolationArray(message);
        if (!arr) continue;
        for (const v of arr) {
          allViolations.push(normaliseViolation(v, item.spec.title));
          extracted++;
        }
      }
      if (extracted === 0) {
        failedWithoutPayload.push(item.spec.title);
      }
    }
  }

  const totalViolations = allViolations.length + failedWithoutPayload.length;

  // Per-rule aggregation: id → { count, impact (worst), help, helpUrl }.
  // Worst-impact wins on collision because that's the operator-visible
  // SLA signal (critical > serious > moderate > minor).
  const IMPACT_RANK = { critical: 4, serious: 3, moderate: 2, minor: 1, unknown: 0 };
  const perRule = new Map();
  for (const v of allViolations) {
    const cur = perRule.get(v.id);
    if (cur) {
      cur.count += 1;
      const curRank = IMPACT_RANK[cur.impact] ?? 0;
      const newRank = IMPACT_RANK[v.impact] ?? 0;
      if (newRank > curRank) cur.impact = v.impact;
      if (!cur.help && v.help) cur.help = v.help;
      if (!cur.helpUrl && v.helpUrl) cur.helpUrl = v.helpUrl;
    } else {
      perRule.set(v.id, {
        count: 1,
        impact: v.impact,
        help: v.help,
        helpUrl: v.helpUrl,
      });
    }
  }

  // Per-route aggregation: route → { count, rules: string[] }.
  const perRoute = new Map();
  for (const v of allViolations) {
    const cur = perRoute.get(v.route);
    if (cur) {
      cur.count += 1;
      cur.rules.push(v.id);
    } else {
      perRoute.set(v.route, { count: 1, rules: [v.id] });
    }
  }
  for (const route of failedWithoutPayload) {
    const cur = perRoute.get(route);
    if (cur) {
      cur.count += 1;
      cur.rules.push("<unknown>");
    } else {
      perRoute.set(route, { count: 1, rules: ["<unknown>"] });
    }
  }

  const isoNow = new Date().toISOString();
  const lines = [];
  lines.push("# Admin axe-core nightly scan");
  lines.push("");
  lines.push(`**Run:** ${isoNow}`);
  lines.push(`**Total violations:** ${totalViolations}`);
  lines.push("");

  if (totalViolations === 0) {
    lines.push("No violations detected across the admin axe-core suite.");
  } else {
    lines.push("## Per-route breakdown");
    lines.push("");
    lines.push("| Route | Violations | Top rule |");
    lines.push("| --- | ---: | --- |");
    for (const [route, info] of perRoute) {
      const topRule = info.rules[0] ?? "—";
      lines.push(`| \`${route}\` | ${info.count} | \`${topRule}\` |`);
    }
    lines.push("");

    lines.push("## Per-rule breakdown");
    lines.push("");
    lines.push("| Rule | Impact | Count | Help |");
    lines.push("| --- | --- | ---: | --- |");
    for (const [id, info] of perRule) {
      const helpCell = info.helpUrl
        ? `[${info.help || "details"}](${info.helpUrl})`
        : info.help || "—";
      lines.push(`| \`${id}\` | ${info.impact} | ${info.count} | ${helpCell} |`);
    }

    if (failedWithoutPayload.length > 0) {
      lines.push("");
      lines.push("## Tests that failed without a parseable axe payload");
      lines.push("");
      lines.push(
        "These tests failed for non-axe reasons (timeout, navigation error, etc.) — investigate the workflow log and full HTML report.",
      );
      lines.push("");
      for (const t of failedWithoutPayload) {
        lines.push(`- \`${t}\``);
      }
    }
  }

  const markdown = lines.join("\n") + "\n";

  try {
    writeFileSync(summaryPath, markdown, "utf8");
  } catch {
    process.stderr.write(
      `parse-axe-report: cannot write summary file at ${summaryPath}\n`,
    );
    process.exit(1);
  }

  process.stdout.write(markdown);
  process.exit(totalViolations > 0 ? 1 : 0);
}

main();
