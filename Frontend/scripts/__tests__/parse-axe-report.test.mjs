/**
 * parse-axe-report.test.mjs — Cycle 7 / C7-T09
 *
 * Stdlib-only (`node:test`) unit tests for `../parse-axe-report.mjs`.
 * Run with: `node --test Frontend/scripts/__tests__/parse-axe-report.test.mjs`
 *
 * Each case spawns the parser as a subprocess so we exercise the real
 * argv → exit-code contract that the GitHub Action depends on. We
 * write synthetic Playwright JSON reports to a per-test temp dir,
 * invoke the parser, and assert exit code + summary content.
 *
 * No npm deps. Cleans up its own temp files in `t.after()`.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  writeFileSync,
  readFileSync,
  mkdtempSync,
  existsSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  VIOLATION_MARKER,
  SUMMARY_TOTAL_LINE_PREFIX,
} from "../axe-report-contract.mjs";

const PARSER_PATH = fileURLToPath(
  new URL("../parse-axe-report.mjs", import.meta.url),
);

const SPEC_PATH = fileURLToPath(
  new URL("../../tests/e2e/admin-axe.spec.ts", import.meta.url),
);

/**
 * Escape regex metacharacters in a literal string so it can be safely
 * embedded inside a `new RegExp(...)`. Used to derive assertion patterns
 * from the shared contract constants (which contain `*` etc.).
 */
function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const SUMMARY_TOTAL_PREFIX_RE = escapeRegex(SUMMARY_TOTAL_LINE_PREFIX);

/**
 * Build a Playwright-shaped JSON report from a compact spec list.
 * Each entry is { title, violations? }: a non-null/empty `violations`
 * marks the spec as failed and embeds the projected payload (matching
 * the existing admin-axe.spec.ts format) inside the assertion message.
 */
function buildReport(specs) {
  const renderedSpecs = specs.map((s) => {
    const failed = Array.isArray(s.violations) && s.violations.length > 0;
    const message = failed
      ? `[${s.title}] ${VIOLATION_MARKER}\n${JSON.stringify(s.violations, null, 2)}\n\nExpected: []\nReceived: ${JSON.stringify(s.violations)}`
      : null;
    return {
      title: s.title,
      ok: !failed,
      tests: [
        {
          status: failed ? "unexpected" : "expected",
          results: [
            {
              status: failed ? "failed" : "passed",
              ...(failed ? { error: { message } } : {}),
            },
          ],
        },
      ],
    };
  });

  return {
    config: {},
    suites: [
      {
        title: "admin-axe.spec.ts",
        file: "tests/e2e/admin-axe.spec.ts",
        specs: renderedSpecs,
      },
    ],
    errors: [],
  };
}

/**
 * Run the parser as a subprocess against either a synthetic report
 * object or a raw string (for malformed-input testing). Returns
 * { code, stdout, stderr, summary } and registers a per-test cleanup.
 */
function runParser(t, payload, { malformed = false } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "axe-parser-test-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  const reportPath = join(dir, "results.json");
  const summaryPath = join(dir, "summary.md");

  if (malformed) {
    writeFileSync(reportPath, payload ?? "{ this is not json", "utf8");
  } else {
    writeFileSync(reportPath, JSON.stringify(payload), "utf8");
  }

  const r = spawnSync(
    process.execPath,
    [PARSER_PATH, reportPath, summaryPath],
    { encoding: "utf8" },
  );

  return {
    code: r.status,
    stdout: r.stdout ?? "",
    stderr: r.stderr ?? "",
    summary: existsSync(summaryPath)
      ? readFileSync(summaryPath, "utf8")
      : null,
  };
}

test("empty results — exit 0 and 'Total violations: 0'", (t) => {
  const report = buildReport([
    { title: "findings triage (super-admin)" },
    { title: "audit log viewer (super-admin)" },
  ]);

  const r = runParser(t, report);

  assert.equal(r.code, 0, `expected exit 0; stderr=${r.stderr}`);
  assert.ok(r.summary, "expected summary file to be written");
  assert.match(r.summary, new RegExp(`${SUMMARY_TOTAL_PREFIX_RE} 0`));
  assert.match(r.summary, /No violations detected/);
});

test("one violation — exit 1; summary lists the rule", (t) => {
  const report = buildReport([
    {
      title: "findings triage (super-admin)",
      violations: [
        {
          id: "color-contrast",
          impact: "serious",
          help: "Elements must have sufficient color contrast",
          helpUrl: "https://dequeuniversity.com/rules/axe/4.7/color-contrast",
          nodes: 2,
        },
      ],
    },
    { title: "audit log viewer (super-admin)" },
  ]);

  const r = runParser(t, report);

  assert.equal(r.code, 1, `expected exit 1; stderr=${r.stderr}`);
  assert.ok(r.summary, "expected summary file to be written");
  assert.match(r.summary, new RegExp(`${SUMMARY_TOTAL_PREFIX_RE} 1`));
  assert.match(r.summary, /color-contrast/);
  assert.match(r.summary, /serious/);
  assert.match(r.summary, /findings triage \(super-admin\)/);
});

test("multi-route violations — aggregates per-rule and per-route", (t) => {
  const report = buildReport([
    {
      title: "findings triage (super-admin)",
      violations: [
        {
          id: "color-contrast",
          impact: "serious",
          help: "Color contrast",
          helpUrl: "https://example/color-contrast",
          nodes: 1,
        },
        {
          id: "aria-required-attr",
          impact: "critical",
          help: "ARIA",
          helpUrl: "https://example/aria-required-attr",
          nodes: 3,
        },
      ],
    },
    {
      title: "audit log viewer (super-admin)",
      violations: [
        {
          id: "color-contrast",
          impact: "serious",
          help: "Color contrast",
          helpUrl: "https://example/color-contrast",
          nodes: 1,
        },
      ],
    },
    { title: "scans (admin, with export toggle)" },
  ]);

  const r = runParser(t, report);

  assert.equal(r.code, 1, `expected exit 1; stderr=${r.stderr}`);
  assert.ok(r.summary);
  assert.match(r.summary, new RegExp(`${SUMMARY_TOTAL_PREFIX_RE} 3`));

  // Per-route table includes both failing routes.
  assert.match(r.summary, /findings triage \(super-admin\)/);
  assert.match(r.summary, /audit log viewer \(super-admin\)/);
  // The passing scan route is NOT listed.
  assert.doesNotMatch(r.summary, /scans \(admin, with export toggle\)/);

  // Per-rule: color-contrast aggregated to count 2 across two routes.
  const colorContrastRow = r.summary.match(
    /\|\s*`color-contrast`\s*\|\s*\w+\s*\|\s*(\d+)\s*\|/,
  );
  assert.ok(
    colorContrastRow,
    `per-rule row for color-contrast not found in summary:\n${r.summary}`,
  );
  assert.equal(colorContrastRow[1], "2", "expected color-contrast count == 2");

  // The critical aria rule appears with its impact.
  assert.match(r.summary, /aria-required-attr/);
  assert.match(r.summary, /critical/);
});

test("malformed JSON — exit 1; friendly stderr; no stack trace leak", (t) => {
  const r = runParser(t, "{ this is not valid json", { malformed: true });

  assert.equal(r.code, 1, `expected exit 1; stderr=${r.stderr}`);
  assert.match(
    r.stderr,
    /malformed JSON/i,
    `expected friendly malformed-JSON message; got: ${r.stderr}`,
  );
  // Must NOT leak V8 stack frames or the underlying SyntaxError class.
  assert.doesNotMatch(
    r.stderr,
    /SyntaxError/,
    "stderr should not include the underlying error class name",
  );
  assert.doesNotMatch(
    r.stderr,
    /\n\s+at\s+\w+/,
    "stderr should not include stack frames",
  );
});

test("contract — parser uses the same VIOLATION_MARKER as the spec", () => {
  // Static drift guard: the producer (admin-axe.spec.ts) and the consumer
  // (parse-axe-report.mjs) MUST reference the same magic substring. We
  // assert the spec source imports the constant from the shared module
  // and embeds it as `${VIOLATION_MARKER}` inside its assertion message —
  // not as a hardcoded literal. If anyone reverts the spec to a string
  // literal, this test fires immediately and the cron stays drift-blind
  // for ZERO days instead of "until the next axe regression".
  const specSource = readFileSync(SPEC_PATH, "utf8");

  assert.match(
    specSource,
    /from\s+["']\.\.\/\.\.\/scripts\/axe-report-contract\.mjs["']/,
    "spec must import from the shared contract module",
  );
  assert.match(
    specSource,
    /\bVIOLATION_MARKER\b/,
    "spec must reference the VIOLATION_MARKER identifier",
  );
  assert.match(
    specSource,
    /\$\{VIOLATION_MARKER\}/,
    "spec must interpolate VIOLATION_MARKER into the assertion message (not hardcode the literal)",
  );
  assert.doesNotMatch(
    specSource,
    new RegExp(`["'\`][^"'\`]*${escapeRegex(VIOLATION_MARKER)}[^"'\`]*["'\`]`),
    "spec must NOT contain the VIOLATION_MARKER as a hardcoded literal — use the imported constant",
  );

  // Sanity: the marker we imported is the same string the parser sees.
  assert.equal(
    VIOLATION_MARKER,
    "axe violations:",
    "VIOLATION_MARKER drifted from its documented value — also update the workflow + runbook",
  );
});
