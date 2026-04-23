# Admin axe-core nightly cron — Operator Runbook

> Owner: Frontend on-call. Last reviewed: 2026-04-23.
> Cycle 7 / C7-T09. Plan: [`ai_docs/develop/plans/2026-04-22-argus-cycle7.md`](../../ai_docs/develop/plans/2026-04-22-argus-cycle7.md).

Self-sufficient runbook for the nightly admin accessibility regression scan. Audience: a Frontend on-call who may have never touched the axe-core suite. Every cited file path, npm script, and CLI flag has been verified against `main` at the date above.

---

## 1. Purpose

The push/PR axe-core gate (`Frontend/tests/e2e/admin-axe.spec.ts`) only fires on direct `Frontend/` changes. A PR that, say, reverts the `--warning-strong` design token (C7-T08) without touching the Frontend tree will silently drop us below WCAG-AA without ever hitting the gate. This cron closes that loophole.

| Property | Value |
| --- | --- |
| Workflow | [`.github/workflows/admin-axe-cron.yml`](../../.github/workflows/admin-axe-cron.yml) |
| Schedule | `cron: "17 3 * * *"` — daily at **03:17 UTC** (off-peak, avoids the 00 / 06 / 12 / 18 UTC hot windows) |
| Manual trigger | `workflow_dispatch` (Actions UI → "Admin axe-core nightly" → "Run workflow") |
| Concurrency | `group: admin-axe-cron, cancel-in-progress: false` (a manual run never cancels an in-flight nightly) |
| Permissions | `contents: read`, `issues: write` |
| Token | Default `GITHUB_TOKEN` — no PAT, no third-party secret |
| Scope | Admin surfaces only — drives the spec at `Frontend/tests/e2e/admin-axe.spec.ts`, which audits `/admin/findings`, `/admin/audit-logs`, `/admin/scans`, `/admin/operations`, `/admin/schedules` and their interactive states. |
| Failure routing | Auto-files / appends to a single rolling GitHub issue with labels `a11y`, `regression`, `cycle-followup`. Branch protection on `main` is **not** affected — the issue **is** the failure signal. |
| Artefacts | `axe-report/` (HTML + JSON), `axe-summary.md`, `axe-stdout.log` — retained 30 days. |

---

## 2. Reproduce locally

The CI job is byte-equivalent to the local developer loop because it reuses the same `playwright.a11y.config.ts` (which spawns its own dev server pointed at the in-memory admin-backend mock — no real backend needed).

### One-shot reproduction

```powershell
cd Frontend
npm ci
npm run test:e2e:install                  # one-time Playwright browser install
$env:PLAYWRIGHT_JSON_OUTPUT_NAME = "axe-report/results.json"
$env:PLAYWRIGHT_HTML_REPORT       = "axe-report/html"
npm run test:e2e:a11y -- --reporter=html,json,line 2>&1 | Tee-Object -FilePath axe-stdout.log
node scripts/parse-axe-report.mjs axe-report/results.json axe-summary.md
```

POSIX shell (Linux / WSL / macOS):

```bash
cd Frontend
npm ci
npm run test:e2e:install
PLAYWRIGHT_JSON_OUTPUT_NAME=axe-report/results.json \
PLAYWRIGHT_HTML_REPORT=axe-report/html \
npm run test:e2e:a11y -- --reporter=html,json,line 2>&1 | tee axe-stdout.log
node scripts/parse-axe-report.mjs axe-report/results.json axe-summary.md
```

### Inspecting the parser without Playwright

```bash
# Quick contract check — confirms exit codes wire up correctly.
node Frontend/scripts/parse-axe-report.mjs path/to/results.json /tmp/summary.md
echo "exit: $?"   # 0 = clean, 1 = at least one violation
node --test Frontend/scripts/__tests__/parse-axe-report.test.mjs
```

The parser is stdlib-only (`node:fs`, `node:path`) — works on any Node ≥ 18 with no `npm install`.

---

## 3. Triaging the auto-filed issue

When violations are detected the workflow opens (or comments on) a GitHub issue titled:

```
[axe-core] Nightly admin a11y scan: <N> violations on <YYYY-MM-DD>
```

The body contains the first 200 lines of `axe-summary.md` plus a footer with the workflow run URL. The issue template skeleton lives at [`.github/ISSUE_TEMPLATE/admin-axe-violation.md`](../../.github/ISSUE_TEMPLATE/admin-axe-violation.md).

### 3.1 Severity ladder & SLAs

axe-core's own taxonomy drives priority. The SLA clock starts when the issue is auto-filed (issue `created_at` for first occurrence; latest comment timestamp for ongoing regressions).

| axe impact | SLA (business days) | Notes |
| ---------- | ------------------: | ----- |
| `critical` | **5** | Blocks assistive-tech users entirely (e.g. missing `<label>` on a form input). Drop other work. |
| `serious`  | **5** | High-impact (e.g. WCAG-AA contrast failure like ISS-T26-001). |
| `moderate` | **10** | Degrades but doesn't block. |
| `minor`    | next sprint | Polish — fold into the next admin-surface ticket. |

### 3.2 Triage workflow

1. Open the **Workflow run** link in the issue footer.
2. Download the `admin-axe-cron-<run-id>` artefact (top-right of the run page).
3. Open `axe-report/html/index.html` in a browser — Playwright's HTML report has the violating selectors, screenshots, and node snippets.
4. Cross-reference each rule id against the [Deque rule catalogue](https://dequeuniversity.com/rules/axe/) (linked from the per-rule table in the issue body).
5. Land a fix PR. Reference the issue (`Fixes #<N>`).
6. Manually re-run the workflow via `workflow_dispatch` to confirm the fix.
7. Close the issue. The next nightly will re-file automatically if the regression returns.

### 3.3 Why are there comments on an old open issue instead of new issues?

By design. The workflow dedupes on title prefix `[axe-core] Nightly admin a11y scan:` so a multi-day regression accumulates comments on a single issue rather than spamming N issues per day. Close the issue once the fix lands; the next nightly will open a fresh one if needed.

---

## 4. False-positive suppression

axe-core occasionally fires on third-party widgets you can't fix (e.g. an embedded iframe), or on a rule that's intentionally relaxed for a specific surface (e.g. an explicitly-decorative element). To silence one rule on the entire admin suite, edit the `expectNoAxeViolations` helper in [`Frontend/tests/e2e/admin-axe.spec.ts`](../../Frontend/tests/e2e/admin-axe.spec.ts) and add `.disableRules([...])` to the `AxeBuilder` chain:

```ts
const builder = new AxeBuilder({ page })
  .withTags([...AXE_TAGS])
  .include("main")
  .disableRules(["color-contrast"]);   // <-- example: silence ONE rule
```

To silence a rule on a single page only, copy the `expectNoAxeViolations` helper into the relevant test and add the `.disableRules()` call there instead of in the shared helper.

> **WARNING.** Suppressing a rule globally to make a real violation close defeats the purpose of the cron and re-introduces the exact regression class C7-T08 was designed to prevent. Suppressions MUST land in their own PR with:
>
> - A short comment in the spec naming the suppressed rule, the surface, and the design rationale (e.g. `// disableRules: 'color-contrast' on /admin/foo — third-party iframe, not under our control`).
> - A linked design-tokens or RFC entry justifying the exception.
> - Code-owner sign-off from the Frontend lead.
>
> If you cannot meet those three conditions, fix the violation instead.

---

## 5. Operator follow-ups (not wired today)

### 5.1 Slack / Teams webhook

Today the workflow only files a GitHub issue. There is **no** Slack/Teams notification because no `SLACK_AXE_WEBHOOK` (or equivalent) repo secret is currently provisioned, and the C7-T09 hard rules forbid referencing unverified secrets.

To wire up Slack (10-minute change, requires SRE secret-rotation access):

1. Create an incoming webhook in the relevant Slack workspace (`#frontend-on-call` or similar).
2. Add the URL as a **repo secret** named `SLACK_AXE_WEBHOOK` (Settings → Secrets and variables → Actions).
3. Append a step to `.github/workflows/admin-axe-cron.yml`, gated identically to the issue step:

```yaml
- name: Notify Slack on regression
  if: failure() && steps.parse_axe.outcome == 'failure'
  env:
    SLACK_WEBHOOK: ${{ secrets.SLACK_AXE_WEBHOOK }}
  run: |
    set -euo pipefail
    if [[ -z "${SLACK_WEBHOOK:-}" ]]; then
      echo "SLACK_AXE_WEBHOOK not set; skipping Slack notification."
      exit 0
    fi
    DATE_UTC="$(date -u +%Y-%m-%d)"
    PAYLOAD=$(printf '{"text":"axe-core nightly: violations on %s — %s/%s/actions/runs/%s"}' \
      "${DATE_UTC}" "${GITHUB_SERVER_URL}" "${GITHUB_REPOSITORY}" "${GITHUB_RUN_ID}")
    curl --fail --silent --show-error \
      -X POST \
      -H 'Content-Type: application/json' \
      --data "${PAYLOAD}" \
      "${SLACK_WEBHOOK}"
```

The `if [[ -z … ]]` guard means the step is a safe no-op if the secret is ever unset (e.g. fork CI). Same pattern works for Teams via `MS_TEAMS_AXE_WEBHOOK`.

### 5.2 Auto-assign on file

The issue template's `assignees: []` is intentional — assigning a fixed individual creates a single-point-of-failure if they're on PTO. Use a CODEOWNERS-driven mention or a Slack tag in the body instead. If your team needs hard auto-assignment, append `--assignee @<github-handle>` to the `gh issue create` invocation in the workflow.

---

## 6. Runbook for cron-itself failures (not violations)

The cron may fail for reasons unrelated to a11y:

| Symptom | Likely cause | Action |
| --- | --- | --- |
| `npm ci` fails | `Frontend/package-lock.json` out of sync with `Frontend/package.json` | Land a sync PR; re-run via `workflow_dispatch`. |
| `npx playwright install` fails | Playwright registry / mirror down | Wait 30 min, re-run. If persistent, add `PLAYWRIGHT_BROWSERS_PATH` cache step. |
| Playwright tests time out (no JSON report produced) | Dev server failed to come up — usually a flaky port-bind on the runner | Re-run via `workflow_dispatch`. If reproducible, raise the `webServer.timeout` in `Frontend/playwright.a11y.config.ts`. |
| Parser fails with `cannot read report file` | Playwright crashed before producing JSON | Inspect `axe-stdout.log` artefact for the underlying error. |
| Parser fails with `malformed JSON` | Disk full on runner mid-write, or Playwright reporter bug | Re-run; if reproducible escalate to GitHub Actions support. |
| `gh issue create` fails with `label not found` | The idempotent label-creation step before it failed silently | Check the workflow log for the prior `gh label create` step; manually create the missing label and re-run. |
| Workflow has not run in > 48 h | GitHub Actions silently disabled the schedule (happens after 60 days of repo inactivity) | Bump any file in the repo to bring activity, or trigger via `workflow_dispatch` once. |

### Escalation path

1. Frontend on-call ➜ check workflow logs + the most recent open `[axe-core]` issue.
2. If the cron itself is broken (not just violations), open a separate `infra` / `ci` labelled issue **without** the `a11y` label so the dedupe lookup doesn't accidentally swallow it.
3. If GitHub Actions itself is degraded ([status.github.com](https://www.githubstatus.com/)), wait it out — the next scheduled run will pick up automatically.

### Disabling the cron temporarily

If the cron must be silenced (e.g. ongoing infra incident causing daily false-positive issues), comment out the `schedule:` block in `.github/workflows/admin-axe-cron.yml` and land via PR with the rationale in the commit message. The workflow remains available via `workflow_dispatch` for manual runs. **Do not delete the workflow** — only disable the trigger.

---

## 7. Related runbooks & references

- [`Frontend/tests/e2e/admin-axe.spec.ts`](../../Frontend/tests/e2e/admin-axe.spec.ts) — the spec the cron drives. Owns the WCAG tag set and the per-route audit list.
- [`Frontend/playwright.a11y.config.ts`](../../Frontend/playwright.a11y.config.ts) — Playwright project config (own dev server, mock backend, 180 s health-check timeout).
- [`ai_docs/architecture/design-tokens.md`](../../ai_docs/architecture/design-tokens.md) §3.5 — the `--warning-strong` token landing that motivated this cron.
- [`docs/operations/admin-sessions.md`](admin-sessions.md) — sibling admin runbook for the auth subsystem the spec exercises.
- [Deque axe-core rule catalogue](https://dequeuniversity.com/rules/axe/) — authoritative source for rule semantics + remediation guidance.
