---
name: Admin axe-core nightly violation
about: Auto-filed when the nightly accessibility cron detects a regression on admin surfaces. Manual operators should rarely need to file this directly.
title: "[axe-core] Nightly admin a11y scan: <N> violations on <YYYY-MM-DD>"
labels:
  - a11y
  - regression
  - cycle-followup
assignees: []
---

> Auto-filed by `.github/workflows/admin-axe-cron.yml` (Cycle 7 / C7-T09).
> Do **not** edit the title prefix `[axe-core] Nightly admin a11y scan:` — it is the dedupe key for subsequent nightly runs (a multi-day regression appends comments to this issue rather than spawning a new one each night).

## Summary

- **Run (UTC):** `<YYYY-MM-DDTHH:MM:SSZ>`
- **Total violations:** `<N>`
- **Workflow run:** `<https://github.com/<owner>/<repo>/actions/runs/<run-id>>`
- **Artefact:** `admin-axe-cron-<run-id>` (HTML report, raw JSON, stdout log)

## Per-route breakdown

Replace this table with the auto-generated content from `axe-summary.md`.

| Route | Violations | Top rule |
| ----- | ---------: | -------- |
|       |            |          |

## Per-rule breakdown

| Rule | Impact | Count | Help |
| ---- | ------ | ----: | ---- |
|      |        |       |      |

## Triage

1. Open the **Workflow run** link above and download the `admin-axe-cron-<run-id>` artefact.
2. Inspect `axe-report/index.html` for the violating selectors, screenshots, and node snippets.
3. Cross-reference the offending rule(s) against the severity SLA in `docs/operations/admin-axe-cron.md`:
   - `critical` / `serious` → fix within **5 business days**
   - `moderate` → **10 business days**
   - `minor` → next sprint
4. If the violation is a **confirmed false positive**, suppress it via `disableRules` in `Frontend/tests/e2e/admin-axe.spec.ts` and link the suppression PR here. **Do not** silence rules to make this issue close — that defeats the purpose of the cron.

## Resolution checklist

- [ ] Root cause identified
- [ ] Fix landed (link the PR here)
- [ ] Verified by re-running the workflow via `workflow_dispatch`
- [ ] Issue closed (the next nightly run will re-file automatically if the regression returns)

## Operator follow-ups

- Slack/Teams webhook integration is **not** wired today. To enable, see `docs/operations/admin-axe-cron.md` § "Operator follow-ups".
