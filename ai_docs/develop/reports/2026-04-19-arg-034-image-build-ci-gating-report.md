# ARG-034 — Image-build CI gating (GHCR push + OCI SBOM + Trivy blocking + branch protection)

**Worker:** Cycle 4 ARG-034 worker (Cursor / Claude Opus 4.7)
**Plan reference:** `ai_docs/develop/plans/2026-04-19-argus-finalization-cycle4.md` lines 199-244
**Workflow:** Worker → Security-auditor → Test-runner → Reviewer (этот отчёт покрывает worker pass)
**Date:** 2026-04-20
**Status:** ✅ Completed

---

## 1. Executive summary

Закрыт supply-chain DoD §19.4 + §19.9 — sandbox-images CI больше не
прокручивает «build → upload-artifact → forget», а переключён на
полноценный **build → push в GHCR → OCI SBOM attach → blocking
Trivy → compose-smoke** конвейер. Информационный Trivy-скан Cycle 3
(`continue-on-error: true`, `exit-code: '0'`, `ignore-unfixed: true`)
заменён **блокирующим** (`exit-code: '1'`, `severity: CRITICAL,HIGH`,
`ignore-unfixed: false`); любой непогашённый CRITICAL/HIGH (fixed
ИЛИ unfixed) теперь fail'ит matrix leg и блокирует merge в `main`.

Каждый из четырёх sandbox-образов (`argus-kali-{web,cloud,browser,full}`)
теперь публикуется в `ghcr.io/<org>/argus-kali-<profile>` под двумя
тегами: `:<github.sha>` (immutable, content-addressable) и `:latest`
(плавающий dev-тег). Авторизация — через `docker/login-action@v3` +
auto-provisioned `secrets.GITHUB_TOKEN` + `permissions.packages: write`,
без PAT и без сторонних секретов. Имя организации приводится к нижнему
регистру POSIX-`tr` shell-стэпом, потому что GHCR rejects uppercase
references.

CycloneDX 1.5 SBOM, который ARG-026 (Cycle 3) запекает в
`/usr/share/doc/sbom.cdx.json`, извлекается прямо из контейнера
(`docker run --rm --entrypoint cat`), валидируется инлайн-Python-checkом
(`bomFormat == "CycloneDX"`, `specVersion ∈ {1.5, 1.6}`, `components`
non-empty list), затем прикрепляется к манифесту в GHCR командой
`cosign attach sbom --type cyclonedx`. Внешние верификаторы могут
забрать SBOM без скачивания multi-GB образа: `cosign download sbom
ghcr.io/<org>/argus-kali-web:<sha> > sbom.cdx.json`. Тот же файл
дублируется в workflow-artifact (`sbom-<profile>-<sha>`, retention
30 дней) как backup, не зависящий от доступности GHCR. Версия Cosign
явно зафиксирована на `v2.4.1`, потому что `cosign attach sbom` была
удалена в v3.x — пин держится до тех пор, пока ARG-033 не переключит
механизм на `cosign attest --predicate ... --type cyclonedx` (работает
в обеих версиях).

Добавлены два новых job'а:
**`trivy-scan`** (matrix:4) — блокирующий vulnerability gate, тянет
свежий образ из GHCR и запускает `aquasecurity/trivy-action@0.28.0`
с зафиксированными параметрами + `trivyignores: '.trivyignore'`;
**`compose-smoke`** — закрывает DoD §19.4 partial: тянет все 4
sandbox-образа из GHCR, выполняет per-image smoke (`docker run --user
65532 --entrypoint id` подтверждает hardened user, `cat
/usr/share/doc/sbom.cdx.json | head -c 256` подтверждает baked-in
SBOM), затем поднимает только data-tier из `infra/docker-compose.yml`
(`postgres`, `redis`, `minio`, `minio-init`). e2e-сканирование
оставлено на Cycle 6.

Создан корневой `.trivyignore` — curated allowlist для CVE-suppressions
с подробной inline-policy: пустой по дефолту, каждая будущая запись
обязана нести четырёхполевой comment block (CVE-ID + justification +
owner + 90-day expiry), никаких wildcard'ов и blanket-фильтров.
`infra/scripts/build_images.sh` получил опциональный флаг `--push`
с защитой от случайных пушей (`--push` без `--registry` падает
с error). Документация `docs/sandbox-images.md` дополнена тремя
новыми секциями: §4a CI build + GHCR push, §4b Trivy blocking
policy, §4c Branch protection requirements (16 required status checks
+ 9-step setup runbook + break-glass procedure).

---

## 2. Files created / modified (full paths)

| Path | Status | LoC delta | Назначение |
|------|--------|-----------|------------|
| `.github/workflows/sandbox-images.yml` | modified | ≈ +220 net | GHCR push, OCI SBOM attach, blocking Trivy job, compose-smoke job, paths-filter scope |
| `.trivyignore` | new | 65 (header only, 0 entries) | Curated CVE allowlist with policy header |
| `infra/scripts/build_images.sh` | modified | +47 | `--push` flag + dry-run consistency fix |
| `docs/sandbox-images.md` | modified | +260 | §4a (CI + GHCR), §4b (Trivy policy), §4c (branch protection) + §5.3 rewrite |
| `CHANGELOG.md` | modified | +13 | `## Cycle 4 (in progress) → Changed (ARG-034 ...)` block |
| `.cursor/workspace/active/orch-2026-04-19-argus-cycle4/tasks.json` | modified | +47 | ARG-034 → completed + полный metadata block |
| `.cursor/workspace/active/orch-2026-04-19-argus-cycle4/links.json` | modified | +3 | Per-task report path append |
| `.cursor/workspace/active/orch-2026-04-19-argus-cycle4/progress.json` | modified | +2 | status → in_progress, completedTasks → [ARG-034] |

**Backend Python — не тронут** (out of scope ARG-034).
**Cycle 3 plan / report / archive — не тронут** (constraint).
**`infra/scripts/sign_images.sh` — не тронут** (домен ARG-033).

---

## 3. Workflow diff summary (Cycle 3 → ARG-034)

| Аспект | Cycle 3 (до) | ARG-034 (после) | Эффект |
|--------|--------------|-----------------|--------|
| Build target | local-only (`docker build`, no push) | **build + push в GHCR** (`:<sha>` + `:latest`) | Reproducible content-addressed deploys; downstream verify-images становится возможным |
| SBOM distribution | workflow-artifact 30d | **OCI artefact в GHCR** + workflow-artifact backup | `cosign download sbom` без pull'а multi-GB образа; внешний audit |
| Cosign version | `v3.x` (default `cosign-installer`) | **pinned `v2.4.1`** | `attach sbom` удалена в v3.x — пин держится до ARG-033 swap |
| Trivy mode | informational (`continue-on-error: true`, `exit-code: '0'`, `ignore-unfixed: true`) | **blocking** (`exit-code: '1'`, `severity: CRITICAL,HIGH`, `ignore-unfixed: false`, `trivyignores: '.trivyignore'`) | Любой непогашённый CRITICAL/HIGH блокирует merge в `main` |
| Trivy job | inline в `build-images` | **отдельный `trivy-scan`** matrix:4, depends_on `build-images` | Отдельная required-status-check колонка для branch protection |
| Compose smoke | отсутствует | **новый `compose-smoke` job** (pull 4 GHCR images + boot data tier) | Закрывает DoD §19.4 partial; e2e — Cycle 6 |
| `paths-filter` | 4 paths | **6 paths** (+`.trivyignore`, +`infra/docker-compose.yml`) | Изменения в curated allowlist и compose-стеке триггерят полный pipeline |
| `permissions` | `contents: read`, `packages: write`, `id-token: write` | без изменений (уже корректные для GHCR + keyless OIDC) | Готово для ARG-033 keyless attest |
| Job count | 4 (`hardening-contract`, `build-images`, `sign-images`, `sign-dry-run`) | **6** (+`trivy-scan`, +`compose-smoke`) | Больше явных gate'ов для branch protection |
| `build-images` job name | `Build (web|cloud|browser|full)` | **`Build & push (web|cloud|browser|full)`** | Сигнализирует семантику в branch protection UI |
| `sign-images` Cosign | `default` (v3.x) | **`v2.4.1`** | Конвергенция версий до ARG-033 keyless rewrite |

---

## 4. Acceptance criteria checklist (vs. plan §3 ARG-034)

| # | Criterion | Status | Evidence |
|---|-----------|--------|----------|
| 1 | `build-images` пушит в `ghcr.io/<org>/argus-kali-<profile>:<sha>` + `:latest` | ✅ | `.github/workflows/sandbox-images.yml` lines 132-164 (login + refs + build_images.sh `--push --registry`); пушит оба тега через `infra/scripts/build_images.sh` с `--push` |
| 2 | SBOM прикреплён к manifest как OCI artefact (`cosign attach sbom`) | ✅ | `.github/workflows/sandbox-images.yml` lines 194-207; cosign pinned to `v2.4.1` (lines 198-200); SBOM extracted via `docker run --rm --entrypoint cat` (lines 166-176) |
| 3 | SBOM envelope валидируется (CycloneDX 1.5, components > 0) | ✅ | `.github/workflows/sandbox-images.yml` lines 178-192 (inline Python heredoc) |
| 4 | Trivy переключён в blocking mode | ✅ | `.github/workflows/sandbox-images.yml` lines 246-258: `severity: 'CRITICAL,HIGH'`, `ignore-unfixed: false`, `exit-code: '1'`, `trivyignores: '.trivyignore'`; нет `continue-on-error` |
| 5 | Trivy в отдельном job'е (`trivy-scan`), matrix:4, depends_on `build-images` | ✅ | `.github/workflows/sandbox-images.yml` lines 216-258 (`needs: [build-images]`, `matrix.profile: [web, cloud, browser, full]`, `fail-fast: false`) |
| 6 | `.trivyignore` создан, пустой по дефолту, с inline policy | ✅ | `.trivyignore` 65 lines header (policy §1–4 + format template + local replay), zero entries below `# ── Active suppressions` (line 62) |
| 7 | `paths-filter` расширен под `.trivyignore` + `infra/docker-compose.yml` | ✅ | `.github/workflows/sandbox-images.yml` lines 44-51 (push) + 54-61 (pull_request) — оба триггера дополнены |
| 8 | `compose-smoke` job: pull 4 images + `docker compose up -d` без e2e | ✅ | `.github/workflows/sandbox-images.yml` lines 260-338 (pull all 4, smoke per image, seed `.env`, `docker compose up -d postgres redis minio minio-init`, `sleep 15`, cleanup) |
| 9 | `infra/scripts/build_images.sh --push` flag (legacy invocations не сломаны) | ✅ | `infra/scripts/build_images.sh`: `--push` parsed (locally-flagged), требует `--registry` (защита от accidental docker.io push), pushes `:<tag>` + `:latest`, dry-run печатает push-команды; default — local-only |
| 10 | `docs/sandbox-images.md` имеет три новые секции (§4a + §4b + §4c) | ✅ | `docs/sandbox-images.md` §4a (CI image build + push to GHCR), §4b (Trivy blocking scan policy), §4c (Branch protection requirements); §5.3 переписана под `--push` |
| 11 | Branch protection required checks задокументированы | ✅ | `docs/sandbox-images.md` §4c.1 list: 11 sandbox-images checks + 5 ci.yml checks = **16 required status checks**; §4c.2 settings table; §4c.3 9-step operator runbook; §4c.4 break-glass procedure |
| 12 | Все GitHub Actions запинены (никаких `@main` / floating tags) | ✅ | `actions/checkout@v4`, `docker/setup-buildx-action@v3`, `docker/login-action@v3`, `actions/setup-python@v5`, `sigstore/cosign-installer@v3.7.0` (with `cosign-release: v2.4.1`), `aquasecurity/trivy-action@0.28.0`, `actions/upload-artifact@v4` |
| 13 | CHANGELOG.md имеет `## Cycle 4 (in progress)` + ARG-034 entry на русском | ✅ | `CHANGELOG.md` lines 7-30 (новый блок выше существующих Cycle 3 записей) |
| 14 | Workspace state обновлён (tasks.json + links.json + progress.json) | ✅ | tasks.json: ARG-034 → completed + filesModified/Created + metrics + verification + outOfScopeFollowUps; links.json: perTaskReports += [arg-034 report path]; progress.json: status → in_progress, completedTasks: [ARG-034] |
| 15 | Worker report на русском (mirror Cycle 3 ARG-026 structure) | ✅ | этот файл (`ai_docs/develop/reports/2026-04-19-arg-034-image-build-ci-gating-report.md`) |

---

## 5. Branch protection setup checklist

Для оператора — копировать в чек-лист релиза или в Settings → Branches.

### 5.1 Required Status Checks (16 штук)

**Из `.github/workflows/sandbox-images.yml` (11):**

- [ ] `hardening-contract`
- [ ] `build-images / Build & push (web)`
- [ ] `build-images / Build & push (cloud)`
- [ ] `build-images / Build & push (browser)`
- [ ] `build-images / Build & push (full)`
- [ ] `trivy-scan / Trivy scan (web)`
- [ ] `trivy-scan / Trivy scan (cloud)`
- [ ] `trivy-scan / Trivy scan (browser)`
- [ ] `trivy-scan / Trivy scan (full)`
- [ ] `compose-smoke`
- [ ] `verify-images` *(добавить после ARG-033 — не сейчас, иначе блокирует merge)*

**Из `.github/workflows/ci.yml` (5):**

- [ ] `lint`
- [ ] `test-no-docker`
- [ ] `test-docker-required`
- [ ] `security`
- [ ] `npm-audit (Frontend)` / `npm-audit (admin-frontend)`

### 5.2 Recommended branch-protection settings

| Setting | Value | Rationale |
|---------|-------|-----------|
| Require pull request reviews before merging | ✅ at least 1 | two-eyes principle |
| Dismiss stale pull request approvals on new commits | ✅ | force re-review |
| Require review from Code Owners | ✅ if `CODEOWNERS` exists | domain ownership |
| Require status checks to pass before merging | ✅ | gate on §5.1 list |
| Require branches to be up to date before merging | ⚠️ optional | `false` рекомендуется (не форсить rebuild на каждый rebase) |
| Require signed commits | ✅ recommended | пара к Cosign keyless signing — closes commit→build→deploy authenticity loop |
| Require linear history | ⚠️ optional | squash/rebase merge style only |
| Include administrators | ✅ | админы не должны bypass'ить blocking gates |
| Allow force pushes | ❌ never | даст переписать signed history |
| Allow deletions | ❌ never | `main` нельзя удалять |

### 5.3 Operator runbook

Полная 9-step instruction в `docs/sandbox-images.md` §4c.3. TL;DR:
1. Open `https://github.com/<org>/argus/settings/branches`
2. Add rule for pattern `main`
3. Tick «Require status checks» + add all 16 checks из §5.1
4. Tick «Include administrators»
5. Save

### 5.4 Break-glass

GHCR/Sigstore outage procedure — см. `docs/sandbox-images.md` §4c.4
(временное снятие чек-бокса с required check + 4-hour SLA на восстановление
+ post-mortem в `ai_docs/develop/issues/ISS-cycle<N>-bp-bypass-<date>.md`).

---

## 6. Verification (local)

Workflow реально проверяется только на следующем PR-push в GitHub
Actions — local Windows worker не имеет Docker, актуального `trivy`,
`actionlint` или `shellcheck`. Документирую gap явно.

| Check | Tool | Result |
|-------|------|--------|
| YAML syntax | `python -c "import yaml; yaml.safe_load(open('.github/workflows/sandbox-images.yml'))"` | ✅ PASS (file parses, no exception) |
| Workflow lint | `actionlint` | ⚠️ skipped (not installed on Windows) |
| Shell lint | `shellcheck infra/scripts/build_images.sh` | ⚠️ skipped (not installed on Windows) |
| Trivy local replay | `trivy image --severity CRITICAL,HIGH --ignore-unfixed=false --exit-code 1 ...` | ⚠️ skipped (no Docker daemon, образы недоступны без CI push) |
| Markdown lint | n/a | ⚠️ no project config — visual review only |

**Recommended follow-up smoke**: открыть no-op PR против `main` после
этой коммита, дождаться первого боевого прогона `sandbox-images.yml`,
скриншотить результаты `build-images / trivy-scan / compose-smoke` в
PR-description как evidence. Если первый Trivy прогон выявит CVE'шки,
**не добавлять их в `.trivyignore` без полного четырёхполевого
комментария** (см. `.trivyignore` policy §2 inline).

---

## 7. Out-of-scope follow-ups

Эти пункты **намеренно** не в ARG-034 — закроются в других задачах
Cycle 4 / Cycle 5.

| Item | Owner | Why deferred |
|------|-------|--------------|
| Keyless Cosign signing (Sigstore Fulcio + Rekor) + новый `verify-images` job | **ARG-033** | Отдельная задача в плане Cycle 4; ARG-034 оставил `sign-images` как Cycle 3 skeleton (только cosign version pin до v2.4.1 для convergence) |
| Trivy SARIF output → GitHub Security tab | **ARG-040 capstone** | Сейчас `format: table` (читаемый в GHA log); SARIF включится единым PR в capstone, чтобы не плодить мелких изменений в workflow |
| `verify-images` чек-бокс в Required Status Checks | оператор + ARG-033 | Чек-бокс **не активировать** до тех пор, пока ARG-033 не зальёт `verify-images` job — иначе все PR'ы заблокируются |
| Real CVE list в `.trivyignore` | first real CI run + cycle owner | Allowlist пуст по дефолту; реальный список рождается на первом прогоне. Каждая будущая запись — manual review per `.trivyignore` policy §2 |
| `version:` field в tool YAML каталоге | **ARG-040 capstone** (см. ISS-cycle3-tool-yaml-version-field.md) | Не блокирует ARG-034; ARG-040 backfill'ит + добавит C14 contract |
| End-to-end scan smoke в `compose-smoke` | **Cycle 6** | DoD §19.4 partial закрыт (boot smoke). Полный e2e — отдельный Cycle |
| Multi-arch builds (linux/arm64) | **Cycle 5+** | Сейчас только linux/amd64 (default). Multi-arch добавится единым PR с `docker/build-push-action` + `platforms: linux/amd64,linux/arm64`, но не сейчас — ARG-034 фокусируется на gating, не на расширении target matrix |
| Build cache (registry-backed BuildKit cache) | **Cycle 5+** | Текущий build занимает ≈ 8 мин на runner; с registry cache можно сократить до ≈ 2 мин на repeated PR. Не критично для DoD §19.4 |

---

## 8. Sign-off

**Worker:** ARG-034 worker (Cursor / Claude Opus 4.7), 2026-04-20
**Hand-off to:** Security-auditor (ревью workflow permissions + cosign
attest semantics + `.trivyignore` policy), затем Test-runner (smoke на
следующем PR-push), затем Reviewer (financial sign-off на DoD §19.4
+ §19.9).

**One-sentence summary:** Image build CI now pushes to GHCR with
blocking Trivy + OCI SBOM attach + compose-smoke gate, and 16 required
status checks are documented for branch protection.

---

## Appendix A: workflow job graph (текстовая)

```
on: push/main, PR/main+develop, workflow_dispatch
                            │
                            ▼
                   ┌────────────────────────┐
                   │  hardening-contract    │  Dockerfile static analysis (65 cases)
                   └───────────┬────────────┘
                               │
                               ▼
              ┌─────────────────────────────────────┐
              │  build-images (matrix: 4 profiles)  │  build + push GHCR + cosign attach SBOM
              └──────────┬──────────────┬───────────┘
                         │              │
                         ▼              ▼
        ┌─────────────────────────┐ ┌────────────────────────────┐
        │  trivy-scan (matrix:4)  │ │  compose-smoke             │
        │   BLOCKING gate         │ │  pull 4 + boot data tier   │
        └─────────────────────────┘ └────────────────────────────┘
                         │
                         ▼
              ┌─────────────────────────────────────┐
              │  sign-images (push:main only)       │  Cycle 3 skeleton, ARG-033 rewrites
              │  sign-dry-run (PR validation)       │
              └─────────────────────────────────────┘
```

## Appendix B: cosign v2 vs v3 — версионная сноска

`cosign attach sbom` была удалена в **cosign v3.0.0** (релиз 2025-09).
Альтернатива в v3 — `cosign attest --predicate <sbom> --type cyclonedx`,
которая создаёт **in-toto attestation envelope** вместо OCI sibling
artefact. Семантика немного другая:

* `attach sbom` — SBOM как separate OCI artefact, доступен через
  `cosign download sbom`. Не подписан (просто attached).
* `attest --predicate ... --type cyclonedx` — SBOM как **signed
  predicate** в in-toto Statement, доступен через `cosign verify-attestation`.
  Подпись проверяется (по ключу или keyless через Fulcio + Rekor).

ARG-033 переключит механизм на `attest` (signed) — это пара к keyless
signing. До тех пор пин на v2.4.1 — самый чистый путь, без необходимости
параллельно поддерживать оба механизма.

## Appendix C: docker-compose smoke seed values

`compose-smoke` сидит `infra/.env` с минимальными значениями только для
boot'а data-tier'а. Они **не используются** в реальных тестах — это
placeholder'ы, чтобы compose не упал на required env vars. После
`docker compose down -v` файл стирается (вместе с runner workspace).

```ini
POSTGRES_USER=argus
POSTGRES_PASSWORD=argus-ci-smoke
POSTGRES_DB=argus
REDIS_PASSWORD=
MINIO_ACCESS_KEY=argus
MINIO_SECRET_KEY=argus-ci-smoke-secret-32chars-min!!
MINIO_BUCKET=argus
MINIO_REPORTS_BUCKET=argus-reports
JWT_SECRET=ci-smoke-jwt-secret-do-not-use-in-prod
DEFAULT_TENANT_ID=00000000-0000-0000-0000-000000000001
LOG_LEVEL=INFO
SANDBOX_ENABLED=true
```

Эти значения не leak'нут наружу: GHA secrets management не задействован,
данные живут только в pod'е runner'а на время прогона `compose-smoke`,
volumes drop'аются в `if: always()` shutdown step. Production credentials
приходят из `secrets.*` через otherwise-routed pipeline (которого пока
нет — Cycle 6 закроет).
