# ARGUS Finalization Cycle 4 — Plan

**Date:** 2026-04-19  
**Orchestration:** `orch-2026-04-19-argus-cycle4`  
**Status:** 🟢 Active (planning → ready to execute)  
**Predecessor (plan):** [`ai_docs/develop/plans/2026-04-19-argus-finalization-cycle3.md`](2026-04-19-argus-finalization-cycle3.md)  
**Predecessor (report):** [`ai_docs/develop/reports/2026-04-19-argus-finalization-cycle3.md`](../reports/2026-04-19-argus-finalization-cycle3.md)  
**Carry-over backlog:** [`ai_docs/develop/issues/ISS-cycle4-carry-over.md`](../issues/ISS-cycle4-carry-over.md)  
**Backlog (источник истины):** [`Backlog/dev1_.md`](../../../Backlog/dev1_.md) §4, §9, §11, §13, §15, §16.10/§16.13/§16.16, §17, §19  

---

## 1. Cycle 3 carry-over (✅ closed — DO NOT replan)

Final state, locked from `ai_docs/develop/reports/2026-04-19-argus-finalization-cycle3.md`:

- **Tool catalog:** 157 signed YAMLs (Backlog §4 fully covered, DoD §19.6 ✅), 23 payloads, 5 prompts — все Ed25519-verifiable.
- **Per-tool parsers:** **68 mapped (43.3 %)** / **89 heartbeat (56.7 %)** / 0 BINARY_BLOB. Цель Cycle 3 «mapped ≥ 68, heartbeat ≤ 89» — попадание ровно в цель.
- **Coverage matrix:** **12 контрактов × 157 tools = 1 884 параметризованных кейсов** (C1–C12, включая новые C11 parser-determinism + C12 evidence-redaction-completeness). 1 887 / 1 887 PASS (1 884 матрица + 3 summary/ratchet).
- **Backend MCP server:** **15 tools / 4 resources / 3 prompts**, FastMCP, JSON-RPC 2.0 stdio + streamable-http, signed manifest `backend/config/mcp/server.yaml`, hashed-args audit log. 429 тестов (396 unit + 33 integration). mypy --strict clean (39 source files).
- **ReportService:** **12 / 18** ячеек матрицы — Midgard (Tier 1) + Asgard (Tier 2) × {HTML, PDF, JSON, CSV, SARIF v2.1.0, JUnit XML}. SHA-256 + `X-Argus-Report-SHA256` header, `replay_command_sanitizer` (21 secret-regex + 13 reverse-shell + 13 destructive-flag, 335 / 335 NIST §5.1.4 кейсов зелёные).
- **Sandbox supply-chain:** 4 / 4 production-ready Dockerfile (`argus-kali-{web,cloud,browser,full}`), USER 65532, no SUID, HEALTHCHECK, SBOM CycloneDX 1.5, Cosign skeleton (dry-run по умолчанию). 65 hardening assertions без Docker daemon. CI workflow `.github/workflows/sandbox-images.yml` (build + SBOM + Cosign dry-run + Trivy informational).
- **Sandbox runtime:** 11 NetworkPolicy templates (+`cloud-aws/gcp/azure`), `NetworkPolicyRef.dns_resolvers` (replace) + `egress_allowlist` (union) — живые поля. 0 wildcard egress peers без `ipBlock.except`. ARG-019 H2-долг закрыт.
- **Test infrastructure:** SQLite-aware engine pool (`StaticPool` для in-memory, `pool_size/overflow` для PostgreSQL); 5 pytest markers (`requires_postgres/redis/oast/docker/weasyprint_pdf`); `pytest -q` dev-default — **9 278 / 9 278 PASS** оффлайн. CI разделён на `test-no-docker` + `test-docker-required` jobs (Postgres 15 + pgvector + Redis 7 service-containers).
- **Cycle 4 carry-over:** 10 пунктов (ARG-031..ARG-040) задокументированы в `ai_docs/develop/issues/ISS-cycle4-carry-over.md`.

Цикл 3 закрыт без regress'ов: catalog signing инвариант (157/23/5 Ed25519 verified) и dispatch-инвариант ARG-020 (89 unmapped tool_id всё ещё дают ровно один `ARGUS-HEARTBEAT` finding) сохранены байт-в-байт.

---

## 2. Cycle 4 goals

Cycle 4 закрывает три критических разрыва Cycle 3 («Headline Metrics Table» строки с дельтой 0 или с known-limitation footnote'ом) и поднимает три новые поверхности до production-ready состояния. Ни одной новой архитектурной поверхности — только **completion + hardening** того, что Cycle 3 ввёл как scaffold.

**Цель 1 — Закрыть ReportService matrix `12 / 18 → 18 / 18`.** Backlog §15 требует все 3 tier'а × 6 форматов (DoD §19.4 явно перечисляет «12 отчётов» как acceptance gate; в полном объёме это 18 ячеек). ARG-031 добавляет **Valhalla tier renderer** (executive summary + business-impact lens, mirrored ARG-024+ARG-025 структуры) — последние 6 ячеек матрицы. Risk score per asset, OWASP rollup, top-N findings by `(severity × exploitability × business_value)`. После закрытия — `ReportService` становится атомарной операцией для **любой** комбинации tier × format с детерминированным `ReportBundle.sha256`.

**Цель 2 — Production-grade PDF rendering.** Cycle 3 закрыл WeasyPrint stub в structural-snapshot режиме (`pypdf` page-count assertion), но Asgard / Midgard / Valhalla — все trei tier'а — заслуживают branded HTML/CSS template'ы (logo, цветовая схема per-tier, header/footer с tenant_id + scan_id + SHA-256, page numbering, TOC). ARG-036 закрывает: branded template'ы, fixed-font embedding для PDF-determinism (no `/CreationDate` randomness), optional **LaTeX fallback** (`REPORT_PDF_BACKEND=weasyprint|latex|disabled`) для CI-окружений без Cairo/Pango/GDK-PixBuf native libs. PDF становится first-class deliverable, а не graceful-skip артефакт.

**Цель 3 — Сократить heartbeat fallback с 89 → ~59.** Backlog §4 содержит 157 tool_id; mapped 68 (43.3 %) — высокая цифра, но catalog coverage по категориям сильно неоднородна (`browser` 0/6 = 0 %, `binary` 1/5 = 20 %, `recon` 7/35 = 20 %, `auth` 3/11 = 27 %). ARG-032 поднимает mapped → ~98, heartbeat → ~59 (новые +30 парсера) с приоритетом по low-coverage categories. Каждый парсер — pure-функция в стиле ARG-021/022/029, ноль новых helper'ов, per-module coverage ≥ 90 %. **Цель Cycle 4 — DoD §19.6 catalog coverage ratio выше 60 %.**

**Цель 4 — Production supply-chain (Cosign keyless + image CI gating).** ARG-034 переключает `.github/workflows/sandbox-images.yml::build-images` job с «build + extract SBOM локально» на «build + push в `ghcr.io/<org>/argus-kali-<profile>` + push SBOM как OCI artefact через `cosign attach sbom`», добавляет `paths-filter` для CI-минут, fail-on-CRITICAL Trivy gate, branch-protection на merge в `main`. ARG-033 поверх ARG-034 включает Sigstore Fulcio keyless подпись (`cosign sign --tlog-upload=true` через GH OIDC) + `cosign attest --predicate <SBOM> --type cyclonedx` + verify-job в CI. После Cycle 4 каждый push в `main` подписан keyless и проверяем через `cosign verify --certificate-identity-regexp ... --certificate-oidc-issuer https://token.actions.githubusercontent.com`. Это закрывает DoD §19 supply-chain секцию полностью.

**Цель 5 — MCP production readiness (webhooks + rate-limiter + OpenAPI export).** ARG-035 добавляет webhook-эмиттеры (`SlackNotifier`, `LinearAdapter`, `JiraAdapter` — за feature-flag `MCP_NOTIFICATIONS_ENABLED=false`) для `approval.pending` / `scan.completed` / `critical.finding.detected` событий + per-LLM-client token-bucket rate-limiter (защита от runaway-loop'ов в Claude/GPT/Gemini). ARG-039 генерит OpenAPI 3.1 spec'у MCP-tools surface'а из Pydantic-моделей, публикует как `docs/mcp-server-openapi.yaml`, добавляет CI-gate: каждый public MCP tool обязан иметь docstring. После закрытия — backend MCP сервер становится integration-ready для production (notifications + SDK generation), без ручного парсинга manifest'а клиентами.

**Цель 6 — Test-infrastructure cleanup + cycle close.** ARG-037 закрывает 4 follow-up issue'а (`ISS-fix-004-imports`, `ISS-fix-006-imports`, `ISS-payload-signatures-drift`, `ISS-pytest-test-prefix-collisions`) одним worker-проходом с PR-чеклистом — мелкие правки, surfaced в ARG-028/ARG-029. ARG-038 локализует root-cause `apktool.yaml` mid-run mutation (несколько worker'ов в Cycle 3 поверхностно «починили» восстановлением из git без bisection'а) — единственная серьёзная test-infrastructure тайна, оставшаяся открытой. ARG-040 — capstone: расширяет coverage matrix с **12 → 14 контрактов** (новые C13 — `signature-mtime-stability` и C14 — `tool-yaml-version-field-presence`), регенерирует `docs/tool-catalog.md` (с per-image coverage по pinned-versions из ARG-026), пишет sign-off report Cycle 4, обновляет CHANGELOG, готовит Cycle 5 carry-over.

**Trade-offs:** Observability (OTel spans + Prometheus metrics, Backlog §15) — defer на Cycle 5 (см. §7 Risks). Frontend MCP integration — defer на Cycle 4-5 frontend workstream. Real cloud_iam ownership для AWS/GCP/Azure — defer на Cycle 5. Polный CISA SSVC v2.1 + EPSS percentile — defer на Cycle 5.

---

## 3. Tasks (10, упорядочены по зависимостям)

### ARG-031 — Valhalla tier renderer (executive summary + business-impact lens)

- **Status:** ⏸ Pending
- **Backlog reference:** §11 (Reporting — sections), §15 (Reports — Valhalla tier), §17 (snapshot tests), §19.4 (DoD: 12 reports — 18 ячеек matrix)
- **Priority:** HIGH
- **Complexity:** complex
- **Hours:** 8
- **Dependencies:** none (Cycle 3 ARG-024 / ARG-025 ✅ — pre-existing pass-through `tier_classifier._project_valhalla`)

**Description:**  
Замкнуть ReportService matrix (12 / 18 → **18 / 18**), добавив Valhalla tier — executive-level отчёт с business-impact lens'ом для CISO / Board / Audit. В отличие от Midgard (только counts + top-10) и Asgard (full findings + remediation + reproducer), Valhalla добавляет: risk-quantification per asset (CVSS × asset_business_value × exploitability), сжатую OWASP rollup-матрицу (Top-10 категории × severity), top-N findings ranked by `(severity × exploitability × business_value)` композитной метрикой, executive summary paragraph (auto-generated через prompt template `valhalla_executive_summary_v1` если LLM enabled, иначе deterministic template-fill), risk-trend graph (если есть >1 исторический scan). Реализация — mirror ARG-025 структуры: Pydantic-модель `ValhallaSectionAssembly` (immutable, frozen, hashable), pure-функция `assemble_valhalla_sections(scan_data, business_context, sanitize_context) → ValhallaSectionAssembly`, projector `valhalla_assembly_to_jinja_context(...)`, wire через `ReportService.render_bundle` для всех 6 форматов с byte-stable snapshot'ами (PDF — structural через `pypdf`).

**Acceptance criteria:**

- [ ] `backend/src/reports/valhalla_tier_renderer.py` — `class ValhallaSectionAssembly(BaseModel, frozen=True, extra="forbid")` со полями `executive_summary, risk_quantification_per_asset, owasp_rollup_matrix, top_findings_by_business_impact, remediation_roadmap, evidence_refs, timeline_entries`; pure-функция `assemble_valhalla_sections(scan_data, business_context, sanitize_context) → ValhallaSectionAssembly`; projector `valhalla_assembly_to_jinja_context(assembly) → dict[str, Any]`
- [ ] `backend/src/reports/tier_classifier.py` — расширить `_project_valhalla` (currently pass-through) на полный pipeline: композитная risk-метрика `(severity × exploitability × business_value)`, OWASP rollup (Top-10 × severity bins), business-impact ranking, threading `SanitizeContext` (Valhalla тоже сanitize'ит reproducer / timeline / PoC, как Asgard)
- [ ] `backend/src/reports/report_service.py` — `_build_jinja_context(...)` добавляет `valhalla_report` блок при `tier == ReportTier.VALHALLA`, mirror Asgard branch'у (ARG-025)
- [ ] `backend/src/reports/generators.py` — `generate_json(...)` embed'ит `valhalla_report` blob при `tier == VALHALLA` (mirror текущего Asgard pattern)
- [ ] Branded HTML template'ы в `backend/templates/reports/valhalla/` — executive layout (cover page с logo + tenant + scan_id + SHA-256, TOC, exec-summary section, risk-quant table, OWASP rollup matrix, top-N findings cards, evidence appendix, footer с page numbers + legal disclaimer)
- [ ] Unit tests — `backend/tests/unit/reports/test_valhalla_tier_renderer.py` (≥ 25 кейсов: assembly determinism, ordering invariants, sanitizer threading, business-context propagation, OWASP rollup correctness, presigned URL embedding)
- [ ] Integration tests — `backend/tests/integration/reports/test_valhalla_tier_all_formats.py` (≥ 18 кейсов: 6 форматов × 3 фикстура — minimal/typical/max-findings; PDF — structural snapshot через `pypdf`)
- [ ] Snapshot tests — `backend/tests/snapshots/reports/valhalla_canonical.{html,json,csv,sarif,xml}` byte-identical
- [ ] Security gate — `backend/tests/security/test_report_no_secret_leak.py` параметризован по {Midgard, Asgard, **Valhalla**} × 6 форматов × 55 secret patterns → итого **990 кейсов** (вместо 335) — ноль raw-secret bytes в Valhalla bundle bytes
- [ ] `mypy --strict --follow-imports=silent backend/src/reports/valhalla_tier_renderer.py backend/src/reports/tier_classifier.py backend/src/reports/report_service.py` — clean
- [ ] `ruff check + ruff format --check` — clean для touched files
- [ ] Coverage matrix gate всё ещё зелёный (12 × 157 = 1 884 кейсов; не ломаем существующие C1..C12)
- [ ] `docs/report-service.md` — новая секция `## ARG-031 — Valhalla tier` с tier diff table, branded template recipe, snapshot regen recipe
- [ ] CHANGELOG.md — `### Added (ARG-031 — Cycle 4: Valhalla tier renderer + business-impact lens)` block

**Files to create / modify:**

```
backend/src/reports/valhalla_tier_renderer.py             (new)
backend/src/reports/tier_classifier.py                    (modify: full _project_valhalla)
backend/src/reports/report_service.py                     (modify: VALHALLA branch in _build_jinja_context)
backend/src/reports/generators.py                         (modify: VALHALLA branch in generate_json)
backend/src/reports/__init__.py                           (modify: re-export public symbols)
backend/templates/reports/valhalla/{layout.html,exec_summary.html,risk_quant.html,owasp_rollup.html,top_findings.html,evidence.html,footer.html}
backend/tests/unit/reports/test_valhalla_tier_renderer.py (new)
backend/tests/integration/reports/test_valhalla_tier_all_formats.py (new)
backend/tests/security/test_report_no_secret_leak.py      (modify: parametrize on VALHALLA tier)
backend/tests/snapshots/reports/valhalla_canonical.{html,json,csv,sarif,xml} (new)
docs/report-service.md                                    (modify: +Valhalla section)
CHANGELOG.md                                              (modify: +ARG-031 entry)
```

**Workflow:** Worker → Test-writer → Security-auditor (sanitizer threading на новый tier!) → Test-runner → Reviewer

---

### ARG-032 — Per-tool parsers batch 4 (browser + binary + recon + auth, 30 tools, mapped → ~98)

- **Status:** ⏸ Pending
- **Backlog reference:** §4.2 (Active recon, 7/35 mapped) + §4.12 (Auth/brute, 3/11) + §4.18 (Binary/mobile, 1/5) + §4.19 (Browser-based, 0/6) + §11 (Evidence redaction)
- **Priority:** HIGH
- **Complexity:** complex
- **Hours:** 12
- **Dependencies:** none (Cycle 3 ARG-021/022/029 ✅ — `_base.py` / `_text_base.py` / `_jsonl_base.py` infrastructure готова; ARG-030 C11+C12 contracts ✅ — новые парсеры будут проверяться автоматически)

**Description:**  
Сократить heartbeat fallback с **89 → ~59 (-30)**, mapped с **68 → ~98 (+30)**, итог DoD §19.6 catalog coverage ratio **> 60 %**. Приоритет по `Parser coverage by category` секции `docs/tool-catalog.md` — три самые низкие категории (`browser` 0 %, `binary` 20 %, `recon` 20 %, `auth` 27 %). Каждый парсер — pure-функция `parse_<tool>(stdout, stderr, artifacts_dir, tool_id) → list[FindingDTO]` поверх единого `_base.py` / `_text_base.py` / `_jsonl_base.py` фундамента, ноль новых helper'ов; per-module coverage ≥ 90 %; интеграционный suite `test_arg032_dispatch.py` со всеми security-gate'ами (redaction completeness, dedup determinism, hash redaction где relevant). Разбить на 3 параллельных worker-batch'а для сокращения wall time:

- **Batch 4a (browser, 0/6):** `playwright_runner`, `pyppeteer_runner`, `puppeteer_runner`, `retire_js`, `chrome_devtools_csp`, `webcheck` (или другие 6 браузерных tools из §4.19; точный список — по актуальному catalog scan)
- **Batch 4b (binary, 1/5 → 5/5; recon overflow):** `radare2`, `ghidra_headless`, `ropgadget`, `capstone_disasm` + 6 recon tools (`assetfinder`, `subfinder`, `amass`, `dnsrecon`, `fierce`, `sublist3r`)
- **Batch 4c (auth + recon overflow):** `hydra`, `medusa`, `patator`, `ncrack`, `crackmapexec`, `responder`, `shodan_cli`, `censys_cli`, `whois`, `dnstwist`, `sn1per`, `nuclei_dns_takeover`, `ntdsxtract`, `secretsdump_remote`

(Точный per-batch список — finalize'ить worker'у на основе актуального `docs/tool-catalog.md::Parser coverage by category` после ARG-038 закроет apktool.yaml drift; цель — total +30, не строгое разделение.)

**Acceptance criteria:**

- [ ] +30 новых модулей `backend/src/sandbox/parsers/<tool>_parser.py`; ни один не превышает 350 LOC; средний ≈ 220 LOC; SoC: severity normaliser → category classifier → finding builder → sidecar emitter
- [ ] Все 30 — pure functions без I/O побочных эффектов (стандарт ARG-021/022/029)
- [ ] Регистрация в `_DEFAULT_TOOL_PARSERS` (+30 entries) — `mapped` parsers вырастают с 68 → ≥ 98; `heartbeat` сокращается с 89 → ≤ 59
- [ ] Unit tests: ≥ 6 кейсов на парсер → ≥ 180 новых unit-тестов
- [ ] Integration tests: `backend/tests/integration/sandbox/parsers/test_arg032_dispatch.py` (≥ 90 параметризованных кейсов: registration, dispatch, sidecar isolation, redaction, cross-routing, determinism, multi-tool I/O)
- [ ] **Critical security gates:** `responder` log → ноль NTLMv1/v2 hash bytes в sidecar (regex `[0-9a-fA-F]{16,}:[0-9a-fA-F]{32}`); `crackmapexec` cred-spray output → masked passwords; `playwright_runner` / `puppeteer_runner` / `pyppeteer_runner` screenshots → стрипают cookies / Authorization headers из HAR
- [ ] **Browser parsers** обязаны корректно обрабатывать BINARY_BLOB (PNG screenshots, video.webm, HAR.json) — `BINARY_BLOB skip-rule` сохранён, парсер только summarize'ит metadata (file count, severity rollup из retire-js JSON output)
- [ ] **Binary parsers** (radare2, ghidra, ropgadget, capstone) — обязаны hash-redact адреса памяти / register-state дампы перед записью в `evidence.raw_*` (если адреса попадают в evidence) — heuristic redaction для `0x[0-9a-fA-F]{8,}` patterns
- [ ] Coverage matrix gate (12 × 157 = 1 884) — все зелёные (новые парсеры автоматически проверяются C11 + C12); `_C12_KNOWN_LEAKERS` остаётся пустым
- [ ] Heartbeat fallback test для оставшихся ≤ 59 unmapped tools — ARGUS-HEARTBEAT path работает (verified by `test_heartbeat_finding.py`)
- [ ] `mypy --strict src/sandbox/parsers` — clean (все ~100 source files)
- [ ] `ruff check + ruff format --check src/sandbox/parsers tests/unit/sandbox/parsers tests/integration/sandbox/parsers` — clean
- [ ] Per-module coverage ≥ 90 % branch coverage (как в Cycle 3 ARG-029 — ни один модуль ниже 91 %)
- [ ] `docs/tool-catalog.md` регенерирован — `Mapped: ≥98 (≥62%)`, `Heartbeat: ≤59 (≤38%)` в header summary
- [ ] CHANGELOG.md — `### Added (ARG-032 — Cycle 4: Parsers batch 4 — browser/binary/recon/auth)` block с per-category дельтами

**Files to create / modify:**

```
backend/src/sandbox/parsers/{30 new <tool>_parser.py modules}
backend/src/sandbox/parsers/__init__.py                    (modify: +30 dispatch entries)
backend/tests/unit/sandbox/parsers/test_{30 new files}.py
backend/tests/fixtures/sandbox_outputs/{30 new tool dirs}/sample.{json,jsonl,txt,har}
backend/tests/integration/sandbox/parsers/test_arg032_dispatch.py     (new — ≥ 90 cases)
docs/tool-catalog.md                                       (regenerated)
CHANGELOG.md                                               (modify: +ARG-032 entry)
```

**Workflow:** Worker (×3 параллельные batch'и: 4a browser, 4b binary+recon, 4c auth) → Test-writer → Security-auditor (responder hash redaction + browser HAR cookie strip!) → Test-runner → Reviewer

---

### ARG-033 — Cosign keyless signing (GitHub OIDC + Sigstore Fulcio + Rekor transparency log)

- **Status:** ⏸ Pending
- **Backlog reference:** §9 (Sandbox runtime — supply chain), §16.13 (DevSecOps), §16.16 (deployment), DoD §19 (supply-chain gates)
- **Priority:** HIGH
- **Complexity:** moderate
- **Hours:** 5
- **Dependencies:** **ARG-034** (real `docker push` в `ghcr.io` обязан произойти раньше — ARG-033 подписывает уже-push'ed образы)

**Description:**  
Превратить `infra/scripts/sign_images.sh` skeleton (dry-run по умолчанию, реальная подпись только при наличии `COSIGN_KEY` env var) в production-ready подпись через **GitHub Actions OIDC + Sigstore Fulcio (keyless)**, с записью в Rekor transparency log. Удалить флаг `--tlog-upload=false`; добавить `cosign attest --predicate <SBOM> --type cyclonedx` для каждого образа (in-toto SLSA-style attestation). Добавить **verify-job** в CI (`cosign verify --certificate-identity-regexp "https://github\\.com/<org>/argus/.+@refs/heads/main" --certificate-oidc-issuer https://token.actions.githubusercontent.com`) — fail merge если подпись отсутствует или identity не матчит. Документировать в `docs/sandbox-images.md` § «Cosign keyless signing» полный recipe + roll-back plan (как откатиться на keyed mode если Sigstore down).

**Acceptance criteria:**

- [ ] `infra/scripts/sign_images.sh` — переписан под keyless mode по умолчанию: `cosign sign --yes <image>` без `--key`, `--tlog-upload=true` (default since cosign v2)
- [ ] `cosign attest --predicate <SBOM-path> --type cyclonedx --yes <image>` для каждого из 4 образов
- [ ] `.github/workflows/sandbox-images.yml::sign-images` job — keyless mode; secrets `COSIGN_PRIVATE_KEY` / `COSIGN_PASSWORD` больше не нужны (удалены из job env); `permissions.id-token: write` уже включён в Cycle 3 — оставить
- [ ] **Новый job** `verify-images` в `.github/workflows/sandbox-images.yml`:
  - Запускается после `sign-images`
  - `cosign verify --certificate-identity-regexp '^https://github\\.com/[^/]+/[^/]+/\\.github/workflows/sandbox-images\\.yml@refs/heads/main$' --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' <image>`
  - `cosign verify-attestation --type cyclonedx --certificate-identity-regexp ... <image>` — атестейшн SBOM
  - Fail на missing signature ИЛИ certificate identity mismatch
- [ ] Branch protection rule — добавить требование `verify-images` job pass для merge в `main`
- [ ] **Rollback plan** в `docs/sandbox-images.md`:
  - Раздел «Cosign keyless signing» — full recipe с YAML примерами
  - Раздел «Rollback to keyed mode» — pinned cosign v2 invocation если Fulcio / Rekor недоступны: `cosign sign --key <key.pem> --tlog-upload=false <image>` + warning что transparency log будет вне зоны действия
  - Раздел «Verifying offline» — `cosign verify --offline --certificate ... --rekor-url ...`
- [ ] Acceptance test (manual / CI): `cosign verify --certificate-identity-regexp <pattern> --certificate-oidc-issuer https://token.actions.githubusercontent.com ghcr.io/<org>/argus-kali-web:<tag>` — exit 0
- [ ] mypy / ruff — N/A (script-only); `shellcheck infra/scripts/sign_images.sh` — clean
- [ ] CHANGELOG.md — `### Changed (ARG-033 — Cycle 4: Cosign keyless prod wiring + Rekor + SLSA attestation)` block

**Files to create / modify:**

```
infra/scripts/sign_images.sh                              (rewrite: keyless mode + cosign attest)
.github/workflows/sandbox-images.yml                      (modify: sign-images keyless + new verify-images job)
docs/sandbox-images.md                                    (modify: +Cosign keyless section + rollback plan)
CHANGELOG.md                                              (modify: +ARG-033 entry)
```

**Workflow:** Worker → Security-auditor (signature verification logic, OIDC trust chain!) → Test-runner (CI smoke) → Reviewer

---

### ARG-034 — Image-build CI gating (real `docker build` + push to ghcr.io + SBOM as OCI artefact + Trivy blocking)

- **Status:** ⏸ Pending
- **Backlog reference:** §9 (Sandbox runtime), §16.13 (DevSecOps gates), §16.16 (deployment), DoD §19.1 (`pytest -q` green incl. CI), DoD §19.4 (sandbox stack ready)
- **Priority:** **CRITICAL**
- **Complexity:** moderate
- **Hours:** 5
- **Dependencies:** none (Cycle 3 ARG-026 ✅ — Dockerfiles + `infra/scripts/build_images.sh` готовы; ARG-033 надстраивает поверх ARG-034)

**Description:**  
Переключить `.github/workflows/sandbox-images.yml::build-images` job из «build + extract SBOM локально + upload-artifact (retention 30d)» в «build + push в `ghcr.io/<org>/argus-kali-<profile>:<tag>` + push SBOM как OCI artefact через `cosign attach sbom <image> --sbom <path>`». Включить `paths-filter` по `sandbox/images/**` + `infra/scripts/{build,sign}_images.sh` для экономии CI-минут (текущая конфигурация уже это делает — расширить и убедиться что также ловит ARG-033 changes). Добавить gate на merge в `main`: build-images матрица [web, cloud, browser, full] обязана пройти **И** push в GHCR обязан succeed (`needs:` chain). Trivy scan job переключить с `informational` (`continue-on-error: true`, `exit-code: '0'`) на **blocking** (`exit-code: '1'`, `severity: CRITICAL,HIGH`, `ignore-unfixed: false`). Добавить branch protection rule: `build-images / build (web)`, `build-images / build (cloud)`, `build-images / build (browser)`, `build-images / build (full)` — required status checks для merge.

**Acceptance criteria:**

- [ ] `.github/workflows/sandbox-images.yml::build-images` job:
  - Login в GHCR через `docker login ghcr.io -u $GITHUB_ACTOR -p $GITHUB_TOKEN` (используя `permissions.packages: write`, который уже включён в Cycle 3)
  - `docker push ghcr.io/<org>/argus-kali-${profile}:${tag}` после `docker build`
  - `cosign attach sbom ghcr.io/<org>/argus-kali-${profile}:${tag} --sbom ${SBOM_PATH}` (требует cosign v2.x; auth через `id-token: write` для keyless attach)
  - SBOM artefact upload (`actions/upload-artifact@v4`) — оставить как backup на 30 дней + push как OCI artefact
- [ ] `paths-filter` extended — добавить `.github/workflows/sandbox-images.yml`, `infra/scripts/build_images.sh`, `infra/scripts/sign_images.sh` в paths trigger (уже частично есть — verify completeness)
- [ ] Trivy scan job — **blocking** mode:
  - `continue-on-error: true` → `false`
  - `exit-code: '0'` → `'1'`
  - `severity: 'CRITICAL,HIGH'` остаётся
  - `ignore-unfixed: false` (Cycle 3 был `true` — fail on unfixed CRITICAL)
  - Добавить allowlist в `.trivyignore` для known-acceptable Kali-rolling base CVEs (документировать каждую entry с justification + expiry date 90 дней)
- [ ] Branch protection rules в `.github/branch-protection.yml` (или GitHub UI документировано в `docs/sandbox-images.md`):
  - Required status checks: `build-images / build (web)`, `build-images / build (cloud)`, `build-images / build (browser)`, `build-images / build (full)`, `hardening-contract`, `verify-images` (после ARG-033 включит)
  - Strict: false (allow merge если check up-to-date с base, не требовать rebuild на каждый rebase)
- [ ] **DoD §19.1 проверка**: `test-no-docker` + `test-docker-required` jobs из Cycle 3 ARG-028 — добавить в required status checks (если ещё не there)
- [ ] **DoD §19.4 partial**: `docker compose -f infra/docker-compose.yml up -d` — добавить smoke job который проверяет что 4 sandbox image'а pull'ятся из GHCR и стартуют (без e2e scan — это Cycle 6)
- [ ] `docs/sandbox-images.md` — обновить с новыми GHCR registry pattern + branch protection setup checklist + `.trivyignore` curation policy
- [ ] CHANGELOG.md — `### Changed (ARG-034 — Cycle 4: Image build CI gating + GHCR push + Trivy blocking + branch protection)` block

**Files to create / modify:**

```
.github/workflows/sandbox-images.yml                      (modify: GHCR push, OCI SBOM attach, Trivy blocking)
.trivyignore                                              (new — curated allowlist with expiry dates)
infra/scripts/build_images.sh                             (modify: optional --push flag for CI)
docs/sandbox-images.md                                    (modify: +GHCR + branch protection + .trivyignore policy)
CHANGELOG.md                                              (modify: +ARG-034 entry)
```

**Workflow:** Worker → Security-auditor (Trivy gate threshold, .trivyignore policy) → Test-runner (CI smoke per profile) → Reviewer

---

### ARG-035 — MCP webhook integrations (Slack / Linear / Jira) + per-LLM-client token-bucket rate-limiter

- **Status:** ⏸ Pending
- **Backlog reference:** §13 (MCP server), §15 (Observability — webhook events), §18 (Critical guardrails — rate limiter)
- **Priority:** MEDIUM
- **Complexity:** complex
- **Hours:** 8
- **Dependencies:** none (Cycle 3 ARG-023 ✅ — MCP server scaffold готов; secret-management через переменные окружения)

**Description:**  
Добавить три webhook-эмиттера в `backend/src/mcp/services/notifications/`:

- **`SlackNotifier`** — POST в incoming webhook URL на события `approval.pending`, `scan.completed`, `critical.finding.detected`. Block-format payload (interactive — кнопки Approve/Deny для approval'ов). Retry с exponential backoff (max 3 retry, jittered 1s/4s/16s).
- **`LinearAdapter`** — `linear-sdk` GraphQL mutation `issueCreate` для critical/high findings; map: `severity → Linear priority` (critical → urgent, high → high), `tenant_id → Linear team`, finding evidence URL → issue description; idempotent через `external_id = finding.root_cause_hash` (предотвращает дубли при retry'ях).
- **`JiraAdapter`** — same через Jira REST API v3 (`POST /rest/api/3/issue`). Custom field `argus_finding_id` для traceability.

Все три behind feature-flag `MCP_NOTIFICATIONS_ENABLED=false` по умолчанию (signed manifest `backend/config/mcp/server.yaml` resolves flag → enabled set per-tenant). Secret-management: webhook URLs / API tokens — env vars (`SLACK_WEBHOOK_URL`, `LINEAR_API_KEY`, `JIRA_API_TOKEN`); никогда не в config YAML.

Параллельно: per-LLM-client **token-bucket rate-limiter** (`MCPRuntime.rate_limiter`). Per-client (Claude / GPT / Gemini / generic) + per-tenant budget (`tokens_per_minute`, `burst_size`). Защита от runaway-loop'ов (LLM, который начинает спамить `tool.run.trigger` без human-in-the-loop). Лимиты конфигурируются в signed manifest `backend/config/mcp/server.yaml`. Implementation: in-memory bucket + Redis-backed bucket для distributed deployment (feature-flag `MCP_RATE_LIMITER_BACKEND=memory|redis`).

**Acceptance criteria:**

- [ ] `backend/src/mcp/services/notifications/__init__.py` — public re-exports `SlackNotifier`, `LinearAdapter`, `JiraAdapter`, `NotificationDispatcher`
- [ ] `backend/src/mcp/services/notifications/{slack,linear,jira}.py` — каждый адаптер typed Pydantic schemas, retry with exponential backoff, **circuit breaker** (после 5 consecutive failures — disable adapter на 60s, structured warning `mcp.notifications.circuit_open`)
- [ ] `backend/src/mcp/services/notifications/dispatcher.py` — `NotificationDispatcher` — multiplexes events to enabled adapters (per-tenant flags); idempotency через `external_id = event.event_id`; ровно-один-доставка best-effort с idempotency dedup
- [ ] **Secret hygiene:**
  - Webhook URLs / tokens только в env vars (verified by `bandit -r backend/src/mcp/services/notifications` — ноль hard-coded URLs / tokens)
  - Audit log не пишет webhook payloads целиком — только `event_id` + `adapter_name` + `target_redacted` (`hash(URL)[:12]`)
  - Failed delivery → structured warning + retry queue (Redis); ноль PII / secrets в log lines
- [ ] `backend/src/mcp/runtime/rate_limiter.py` — `TokenBucketLimiter` interface + `InMemoryTokenBucket` + `RedisTokenBucket` implementations
- [ ] `MCPRuntime` integration — каждый `tools/call` request проходит через `rate_limiter.acquire(client_id, tenant_id, tokens=1)`; при reject → JSON-RPC error `-32029 RateLimitExceeded` + `Retry-After` header
- [ ] `backend/config/mcp/server.yaml` — новые поля `notifications.{slack,linear,jira}.{enabled, per_tenant_overrides}` + `rate_limiter.{backend, per_client_budgets, per_tenant_budgets}` (signed manifest — пере-подписать через `python -m scripts.mcp_sign sign ...`)
- [ ] Unit tests:
  - `tests/unit/mcp/services/notifications/test_{slack,linear,jira}.py` — payload shape, retry behavior, circuit breaker, idempotency dedup (≥ 15 cases per adapter, ≥ 45 total)
  - `tests/unit/mcp/runtime/test_rate_limiter.py` — token bucket math, burst behavior, per-client / per-tenant isolation, race-condition tests (≥ 20 cases)
- [ ] Integration tests:
  - `tests/integration/mcp/test_notifications_dispatch.py` — full dispatcher cycle с mock'ами Slack/Linear/Jira HTTP endpoints (≥ 12 cases)
  - `tests/integration/mcp/test_rate_limiter_under_load.py` — concurrent `tools/call` requests, verify bucket math holds (≥ 8 cases)
- [ ] **Critical security gates:**
  - Webhook payload не утекает: `tests/security/test_mcp_notification_no_secret_leak.py` — fixture с finding, который содержит embedded secrets → assert webhook payload (через mock) ноль raw-secret bytes (использует `replay_command_sanitizer` из ARG-025)
  - Rate-limiter не bypass'ится через cross-tenant attack: `test_rate_limiter_per_tenant_isolation` — два tenant'а с одинаковым `client_id` имеют независимые buckets
- [ ] `mypy --strict src/mcp/services/notifications src/mcp/runtime` — clean
- [ ] `ruff check + format --check` — clean для touched files
- [ ] `bandit -r src/mcp/services/notifications` — silent (no findings)
- [ ] `docs/mcp-server.md` — новые секции `## Notifications (Slack/Linear/Jira)` + `## Rate Limiting (per-client token bucket)`
- [ ] CHANGELOG.md — `### Added (ARG-035 — Cycle 4: MCP webhooks + per-LLM-client rate limiter)` block

**Files to create / modify:**

```
backend/src/mcp/services/notifications/{__init__,slack,linear,jira,dispatcher}.py     (new package)
backend/src/mcp/runtime/rate_limiter.py                                                (new)
backend/src/mcp/runtime/__init__.py                                                    (modify: re-exports)
backend/src/mcp/server.py                                                              (modify: rate_limiter wiring)
backend/config/mcp/server.yaml                                                         (modify: notifications + rate_limiter sections)
backend/config/mcp/SIGNATURES                                                          (modify: re-signed manifest)
backend/tests/unit/mcp/services/notifications/test_{slack,linear,jira,dispatcher}.py   (new)
backend/tests/unit/mcp/runtime/test_rate_limiter.py                                    (new)
backend/tests/integration/mcp/test_notifications_dispatch.py                           (new)
backend/tests/integration/mcp/test_rate_limiter_under_load.py                          (new)
backend/tests/security/test_mcp_notification_no_secret_leak.py                         (new)
docs/mcp-server.md                                                                     (modify: +Notifications + Rate Limiting sections)
CHANGELOG.md                                                                           (modify: +ARG-035 entry)
```

**Workflow:** Worker → Test-writer → Security-auditor (webhook secret-handling, circuit breaker, rate-limiter cross-tenant isolation!) → Test-runner → Reviewer

---

### ARG-036 — ReportService PDF templating polish (branded WeasyPrint + LaTeX fallback + PDF determinism)

- **Status:** ⏸ Pending
- **Backlog reference:** §11 (Reporting — affected asset, evidence block, remediation, timeline), §15 (Reports — PDF format), §17 (snapshot tests), §19.4 (DoD: 12 reports)
- **Priority:** HIGH
- **Complexity:** complex
- **Hours:** 7
- **Dependencies:** **ARG-031** (Valhalla — для бизнес-template'а; Midgard / Asgard branded templates можно начинать параллельно с ARG-031)

**Description:**  
Заменить generic-WeasyPrint stub в `src/reports/generators.py::generate_pdf` на полноценные branded HTML/CSS template'ы под все три tier'а (Midgard CISO-facing, Asgard sec-team, Valhalla executive). Каждый template — logo (operator brand или ARGUS default), цветовая схема per-tier (Midgard синий, Asgard оранжевый, Valhalla золотой), header / footer с `tenant_id + scan_id + SHA-256` watermark, page numbering, TOC (через WeasyPrint `--pdf-bookmark` + CSS `target-counter()`). PDF determinism (где возможно): fixed font embedding (Inter / DejaVu Sans bundled, не system fonts), fixed `@bottom-center { content: "ARGUS Confidential — page " counter(page) " of " counter(pages) }`, no `/CreationDate` randomness через `weasyprint.HTML(...).write_pdf(metadata={"creator": "ARGUS", "creation_date": SCAN_TIMESTAMP})` (fixed timestamp = scan completion timestamp, не wall-clock). Optional **LaTeX fallback** через `jinja2-latex` + `latexmk` для CI окружений без Cairo/Pango/GDK-PixBuf native libs (типичный CI bug — Cycle 3 ARG-024/025 PDF tests всегда skip на Windows host). Behind feature-flag `REPORT_PDF_BACKEND=weasyprint|latex|disabled` (env var, читается на ReportService init). Snapshot-тест с `pypdf` для structural equality (page count, section headers, embedded images count, embedded font names) — без byte-equality (deterministic creation_date достаточно, но font subsetting hashes WeasyPrint-version-specific).

**Acceptance criteria:**

- [ ] Branded template'ы:
  - `backend/templates/reports/midgard/pdf_layout.html` + `pdf_styles.css` — синяя цветовая схема, exec-summary layout
  - `backend/templates/reports/asgard/pdf_layout.html` + `pdf_styles.css` — оранжевая цветовая схема, full findings layout с remediation cards
  - `backend/templates/reports/valhalla/pdf_layout.html` + `pdf_styles.css` — золотая цветовая схема, executive layout (TOC, risk-quant tables, OWASP rollup matrix); from ARG-031
- [ ] Bundled fonts в `backend/templates/reports/_fonts/` (Inter Regular + Bold + Italic; DejaVu Sans для Cyrillic/Asian fallback) — все licensed permissively (SIL OFL)
- [ ] `backend/src/reports/pdf_backend.py` — `class PDFBackend(Protocol)` + `WeasyPrintBackend`, `LatexBackend`, `DisabledBackend` implementations
- [ ] `backend/src/reports/generators.py::generate_pdf` — dispatch к active backend через `os.environ.get("REPORT_PDF_BACKEND", "weasyprint")`; fallback chain weasyprint → latex → disabled (graceful 503 если все unavailable)
- [ ] PDF determinism — fixed `creation_date = scan.completed_at` (не `datetime.now()`); fixed `metadata.producer = "ARGUS Cycle 4"`; verified by `test_pdf_creation_date_is_scan_timestamp`
- [ ] LaTeX backend — `jinja2-latex` template'ы в `backend/templates/reports/_latex/{midgard,asgard,valhalla}/main.tex.j2`; `latexmk -pdf -interaction=nonstopmode -output-directory=<tmpdir>` invocation; required system pkg: `texlive-latex-recommended` + `texlive-fonts-recommended` (документировать в `docs/report-service.md`)
- [ ] Snapshot tests — `tests/integration/reports/test_pdf_branded.py`:
  - 3 tiers × 1 PDF backend (weasyprint default) = 3 кейса; каждый assert через `pypdf`: ≥ 1 page, TOC present (для valhalla, asgard ≥ 2 pages), header/footer text contains `ARGUS Confidential`, embedded fonts list contains `Inter`, creation_date == fixture's `scan.completed_at`
  - 3 tiers × 1 LaTeX backend = 3 кейса (skipped if `latexmk` not on PATH; добавить `requires_latex` pytest marker)
- [ ] Visual regression — bundle `tests/snapshots/reports/midgard.pdf.png` (1st page rendered to PNG через `pdftoppm`) для manual visual review; не enforced byte-equal, но stored для design audit'а
- [ ] **Critical:** `tests/security/test_report_no_secret_leak.py` extended на PDF byte-content (через `pypdf.extract_text()`) — Asgard / Valhalla PDF не содержат raw secrets из 55 patterns
- [ ] `mypy --strict src/reports/pdf_backend.py src/reports/generators.py` — clean
- [ ] `ruff check + format --check` — clean для touched files
- [ ] `docs/report-service.md` — новые секции:
  - `## PDF Backends — WeasyPrint vs LaTeX trade-offs`
  - `## Branded Templates — designer customisation guide`
  - `## PDF determinism guarantees`
  - System pkg requirements per backend (Cairo/Pango/GDK-PixBuf for WeasyPrint; texlive for LaTeX)
- [ ] CHANGELOG.md — `### Changed (ARG-036 — Cycle 4: PDF templating polish + LaTeX fallback + determinism)` block

**Files to create / modify:**

```
backend/src/reports/pdf_backend.py                                                   (new)
backend/src/reports/generators.py                                                    (modify: dispatch via PDFBackend)
backend/templates/reports/midgard/{pdf_layout.html,pdf_styles.css}                   (new — branded)
backend/templates/reports/asgard/{pdf_layout.html,pdf_styles.css}                    (new — branded)
backend/templates/reports/valhalla/{pdf_layout.html,pdf_styles.css}                  (new — branded; from ARG-031)
backend/templates/reports/_fonts/{Inter-{Regular,Bold,Italic}.woff2,DejaVuSans.woff2} (new — bundled)
backend/templates/reports/_latex/{midgard,asgard,valhalla}/main.tex.j2               (new — LaTeX fallback)
backend/tests/integration/reports/test_pdf_branded.py                                (new)
backend/tests/security/test_report_no_secret_leak.py                                 (modify: PDF text extraction check)
backend/tests/snapshots/reports/{midgard,asgard,valhalla}.pdf.png                    (new — visual regression baselines)
backend/pyproject.toml                                                               (modify: +jinja2-latex dev dep)
docs/report-service.md                                                               (modify: +PDF backends section)
CHANGELOG.md                                                                         (modify: +ARG-036 entry)
```

**Workflow:** Worker → Test-writer → Test-runner → Reviewer (с дизайнером — manual visual review PNG snapshots)

---

### ARG-037 — Stale-import cleanup batch (4 follow-up issues from ARG-028 / ARG-029)

- **Status:** ⏸ Pending
- **Backlog reference:** §17 (Test discipline), §19.2 (DoD: ruff/mypy clean), §16.10 (Docs hygiene)
- **Priority:** MEDIUM
- **Complexity:** moderate
- **Hours:** 4
- **Dependencies:** none (Cycle 3 ARG-028 ✅ — pytest marker discipline established)

**Description:**  
Закрыть 4 follow-up issue'а одним worker-проходом с PR-чеклистом. Каждый по отдельности — мелкая правка, но требует систематического прогона по нескольким файлам:

1. **`ISS-fix-004-imports`** — stale import'ы в `src/api/routers/*.py` (несколько `from src.X import Y` где `Y` уже не существует или переехал между Cycle 1 → Cycle 3 рефакторингами). Surface'ed в `ruff check` (Cycle 3 sign-off — 98 pre-existing F401/F811 warnings); фиксы делятся на **dead imports** (просто удалить) и **moved symbols** (заменить путь).
2. **`ISS-fix-006-imports`** — same в `src/services/*.py`. Cycle 3 sign-off отдельно посчитал: ~60 instances в этих двух директориях.
3. **`ISS-payload-signatures-drift`** — `backend/config/payloads/SIGNATURES` content-hash для нескольких `*.yaml` периодически расходится с YAML после некоторых test-runs. Скоррелировано с ARG-038 (apktool drift), но не идентично — отдельная investigation. Скорее всего: какой-то integration test переписывает payload yaml для теста versioning'а и не восстанавливает.
4. **`ISS-pytest-test-prefix-collisions`** — несколько `tests/test_*.py` модулей содержат class'ы с одинаковыми prefix'ами (`TestUser`, `TestScan`, `TestFinding` встречается в 3-5 разных модулях соответственно). В legacy `pytest-rootdir` mode это работает, но в `pyproject-mode` (актуальный для ARG-028) ломает test discovery на edge cases (parametrize id collision). Решение — переименовать в `TestUserAuth`, `TestUserModel`, `TestUserAPI` etc.

**Acceptance criteria:**

- [ ] **ISS-fix-004:** `ruff check src/api/routers --select F401,F811` — clean (ноль unused / re-imported); каждый dead import документирован в commit message с обоснованием
- [ ] **ISS-fix-006:** `ruff check src/services --select F401,F811` — clean
- [ ] **ISS-payload-signatures-drift:** root-cause локализован (bisection через `git bisect run pytest` или `pytest --collect-only -k <pattern>` сужающий до конкретного теста); fix:
  - Если test mutates payload — переместить mutation в `tmp_path`, не трогать ground-truth `backend/config/payloads/*.yaml`
  - Если test legitimately validates re-signing — обернуть в fixture `restore_payload_signatures` с `yield + restore-from-git`
  - Если YAML auto-formatter (ruff/black) переписывает — pin formatting в `pre-commit` config с `--check` mode на `config/payloads/**`
- [ ] **ISS-pytest-prefix-collisions:** `pytest --collect-only -q 2>&1 | rg 'class TestX'` — каждое class name уникально; renamed classes документированы в commit message
- [ ] Все 4 fix'а — отдельные коммиты в одной PR'ке (`fix(api): remove dead imports (ISS-fix-004)`, `fix(services): remove dead imports (ISS-fix-006)`, `fix(payloads): isolate test mutation (ISS-payload-drift)`, `test(*): rename class collisions (ISS-pytest-prefix)`)
- [ ] `pytest -q` (dev-default, no docker) — passes; test count ≥ baseline 9 278 (нет регрессии тестов из переименований)
- [ ] `ruff check src tests --select F401,F811` — count 98 (Cycle 3 baseline) → **0** для touched directories (api/routers, services); остальные F401/F811 в `src/recon/*` и legacy test-модулях документированы как Cycle 5 (не trogаем)
- [ ] `python -m scripts.payloads_sign verify` — ✅ exit 0 (`verified_count=23`); запустить дважды подряд + после полного `pytest -q` — drift ноль
- [ ] CHANGELOG.md — `### Fixed (ARG-037 — Cycle 4: stale-import cleanup + payload signature drift + test prefix collisions)` block

**Files to create / modify:**

```
backend/src/api/routers/*.py                              (modify: dead imports removed)
backend/src/services/*.py                                 (modify: dead imports removed)
backend/config/payloads/*.yaml                            (NOT modified — but root-cause may touch tests/conftest.py or specific fixtures)
backend/tests/conftest.py                                 (modify: +restore_payload_signatures fixture if needed)
backend/tests/test_*.py                                   (rename: TestX collisions disambiguated)
.pre-commit-config.yaml                                   (modify: +ruff format --check on config/payloads if needed)
ai_docs/develop/issues/ISS-fix-004-imports.md             (close — link to PR)
ai_docs/develop/issues/ISS-fix-006-imports.md             (close — link to PR)
ai_docs/develop/issues/ISS-payload-signatures-drift.md    (close — link to PR + root-cause writeup)
ai_docs/develop/issues/ISS-pytest-test-prefix-collisions.md  (close — link to PR)
CHANGELOG.md                                              (modify: +ARG-037 entry)
```

**Workflow:** Worker → Test-runner → Reviewer

---

### ARG-038 — `apktool.yaml` drift root-cause investigation + fixture isolation

- **Status:** ⏸ Pending
- **Backlog reference:** §17 (Test discipline — read-only ground truth), §16.2 (Tool registry signing invariant)
- **Priority:** LOW
- **Complexity:** simple
- **Hours:** 3
- **Dependencies:** none (parallel с любой другой задачей; не блокирует ARG-032 даже хотя оба touch tools/)

**Description:**  
В нескольких worker-проходах Cycle 3 (ARG-021, ARG-022, ARG-027, ARG-029) поверхностно всплыла идентичная аномалия: `backend/config/tools/apktool.yaml` мутировался mid-run каким-то test'ом / fixture'ом, и `python -m scripts.docs_tool_catalog --check` начинал ругаться на signature drift между YAML hash'ом и записью в `SIGNATURES`. Никто из worker'ов не локализовал root-cause — каждый просто восстанавливал YAML из git и шёл дальше. Cycle 4 закрывает этот тайник:

1. Запустить bisection: `pytest --collect-only -q | shuf | head -1000 | xargs pytest --tb=short` повторять с binary search до конкретного test ID, который мутирует `apktool.yaml`. Альтернатива: `inotify-watch` на `config/tools/apktool.yaml` во время `pytest -q` run + correlate timestamps с `pytest --verbose` log.
2. Когда тест найден — определить, mutation **legitimate** (тест валидирует `ToolRegistry.reload()` после YAML edit) или **accidental** (тест случайно открывает yaml на write через `open(..., "w")` вместо `tmp_path`).
3. Применить fix:
   - Legitimate → mutation должна происходить в `tmp_path` копии, не в ground-truth; fixture `read_only_catalog` (новая) делает `pathlib.Path.chmod(0o444)` на `config/tools/*.yaml` для сессии теста
   - Accidental → fix теста (использовать `tmp_path` вместо ground-truth)
4. Защититься: `tests/conftest.py::pytest_collection_modifyitems` hook отмечает все тесты которые **должны** иметь право мутировать catalog (явный marker `@pytest.mark.mutates_catalog`); все остальные — read-only (chmod 0444 в session-scope fixture, restore в teardown).

**Acceptance criteria:**

- [ ] Root-cause локализован — конкретный test ID документирован в `ai_docs/develop/issues/ISS-apktool-drift-rootcause.md` (новый issue, closing) с git blame на проблемную строку
- [ ] Fix применён по соответствующему сценарию (legitimate / accidental)
- [ ] **Read-only catalog fixture:** `backend/tests/conftest.py` — новый session-scope fixture `read_only_catalog`:
  - До session: `chmod 0444 backend/config/{tools,payloads,prompts}/*.yaml + backend/config/{tools,payloads,prompts}/SIGNATURES`
  - После session: `chmod 0644` (restore)
  - Skipped для тестов с `@pytest.mark.mutates_catalog` marker
- [ ] **Negative test:** новый `backend/tests/test_catalog_immutable_during_pytest.py` — после полного `pytest -q -m "not requires_docker"` run, `python -m scripts.tools_sign verify` + `python -m scripts.payloads_sign verify` + `python -m scripts.prompts_sign verify` все ✅ EXIT=0 без manual git restore
- [ ] **Smoke (manual + CI):** запустить `pytest -q` 5 раз подряд → `python -m scripts.tools_sign verify` → exit 0 каждый раз; ноль drift
- [ ] `ruff check + format --check` — clean для touched files
- [ ] CHANGELOG.md — `### Fixed (ARG-038 — Cycle 4: apktool.yaml drift root-cause + read-only catalog fixture)` block

**Files to create / modify:**

```
backend/tests/conftest.py                                 (modify: +read_only_catalog session fixture)
backend/tests/<test that mutates apktool.yaml>            (modify: use tmp_path)
backend/tests/test_catalog_immutable_during_pytest.py     (new — regression gate)
backend/pyproject.toml                                    (modify: register `mutates_catalog` marker)
ai_docs/develop/issues/ISS-apktool-drift-rootcause.md     (new — closes investigation)
CHANGELOG.md                                              (modify: +ARG-038 entry)
```

**Workflow:** Worker (bisection-heavy) → Test-runner → Reviewer

---

### ARG-039 — OpenAPI 3.1 export of MCP server schema + TypeScript SDK generation + docstring CI gate

- **Status:** ⏸ Pending
- **Backlog reference:** §13 (MCP server), §16.10 (Docs), §17 (snapshot tests)
- **Priority:** MEDIUM
- **Complexity:** moderate
- **Hours:** 4
- **Dependencies:** none (Cycle 3 ARG-023 ✅ — MCP server schemas finalized)

**Description:**  
Сейчас MCP server (`backend/src/mcp/`) описан signed manifest'ом `backend/config/mcp/server.yaml` + Pydantic-схемами в `backend/src/mcp/schemas/*.py`. Клиенты вынуждены либо парсить manifest, либо вручную писать TypeScript / Python типы. ARG-039:

1. Сгенерить OpenAPI 3.1 spec'у MCP-tools surface'а из Pydantic-моделей (через `pydantic.json_schema_of()` + custom OpenAPI emitter, который маппит JSON-RPC 2.0 method'ы в `paths` / `operations`). Опубликовать как `docs/mcp-server-openapi.yaml` (single canonical source of truth).
2. Автоматическая генерация TypeScript SDK через `openapi-typescript-codegen` (CI job → publish в `Frontend/src/sdk/argus-mcp/`); pinned npm version, deterministic output.
3. CI-gate: каждый public MCP tool (15 шт.) обязан иметь docstring (Pydantic model docstring + `@mcp.tool()` decorator description). Existing tools уже имеют docstrings (Cycle 3 ARG-023), но CI gate enforces для новых tools (ARG-035 webhook tools например).
4. Snapshot test: `tests/integration/mcp/test_openapi_export_stable.py` — pytest fixture генерит OpenAPI spec → assert `docs/mcp-server-openapi.yaml` matches (regenerate через `python -m scripts.export_mcp_openapi --check` если drift).

**Acceptance criteria:**

- [ ] `backend/scripts/export_mcp_openapi.py` — CLI tool: `python -m scripts.export_mcp_openapi [--check] [--out PATH]`. `--check` — exit 1 если committed `docs/mcp-server-openapi.yaml` не матчит generated; `--out` — write to file
- [ ] `backend/src/mcp/openapi_emitter.py` — pure-функция `build_openapi_spec(mcp_runtime: MCPRuntime) → dict` — обходит `_REGISTERED_TOOLS / _REGISTERED_RESOURCES / _REGISTERED_PROMPTS`, генерит valid OpenAPI 3.1 (info, servers, paths={JSON-RPC method per tool}, components.schemas={Pydantic→JSON-Schema через `model_json_schema()`})
- [ ] `docs/mcp-server-openapi.yaml` — initial commit (155+ lines: 15 tools + 4 resources + 3 prompts + shared schemas)
- [ ] `Frontend/src/sdk/argus-mcp/` — generated TypeScript SDK через `npx openapi-typescript-codegen --input docs/mcp-server-openapi.yaml --output Frontend/src/sdk/argus-mcp --client fetch --useUnionTypes`; pinned `openapi-typescript-codegen@0.29.0` в `Frontend/package.json` devDeps
- [ ] `Frontend/src/sdk/argus-mcp/.gitignore` — НЕТ; SDK committed в repo для reproducibility (cycle 5 будет переход на npm package если Frontend team согласится)
- [ ] CI gate: `.github/workflows/ci.yml` — добавить job `mcp-openapi-drift`:
  - `python -m scripts.export_mcp_openapi --check` — fail если drift
  - `cd Frontend && npm run sdk:check` (новый script: `openapi-typescript-codegen ... && git diff --exit-code src/sdk/argus-mcp`)
- [ ] **Docstring CI gate:** `tests/test_mcp_tools_have_docstrings.py` — для каждого `@mcp.tool` декорированного callable assert `inspect.getdoc(callable) is not None and len(...) > 30` (минимум 30 chars meaningful docstring); same для `@mcp.resource` + `@mcp.prompt`
- [ ] Snapshot test: `tests/integration/mcp/test_openapi_export_stable.py` — `assert build_openapi_spec(runtime) == load_yaml(docs/mcp-server-openapi.yaml)` (round-trip stable)
- [ ] `mypy --strict src/mcp/openapi_emitter.py scripts/export_mcp_openapi.py` — clean
- [ ] `ruff check + format --check` — clean
- [ ] `docs/mcp-server.md` — новая секция `## OpenAPI 3.1 export + TypeScript SDK` + recipe `python -m scripts.export_mcp_openapi --out docs/mcp-server-openapi.yaml`
- [ ] CHANGELOG.md — `### Added (ARG-039 — Cycle 4: MCP OpenAPI 3.1 export + TS SDK + docstring CI gate)` block

**Files to create / modify:**

```
backend/src/mcp/openapi_emitter.py                        (new)
backend/scripts/export_mcp_openapi.py                     (new — CLI)
backend/tests/test_mcp_tools_have_docstrings.py           (new — gate)
backend/tests/integration/mcp/test_openapi_export_stable.py  (new — snapshot)
docs/mcp-server-openapi.yaml                              (new — generated, committed)
docs/mcp-server.md                                        (modify: +OpenAPI section)
Frontend/src/sdk/argus-mcp/**/*                           (new — auto-generated SDK)
Frontend/package.json                                     (modify: +openapi-typescript-codegen devDep + sdk:check script)
.github/workflows/ci.yml                                  (modify: +mcp-openapi-drift job)
CHANGELOG.md                                              (modify: +ARG-039 entry)
```

**Workflow:** Worker → Test-writer → Test-runner → Reviewer

---

### ARG-040 — CAPSTONE Cycle 4 (coverage matrix C13 + C14, docs regen, sign-off, Cycle 5 carry-over)

- **Status:** ⏸ Pending
- **Backlog reference:** §17 (Test discipline), §19 (DoD), §16.10 (Docs)
- **Priority:** **CRITICAL** (capstone — финализация Cycle 4, gate to Cycle 5)
- **Complexity:** complex
- **Hours:** 6
- **Dependencies:** ARG-031..ARG-039 (все 9 предыдущих задач — capstone проверяет агрегированный output)

**Description:**  
Финальная задача Cycle 4 (mirror ARG-030 Cycle 3 структуры):

1. **Расширить coverage matrix с 12 → 14 контрактов:**
   - **C13 — `signature-mtime-stability`**: touched-but-unchanged YAML файлы НЕ должны инвалидировать `SIGNATURES` (regression gate против ARG-038 root-cause class). Implementation: для каждого из 157 tool YAMLs — `pathlib.Path(yaml).touch()` (mtime change без content change) → `python -m scripts.tools_sign verify` exit 0; same для 23 payloads + 5 prompts.
   - **C14 — `tool-yaml-version-field-presence`**: каждый из 157 tool YAMLs обязан иметь top-level `version: <semver>` поле (закрывает `ISS-cycle3-tool-yaml-version-field` из ARG-026 follow-up'ов). Backfill: добавить `version: "1.0.0"` всем tool YAMLs которые ещё не имеют (regen SIGNATURES после).
2. **Регенерировать `docs/tool-catalog.md`:**
   - Парсер coverage по категориям обновлён (browser 0% → 100%, binary 20% → 100%, recon 20% → ~40%, auth 27% → ~60%)
   - Header summary: `Mapped: ~98 (62.4%), Heartbeat: ~59 (37.6%)`
   - Новая колонка **Per-image coverage** — какой из 4 sandbox images (web/cloud/browser/full) содержит pinned versions для каждого tool_id (по `argus-kali-<profile>/Dockerfile` parsing); фактическая reality check pinned-versions matrix из ARG-026
3. **Cycle 4 sign-off report** в `ai_docs/develop/reports/2026-04-19-argus-finalization-cycle4.md`:
   - Mirror Cycle 3 sign-off структуры (Executive Summary, Per-task Summary, Headline Metrics Table, Architectural Impact, Known Gaps / Cycle 5 Candidates, Acceptance Gates Results, Sign-off block, Ссылки)
   - Headline metrics: parsers mapped 68→98, coverage matrix 12→14, ReportService 12/18→18/18, MCP webhooks/rate-limiter/OpenAPI added, supply-chain Cosign keyless prod live, CI image-build gating live
4. **CHANGELOG.md** — новая Cycle 4 секция в шапке (под `## [Unreleased]`), агрегирует все ARG-031..040 entries
5. **Cycle 5 carry-over backlog** в `ai_docs/develop/issues/ISS-cycle5-carry-over.md`:
   - Observability (OTel spans + Prometheus metrics, Backlog §15) — primed как **ARG-041**
   - Frontend MCP integration (consume generated SDK, replace mock) — **ARG-042**
   - Real cloud_iam ownership для AWS/GCP/Azure (Backlog §10) — **ARG-043**
   - EPSS percentile + KEV catalog ingest (Backlog §6) — **ARG-044**
   - Helm chart для production deployment + Alembic migrations для new tables (`reports`, `mcp_audit`) — **ARG-045**
   - Полный hexstrike purge из docs/tests (Cycle 6 capstone candidate) — **ARG-046**
   - DoD §19.4 e2e capstone (`scripts/e2e_full_scan.sh http://juice-shop:3000`) — **ARG-047 / Cycle 6**

**Acceptance criteria:**

- [ ] **C13 contract:** `tests/test_tool_catalog_coverage.py::test_signature_mtime_stability` — параметризован по 157 + 23 + 5 = 185 файлам; для каждого: `original_mtime = path.stat().st_mtime`; `path.touch()`; `verify_signatures(...)` exit 0; restore mtime; assert verification passed без false-positive drift
- [ ] **C14 contract:** `tests/test_tool_catalog_coverage.py::test_tool_yaml_has_version_field` — для каждого из 157 tool YAMLs assert `yaml.safe_load(path)["version"]` matches semver regex; **backfill** недостающих `version: "1.0.0"` в touched YAMLs (re-sign через `python -m scripts.tools_sign sign-all` + commit `SIGNATURES`)
- [ ] Coverage matrix gate: 14 × 157 + summary = **2 198+ параметризованных кейсов** (рост с 1 884 → 2 198, +314 кейсов); все зелёные
- [ ] `docs/tool-catalog.md` регенерирован через `python -m scripts.docs_tool_catalog --out ../docs/tool-catalog.md`:
  - Per-image coverage колонка добавлена (parser of `sandbox/images/argus-kali-{web,cloud,browser,full}/Dockerfile` → which tool_ids pinned in which image)
  - Header summary updated с новыми Cycle 4 числами
- [ ] `python -m scripts.docs_tool_catalog --check` — markdown синхронен (drift = 0)
- [ ] `ai_docs/develop/reports/2026-04-19-argus-finalization-cycle4.md` создан со структурой Cycle 3 sign-off (mirror'нной байт-в-байт по разделам)
- [ ] `CHANGELOG.md` — обновлён с агрегированной Cycle 4 секцией (после `## [Unreleased]` шапки) — все 10 ARG-031..040 entries сгруппированы
- [ ] `ai_docs/develop/issues/ISS-cycle5-carry-over.md` создан с **5-7 заpriming'ованными** ARG-041..ARG-04N задачами (descriptions, complexity, dependencies, source — mirror ARG-031..ARG-040 schema)
- [ ] **Final DoD checklist** (executed in capstone, all green):
  - `python -m scripts.tools_sign verify` — `verified_count=157`
  - `python -m scripts.payloads_sign verify` — `verified_count=23`
  - `python -m scripts.prompts_sign verify` — `verified_count=5`
  - `python -m scripts.docs_tool_catalog --check` — exit 0
  - `python -m pytest tests/test_tool_catalog_coverage.py -q` — all PASS (2 198+ кейсов)
  - `python -m pytest tests/integration/sandbox/parsers tests/unit/sandbox/parsers -q` — all PASS (≥ 2 100 кейсов после ARG-032)
  - `python -m pytest tests/unit/reports tests/unit/mcp tests/integration/reports tests/integration/mcp -q` — all PASS (≥ 1 100 кейсов после ARG-031/ARG-035/ARG-039)
  - `python -m pytest tests/security -q` — all PASS (≥ 1 000 кейсов: 990 ReportService + 10+ MCP secret-leak gates)
  - `python -m mypy --strict --follow-imports=silent src/sandbox src/sandbox/parsers src/reports src/mcp` — no issues
  - `python -m scripts.export_mcp_openapi --check` — exit 0 (drift 0)
  - `cd Frontend && npm run sdk:check` — exit 0
  - `cosign verify --certificate-identity-regexp ... ghcr.io/<org>/argus-kali-web:<tag>` — exit 0 (keyless verification)

**Files to create / modify:**

```
backend/tests/test_tool_catalog_coverage.py               (modify: +C13 +C14 + ratchet COVERAGE_MATRIX_CONTRACTS=14)
backend/scripts/docs_tool_catalog.py                      (modify: +per-image coverage parser)
backend/config/tools/*.yaml                               (modify: backfill version: "1.0.0" where missing — touched tool YAMLs only)
backend/config/tools/SIGNATURES                           (modify: re-sign после backfill)
docs/tool-catalog.md                                      (regenerated)
ai_docs/develop/reports/2026-04-19-argus-finalization-cycle4.md   (new — Cycle 4 sign-off)
CHANGELOG.md                                              (modify: +Cycle 4 aggregated section)
ai_docs/develop/issues/ISS-cycle5-carry-over.md           (new — 5-7 priming tasks ARG-041..)
.cursor/workspace/active/orch-2026-04-19-argus-cycle4/progress.json    (orchestrator-updated: status="completed")
.cursor/workspace/active/orch-2026-04-19-argus-cycle4/links.json       (orchestrator-updated: report=ai_docs/.../report.md)
```

**Workflow:** Worker → Test-writer → Test-runner → Documenter → Reviewer (final cycle close)

---

## 4. Dependencies graph

```
Cycle 3 (ARG-021..030) ✅ closed — все foundations готовы
  │
  ├──→ ARG-031 (Valhalla tier renderer) ────────┐
  │                                              ├──→ ARG-036 (PDF templating polish) ──┐
  │                                              │                                       │
  ├──→ ARG-032 (parsers batch 4 — 30 tools) ────┤                                       │
  │                                              │                                       │
  ├──→ ARG-034 (image CI gating + GHCR push) ───┼──→ ARG-033 (Cosign keyless prod) ────┤
  │                                              │                                       │
  ├──→ ARG-035 (MCP webhooks + rate-limiter) ───┤                                       │
  │                                              │                                       │
  ├──→ ARG-037 (stale-import cleanup batch) ────┤                                       │
  │                                              │                                       │
  ├──→ ARG-038 (apktool.yaml drift root-cause) ─┤                                       │
  │                                              │                                       │
  └──→ ARG-039 (OpenAPI MCP export + TS SDK) ───┤                                       │
                                                 ↓                                       │
                                            ARG-040 (CAPSTONE — coverage 12→14, docs, sign-off, Cycle 5 carry-over)
                                                 ↑                                       │
                                                 └───────────────────────────────────────┘
```

**Critical path (longest dependency chain):**

```
ARG-031 (8h) ──→ ARG-036 (7h) ──→ ARG-040 (6h)  =  21 hours wall-time
```

(Альтернативные chain'ы: ARG-034 (5h) → ARG-033 (5h) → ARG-040 (6h) = 16h; ARG-032 (12h) → ARG-040 (6h) = 18h. Все короче.)

**Parallel-safe groups (могут стартовать одновременно с t=0):**

- **Group A** (no deps, start immediately): ARG-031, ARG-032 (split в 3 параллельных batch'а 4a/4b/4c), ARG-034, ARG-035, ARG-037, ARG-038, ARG-039 — **7 tasks параллельно**
- **Group B** (start after Group A subset finishes): ARG-033 (после ARG-034 push'нет образы в GHCR), ARG-036 (после ARG-031 финиширует Valhalla template для branded business design)
- **Group C** (start after all 9): ARG-040 capstone

---

## 5. Status table (updated by orchestrator)

| ID | Title | Priority | Hours | Status | Notes |
|---|---|---|---|---|---|
| ARG-031 | Valhalla tier renderer (executive + business-impact) | HIGH | 8 | ⏸ Pending | Closes ReportService 12/18 → 18/18 (DoD §19.4) |
| ARG-032 | Per-tool parsers batch 4 (browser/binary/recon/auth, +30) | HIGH | 12 | ⏸ Pending | mapped 68→98 (>60% catalog coverage, DoD §19.6) |
| ARG-033 | Cosign keyless signing (GH OIDC + Sigstore Fulcio + Rekor) | HIGH | 5 | ⏸ Pending | Production supply-chain (DoD §19) — depends on ARG-034 |
| ARG-034 | Image-build CI gating (GHCR push + OCI SBOM + Trivy blocking) | CRITICAL | 5 | ⏸ Pending | Closes DoD §19.1 + §19.4 supply-chain partial |
| ARG-035 | MCP webhooks (Slack/Linear/Jira) + per-LLM rate-limiter | MEDIUM | 8 | ⏸ Pending | MCP production readiness (Backlog §13 + §15) |
| ARG-036 | ReportService PDF templating polish (branded + LaTeX fallback + determinism) | HIGH | 7 | ⏸ Pending | Branded executive PDFs — depends on ARG-031 |
| ARG-037 | Stale-import cleanup batch (4 follow-up issues) | MEDIUM | 4 | ⏸ Pending | Closes ISS-fix-004/006/payload-drift/pytest-prefix |
| ARG-038 | apktool.yaml drift root-cause + read-only catalog fixture | LOW | 3 | ⏸ Pending | Closes Cycle 3 mystery (4 worker reports surfaced) |
| ARG-039 | OpenAPI 3.1 export of MCP + TS SDK + docstring CI gate | MEDIUM | 4 | ⏸ Pending | MCP client SDK generation, Backlog §16.10 |
| ARG-040 | CAPSTONE (coverage 12→14, docs regen, sign-off, Cycle 5 carry-over) | CRITICAL | 6 | ⏸ Pending | Cycle 4 close + Cycle 5 priming |

**Total estimated hours:** **62 hours** (sum of all task estimates).  
**Critical path wall-time:** **21 hours** (ARG-031 → ARG-036 → ARG-040; assuming ample parallel worker capacity).

---

## 6. Architecture invariants — что НЕ ломаем (carry-over из Cycle 1+2+3)

Каждая Cycle 4 задача **обязана** сохранить guardrails из Cycle 1+2+3:

### Sandbox runtime (Cycle 1+2)

- Non-root pod (`runAsNonRoot=true`, UID/GID 65532), read-only root filesystem, dropped capabilities, seccomp `RuntimeDefault`, `automountServiceAccountToken=false`, `restartPolicy=Never`, `backoffLimit=0`
- ARG-032 новые browser-парсеры **обязаны** работать в `argus-kali-browser` image без эскалации (Chromium setuid sandbox удалён в ARG-026; Playwright должен работать через `--no-sandbox` flag — задокументировать в browser parser fixtures)

### Templating (Cycle 1)

- Allowlisted placeholders only (`src.pipeline.contracts._placeholders.ALLOWED_PLACEHOLDERS`)
- ARG-032 парсеры **никогда** не модифицируют argv — только парсят output
- ARG-035 MCP webhook payloads **никогда** не embed'ят raw argv — только sanitized FindingDTO через `replay_command_sanitizer`

### Signing (Cycle 1+2+3)

- 157 tool YAMLs остаются Ed25519-signed (тот же dev key Cycle 1: `b618704b19383b67`); 23 payloads (key `8b409d74bef23aaf`); 5 prompts (key `681a1d103f2d8759`); MCP manifest (key `1d9876d6be68a494`)
- **ARG-040 backfill** `version: "1.0.0"` в tool YAMLs → MUST re-sign + commit обновлённый `SIGNATURES`; не trogаем dev key
- **ARG-033 Cosign keyless** — отдельный механизм для container images; не пересекается с YAML signing

### NetworkPolicy (Cycle 3)

- Ingress **always** denied (для всех 11 templates, включая cloud-aws/gcp/azure)
- DNS pinned (Cycle 3 wired override но defaults Cloudflare/Quad9 остаются)
- Private ranges (10/8, 172.16/12, 192.168/16, 169.254.169.254/32) blocked
- ARG-035 webhook outbound (Slack/Linear/Jira) — **НЕ** разрешено в sandbox NetworkPolicy; webhooks работают только из application backend (через `argus-backend` deployment), не из sandbox-pod'ов

### Approval & dual-control (Cycle 1)

- `risk_level in {high, destructive}` → `requires_approval=true` (Coverage matrix Contract 10 enforces; не нарушаем)
- ARG-035 MCP `tool.run.trigger` для destructive — обязан вызвать `ApprovalService.request(...)` через audit log; webhook notifies на `approval.pending`

### Audit chain (Cycle 1)

- ApprovalService + AuditChain (Cycle 1 ARG-006) остаются source of truth
- ARG-035 webhook deliveries логируются в AuditChain с `actor=mcp_notification_dispatcher`, `args_hash=hash(event_payload)` — НЕ raw payload
- ARG-039 OpenAPI export — read-only operation, не пишет в AuditChain

### Findings & evidence (Cycle 1+3)

- FindingDTO имеет `root_cause_hash` для дедупликации
- ARG-032 каждый new parser производит детерминированные FindingDTO (C11 enforces — extends на новые ~30 tools автоматически)
- Redaction (`src.evidence.redaction`) применяется до persist в S3 (C12 enforces — extends на новые ~30 tools автоматически)
- ARG-035 webhook payload sanitisation — **mandatory** через `replay_command_sanitizer` из ARG-025 (новый security gate `test_mcp_notification_no_secret_leak`)
- ARG-031 Valhalla — **mandatory** прохождение sanitizer pipeline (security gate parametrized на VALHALLA tier; 990 кейсов = 55 patterns × 6 formats × 3 tiers)

### Test infrastructure (Cycle 3)

- pytest markers (`requires_postgres/redis/oast/docker/weasyprint_pdf`) discipline сохранена
- ARG-036 LaTeX backend → новый marker `requires_latex` (skipped если `latexmk` not on PATH)
- ARG-038 catalog read-only fixture → новый marker `mutates_catalog` (opt-in для legitimate test mutation)
- Coverage matrix ratchet: `MAPPED_PARSER_COUNT` 68 → ≥ 98; `HEARTBEAT_PARSER_COUNT` 89 → ≤ 59; `COVERAGE_MATRIX_CONTRACTS` 12 → 14 — все три ratchet'а enforced в `tests/test_tool_catalog_coverage.py`

### MCP server (Cycle 3)

- 15 tools / 4 resources / 3 prompts surface — стабильно (ARG-035 НЕ добавляет новые tools, только notification side-channel; ARG-039 НЕ добавляет, только экспортирует существующее)
- Tenant isolation enforced (cross-tenant tests из ARG-023 остаются зелёными)
- mypy --strict clean (39 source files; ARG-035 + ARG-039 добавят ~15 новых modules — все strict-clean)
- signed manifest `backend/config/mcp/server.yaml` re-signed после ARG-035 (notifications + rate_limiter sections добавлены)

### ReportService (Cycle 3)

- `ReportService.generate(tenant_id, scan_id, tier, format) → ReportBundle` — единственный public API; не ломаем
- `ReportBundle.sha256` обязательно
- Byte-stable текстовые форматы (HTML / JSON / CSV / SARIF / JUnit); PDF — structural snapshot (Cycle 3 known limitation; Cycle 4 ARG-036 добавляет fixed creation_date — но всё равно structural test, не byte-equal)

---

## 7. Risks + mitigations

### Risk 1: Cosign keyless setup blocked by Sigstore upstream availability or org GitHub OIDC misconfiguration (ARG-033)

**Likelihood:** Medium (Sigstore Fulcio uptime ~99.5%; GH OIDC requires `permissions.id-token: write` at workflow level + repo-level approval for OIDC providers).

**Impact:** ARG-033 stuck в dry-run mode; supply-chain DoD не закрывается полностью.

**Mitigation:** ARG-033 включает explicit **rollback plan** в `docs/sandbox-images.md` — fallback на keyed mode (`cosign sign --key <pem> --tlog-upload=false`) с pinned cosign v2 binary. Verify-job в CI проверяет **либо** keyless **либо** keyed подпись (regex по certificate identity OR fingerprint); даёт graceful degradation. Если **Cycle 4 day 5** Sigstore downtime > 4 hours → defer ARG-033 keyless to Cycle 5, оставить keyed mode как production interim. ARG-040 capstone проверяет: какой бы режим ни был — `cosign verify` должен exit 0.

### Risk 2: ARG-032 batch 4 (30 parsers) underestimated — actual hours > 12 due to category-specific edge cases (browser HAR, binary disasm)

**Likelihood:** High (browser parsers особенно сложны: Playwright/Puppeteer outputs heterogeneous, retire-js JSON shape varies между versions; binary disasm — radare2/ghidra outputs huge, требуют structured truncation для evidence storage).

**Impact:** ARG-032 не закрывает 30 → закрывает 18-22 → mapped → ~88, не ≥98 → DoD §19.6 catalog coverage > 60% не достигается.

**Mitigation:** Worker'у явно разделить ARG-032 на 3 batch'а (4a browser, 4b binary+recon, 4c auth) с **independent acceptance criteria per batch** (если batch 4a достигает 6/6 browser coverage → засчитывается даже если 4c отстаёт). Каждый batch — отдельный worker (3 параллельно), не один последовательно. При 50% batch completion (15+/30) — **decision point** в ARG-040 capstone: либо принять промежуточный результат (mapped → 83, heartbeat → 74) с ratchet update, либо defer 15 оставшихся в Cycle 5 carry-over (документировать как «ARG-032 partial — Cycle 5 ARG-041»). **Hard stop: mapped >= 83** (минимум +15 из плана) — иначе блокируем capstone.

### Risk 3: Observability (OTel + Prometheus) deferred to Cycle 5 — backlog §15 gap remains open through Cycle 4

**Likelihood:** Certain (deliberate trade-off — task budget cap = 10).

**Impact:** Production deployments после Cycle 4 не имеют structured metrics для SLI/SLO; пользователи pipeline не видят `argus_tool_runs_total{tool,category,status}`, `argus_findings_total`, `argus_oast_callbacks_total`, `argus_llm_tokens_total{provider}`, `argus_scan_duration_seconds`. `/metrics` endpoint отсутствует.

**Mitigation:** Документировать как **deferred to Cycle 5 (ARG-041)** в Cycle 5 carry-over backlog (генерируется ARG-040). Промежуточно — structured JSON logs (Cycle 1+2 уже есть) дают наблюдаемость через log aggregator (ELK/Loki). MCP audit log + AuditChain дают per-action traceability. Risk acceptance: Cycle 4 → Cycle 5 production deployment running с logs-only observability ~6 weeks. Если production incident occurs в этом окне → debug через logs + correlation_id (медленнее, но возможно).

### Risk 4: ARG-038 apktool drift root-cause не локализуется через bisection (test passes consistently when run в isolation)

**Likelihood:** Medium (Cycle 3 worker reports описывают drift как «periodic», не «every run» — может быть order-dependent test interaction, который bisection не ловит).

**Impact:** ARG-038 закрывается paliативно — read-only fixture chmod 0444 как safety net, root-cause остаётся unknown. C13 contract (signature-mtime-stability) всё равно зелёный, но real bug может surface в Cycle 5 при добавлении новых tests.

**Mitigation:** Если bisection не дала результата за 2 hours wall-time — переключиться на **defensive mode**:
1. Применить fixture chmod 0444 как enforcement (любой illegitimate write → `PermissionError` с точным test ID в stack trace — следующий регресс самоидентифицируется)
2. Документировать в `ISS-apktool-drift-rootcause.md` как «root-cause unknown, defensive mitigation in place»
3. Закрыть ARG-038 как «mitigated, root-cause investigation deferred» — не блокирует capstone

### Risk 5: ARG-036 PDF determinism блокирован WeasyPrint version-specific font subsetting (PDF bytes меняются между WeasyPrint patch releases даже при fixed inputs)

**Likelihood:** High (Cycle 3 ARG-024/025 sign-off explicitly документировал «WeasyPrint version-dependent» как known limitation).

**Impact:** ARG-036 byte-stable snapshot test для PDF — невозможен; structural snapshot (page count + section headers + embedded fonts list) — единственный realistic gate.

**Mitigation:** Принять как design-by-spec — ARG-036 acceptance criteria **уже** говорят «structural snapshot через `pypdf`», не byte-equal. Pin WeasyPrint version в `pyproject.toml` (`weasyprint==60.2`); pin font files bundled (Inter / DejaVu specific TTF blob hash documented). Если Cycle 5 пожалуется на PDF byte-drift — recipe: bump WeasyPrint version pin → regenerate visual-regression PNG snapshots → manual designer review.

**Deferred to Cycle 5 (per task-budget cap):**

- **ARG-041** Observability — OTel spans + Prometheus metrics + `/metrics`, `/health`, `/ready`, `/providers/health`, `/queues/health` endpoints (Backlog §15)
- **ARG-042** Frontend MCP integration — consume generated TS SDK из ARG-039, replace mock'и в `Frontend/src/services/mcp/` (Backlog §14)
- **ARG-043** Real cloud_iam ownership для AWS/GCP/Azure (Backlog §10) — `OwnershipProof` для cloud accounts через STS / IAM tokens
- **ARG-044** EPSS percentile + KEV catalog ingest (Backlog §6) — full CISA SSVC v2.1 prioritizer integration
- **ARG-045** Helm chart для production deployment + Alembic migrations для new tables (`reports`, `mcp_audit`, `mcp_notification_log`)
- **ARG-046** Полный hexstrike purge из docs/tests (legacy carryover; Cycle 6 capstone candidate)
- **ARG-047** DoD §19.4 e2e capstone — `scripts/e2e_full_scan.sh http://juice-shop:3000` создаёт все 18 отчётов с OAST evidence (Cycle 6)

---

## 8. Verification command (DoD checklist для Cycle 4)

После завершения всех 10 задач оператор может запустить:

```powershell
cd backend

# Catalog signing invariants
python -m scripts.tools_sign verify --tools-dir config/tools --signatures config/tools/SIGNATURES --keys-dir config/tools/_keys
python -m scripts.payloads_sign verify --payloads-dir config/payloads --signatures config/payloads/SIGNATURES --keys-dir config/payloads/_keys
python -m scripts.prompts_sign verify --prompts-dir config/prompts --signatures config/prompts/SIGNATURES --keys-dir config/prompts/_keys

# Docs drift
python -m scripts.docs_tool_catalog --check
python -m scripts.export_mcp_openapi --check

# Coverage matrix (14 contracts × 157 + summary = 2 198+ cases)
python -m pytest tests/test_tool_catalog_coverage.py -q --tb=short

# Parser suites (≥ 2 100 cases after ARG-032 +30)
python -m pytest tests/integration/sandbox/parsers tests/unit/sandbox/parsers -q --tb=short

# Reports + MCP suites (≥ 1 100 cases after ARG-031 + ARG-035 + ARG-039)
python -m pytest tests/unit/reports tests/unit/mcp tests/integration/reports tests/integration/mcp -q --tb=short

# Security suite (≥ 1 000 cases: 990 reports × 3 tiers + 10+ MCP webhook secret-leak gates)
python -m pytest tests/security -q --tb=short

# Lint + type-check + sec scan
python -m mypy --strict --follow-imports=silent src/sandbox src/sandbox/parsers src/reports src/mcp
python -m ruff check src tests
python -m bandit -q -r src

# Frontend SDK drift
cd ../Frontend
npm run sdk:check

# Image signing verification (after ARG-033 keyless)
cd ..
cosign verify --certificate-identity-regexp '^https://github\.com/[^/]+/[^/]+/\.github/workflows/sandbox-images\.yml@refs/heads/main$' --certificate-oidc-issuer https://token.actions.githubusercontent.com ghcr.io/<org>/argus-kali-web:<latest-tag>
cosign verify-attestation --type cyclonedx --certificate-identity-regexp ... ghcr.io/<org>/argus-kali-web:<latest-tag>
```

Все 13+ команд должны завершиться с **exit code 0**.

---

## 9. Sign-off criteria (Cycle 4 DoD)

Cycle 4 считается закрытым только если:

- [ ] Все 10 задач (ARG-031..ARG-040) ✅ Completed
- [ ] Sandbox tests баланс — нет регрессии (Cycle 3 baseline 9 278 dev-default + Cycle 4 additions ≥ 600)
- [ ] Per-tool parsers зарегистрированы: ≥ 30 additional (68 → ≥ 98 mapped); heartbeat ≤ 59
- [ ] ReportService — 18 / 18 матрицы (Midgard / Asgard / Valhalla × 6 форматов) — все ячейки emit byte-stable bytes (PDF — structural)
- [ ] MCP server — 15 tools / 4 resources / 3 prompts surface стабильно (не растёт, не сжимается); + webhooks (Slack/Linear/Jira) behind feature-flag; + per-LLM rate-limiter live
- [ ] OpenAPI 3.1 export — `docs/mcp-server-openapi.yaml` published; TS SDK generated в `Frontend/src/sdk/argus-mcp/`
- [ ] Supply-chain — все 4 sandbox images push'ятся в `ghcr.io`, подписаны Cosign keyless через GH OIDC + Rekor transparency log; SBOM attached как OCI artefact; Trivy gate blocking; branch protection rules enforce required checks для merge в main
- [ ] Coverage matrix — 14 contracts × 157 tools = **2 198 параметризованных кейсов**, все зелёные (включая C13 signature-mtime-stability + C14 tool-yaml-version-field-presence)
- [ ] Heartbeat fallback инвариант ARG-020 сохранён — для всех ≤ 59 unmapped tool_id ARGUS-HEARTBEAT path работает
- [ ] `pytest -q` (dev-default) ≥ 9 800 cases PASS (no docker)
- [ ] `mypy --strict` clean для всех новых модулей (`src/reports/valhalla_tier_renderer.py`, `src/reports/pdf_backend.py`, `src/mcp/services/notifications/*`, `src/mcp/runtime/rate_limiter.py`, `src/mcp/openapi_emitter.py`, всех ARG-032 parsers)
- [ ] `ruff check` clean для touched files; `bandit -q` clean для new modules
- [ ] `docs/tool-catalog.md` — синхронен (Mapped: ≥ 98, Heartbeat: ≤ 59 в header)
- [ ] `ai_docs/develop/reports/2026-04-19-argus-finalization-cycle4.md` создан (mirror Cycle 3 sign-off структуры)
- [ ] `CHANGELOG.md` updated с Cycle 4 разделом
- [ ] `ai_docs/develop/issues/ISS-cycle5-carry-over.md` создан с 5-7 ARG-041..ARG-04N priming tasks
- [ ] Catalog signing инвариант сохранён: 157 tools / 23 payloads / 5 prompts / 1 MCP manifest — все Ed25519-verifiable; 4 sandbox images — все Cosign keyless verified

**Cycle 4 → Cycle 5 handoff:** ARG-040 capstone генерирует `ai_docs/develop/issues/ISS-cycle5-carry-over.md` с приоритизированным списком: Observability (OTel + Prometheus), Frontend MCP SDK consumption, Real cloud_iam ownership, EPSS/KEV ingest, Helm chart + Alembic migrations, hexstrike full purge, e2e capstone scan.

---

## 10. Ссылки

- **Backlog (источник истины):** [`Backlog/dev1_.md`](../../../Backlog/dev1_.md)
- **Cycle 3 plan (predecessor):** [`ai_docs/develop/plans/2026-04-19-argus-finalization-cycle3.md`](2026-04-19-argus-finalization-cycle3.md)
- **Cycle 3 report (predecessor):** [`ai_docs/develop/reports/2026-04-19-argus-finalization-cycle3.md`](../reports/2026-04-19-argus-finalization-cycle3.md)
- **Cycle 4 carry-over backlog:** [`ai_docs/develop/issues/ISS-cycle4-carry-over.md`](../issues/ISS-cycle4-carry-over.md)
- **CHANGELOG:** [`CHANGELOG.md`](../../../CHANGELOG.md)
- **Tool catalog (auto-generated):** [`docs/tool-catalog.md`](../../../docs/tool-catalog.md)
- **Coverage gate:** [`backend/tests/test_tool_catalog_coverage.py`](../../../backend/tests/test_tool_catalog_coverage.py)
- **Tool-catalog generator:** [`backend/scripts/docs_tool_catalog.py`](../../../backend/scripts/docs_tool_catalog.py)
- **MCP server doc:** [`docs/mcp-server.md`](../../../docs/mcp-server.md)
- **Report service doc:** [`docs/report-service.md`](../../../docs/report-service.md)
- **Sandbox images doc:** [`docs/sandbox-images.md`](../../../docs/sandbox-images.md)
- **Network policies doc:** [`docs/network-policies.md`](../../../docs/network-policies.md)
- **Testing strategy doc:** [`docs/testing-strategy.md`](../../../docs/testing-strategy.md)
- **CI workflow:** [`.github/workflows/ci.yml`](../../../.github/workflows/ci.yml)
- **Sandbox-images workflow:** [`.github/workflows/sandbox-images.yml`](../../../.github/workflows/sandbox-images.yml)
- **Workspace metadata:** `.cursor/workspace/active/orch-2026-04-19-argus-cycle4/`

---

**Status:** 🟢 Active — все 10 задач (ARG-031..ARG-040) seeded; ready to execute через `/orchestrate execute orch-2026-04-19-argus-cycle4`.
