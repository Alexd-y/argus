# Cursor prompt: ARGUS Authorized WAF Validation

Ниже находится самостоятельный промпт для Cursor Agent. Выполни задачу полностью в текущем репозитории ARGUS, но строго соблюдай ограничения безопасности и границы авторизации.

---

## Роль и ожидаемый результат

Ты — senior Python/FastAPI security engineer и maintainer ARGUS. Реализуй в ARGUS производственный модуль **Authorized WAF Validation** для защитной, доказательной оценки:

- согласованности HTTP-нормализации между тестовым WAF и инструментированным backend;
- false positive / false negative поведения на **инертных canary-маркерах**;
- покрытия разрешённых content types и правил нормализации;
- корреляции результатов теста с WAF-событиями;
- формирования воспроизводимых, минимизированных и безопасных findings;
- рекомендаций по hardening, normalizer policy и WAF rule tuning.

Модуль должен использовать существующую архитектуру ARGUS: FastAPI, Celery, PostgreSQL/RLS, MinIO, sandbox, подписанные каталоги, `ScopeEngine`, ownership proof, `PolicyEngine`, `ApprovalService`, `PreflightChecker`, audit log, evidence gates и Valhalla reporting.

Итог — не «инструмент обхода», а fail-closed validation harness, который показывает расхождения парсинга на безопасных данных и помогает закрывать их.

## Непереговорные ограничения безопасности

Эти требования — часть функционального контракта. Их нельзя ослаблять, прятать за feature flag или обходить в тестах.

1. Не реализуй и не импортируй:
   - поиск origin IP, direct-to-origin probing или проверку обхода CDN/WAF по IP;
   - эксплуатационные SQLi/XSS/RCE/LFI/SSTI/SSRF/XXE payloads;
   - credential attacks, auth bypass, token theft, reverse shells, persistence или exfiltration;
   - stealth, proxy/IP rotation, CAPTCHA/challenge evasion или подмену доверенного proxy identity;
   - HTTP request smuggling/desync, неоднозначный `Content-Length`/`Transfer-Encoding`, raw CRLF injection, NUL-byte framing, malformed chunking или пакетную фрагментацию;
   - oversize/padding обход inspection limits;
   - произвольный raw HTTP editor или endpoint, принимающий готовые байты запроса от клиента;
   - автоматическое изменение боевых WAF rules, firewall rules или allowlists.
2. Не клонируй, не vendori и не запускай как runtime dependency offensive-репозитории и коллекции payloads, включая перечисленные пользователем `waf-bypass`, `evilwaf`, `waftester`, `nowafpls`, `PayloadsAllTheThings` и `sqlmap`. Их можно упомянуть только в threat-model/ADR как исключённые из scope источники риска. Не копируй из них payloads или bypass-рецепты.
3. Все сетевые тесты используют только инертный маркер вида `ARGUS_WAF_CANARY_<128-bit-random>` и безвредные структурированные данные. Запрещены attack metacharacters и семантика исполнения.
4. В версии 1 сетевой differential-runner работает только с зарегистрированным ARGUS WAF lab profile. Произвольный URL из API/CLI не принимается.
5. Любое сетевое действие до материализации кейса проходит существующий `PreflightChecker`: scope → ownership → policy → approval. Перед фактической отправкой worker выполняет повторный preflight для защиты от stale/replayed job.
6. Redirects отключены. DNS/IP назначения проверяются и pin-ятся на время run; redirect или повторное разрешение за пределы scope немедленно останавливает run.
7. TLS verification включён. Нельзя добавлять пользовательский proxy, отключение TLS, произвольные headers, cookies или credentials.
8. Все лимиты fail-closed. Не должно существовать `unsafe`, `unlimited`, `disable_guardrails`, `skip_preflight`, `allow_any_target` или эквивалентного режима.
9. Raw request/response bodies по умолчанию не сохраняются. Сохраняются структурированные метаданные, hashes и redacted previews. Любое опциональное сохранение лабораторного body должно быть encrypted-at-rest, tenant-scoped, RBAC-gated и с коротким retention.
10. Не считать parser disagreement доказанным exploit. Severity по умолчанию `info` или `low`; повышение допускается только по существующим evidence gates и с отдельным доказательством реального impact, которое этот модуль не генерирует.

## Сначала изучи репозиторий

Перед изменениями прочитай и соблюдай:

- `README.md` и `CLAUDE.md`;
- `backend/src/policy/preflight.py`;
- `backend/src/policy/scope.py`;
- `backend/src/policy/ownership.py`;
- `backend/src/policy/policy_engine.py`;
- `backend/src/payloads/registry.py` и `backend/src/payloads/builder.py` как образец подписанного fail-closed каталога;
- `backend/src/sandbox/adapter_base.py`, `backend/src/sandbox/runner.py`, `backend/src/sandbox/signing.py`;
- `backend/src/recon/vulnerability_analysis/active_scan/`;
- `backend/src/reports/evidence_gates.py`, `finding_quality_filter.py`, `valhalla_report_context.py` и соседние report contracts;
- `infra/docker-compose.vuln-targets.yml` и существующие e2e-паттерны;
- релевантные API/router/service и admin-frontend patterns.

Сначала выполни `git status --short --branch`. Рабочее дерево уже может быть грязным. Не перезаписывай и не форматируй несвязанные пользовательские изменения. Не делай reset/checkout, commit, push или PR.

## Архитектурный принцип

Реализуй три строго разделённых режима:

1. `offline_normalization`
   - сеть не используется;
   - seed превращается в канонический IR;
   - выполняются только безопасные, RFC-valid и семантически эквивалентные преобразования;
   - сравниваются parse tree/hash до и после normalizer chain.
2. `lab_differential`
   - запрос проходит через фиксированный lab WAF endpoint и инструментированный echo/parser backend;
   - backend возвращает только typed parse manifest и canary-presence, но никогда не исполняет значения;
   - runner сопоставляет baseline, WAF action и backend parse manifest.
3. `waf_log_analysis`
   - сетевой fuzzing отсутствует;
   - нормализуются уже полученные WAF events;
   - строятся метрики allow/block/challenge/log/unknown, rule coverage и false-positive candidates.

Поток данных:

```text
Signed seed catalog
  -> safe case planner
  -> preflight + lab-profile gate
  -> deterministic mutator chain
  -> request budget/rate limiter/kill switch
  -> lab WAF
  -> instrumented parser backend
  -> WAF/backend observations
  -> differential oracle
  -> minimizer
  -> evidence artifact + metrics + report
```

## Новые backend-модули

Создай пакет `backend/src/recon/waf_validation/` со следующей ответственностью. Если существующий модуль уже покрывает обязанность, переиспользуй его вместо дублирования.

- `models.py`
  - Pydantic v2 contracts с `extra="forbid"` и строгими bounds;
  - enums для mode, content type, mutation family, observation state и finding state;
  - модели `WafValidationProfile`, `WafSeed`, `WafCase`, `WafObservation`, `BackendParseObservation`, `DifferentialFinding`, `WafRunSummary`;
  - UUID/string conventions должны совпадать с репозиторием.
- `catalog.py`
  - загрузка signed YAML seed/mutation profiles по образцу `PayloadRegistry`;
  - Ed25519 verification и fail-closed поведение при missing/invalid signature, duplicate id, schema drift или неизвестном operator;
  - production catalog read-only.
- `canary.py`
  - CSPRNG marker;
  - allowlist допустимых символов;
  - запрет SQL/shell/HTML control syntax, URL credentials, CR/LF/NUL и control bytes;
  - стабильный hash для корреляции без логирования полного значения.
- `ir.py`
  - typed intermediate representation request method/path/query/headers/body tree;
  - никаких произвольных wire bytes;
  - canonical JSON serialization и SHA-256 manifest hash.
- `normalizers.py`
  - чистые ordered transformations;
  - каждая transformation возвращает новый immutable object и provenance;
  - reject-on-ambiguity вместо угадывания.
- `mutators.py`
  - только разрешённые safe operators из signed catalog;
  - deterministic seed/correlation key;
  - без attack payload mutations.
- `planner.py`
  - baseline первым;
  - bounded cartesian expansion;
  - dedup по canonical hash;
  - hard request budget до enqueue;
  - dry-run возвращает manifest, cost estimate и причины reject без сети.
- `runner.py`
  - единый shared `httpx.AsyncClient` на run;
  - `follow_redirects=False`, `verify=True`, строгие connect/read/write/pool timeouts;
  - bounded concurrency, token bucket, cancellation и global/tenant kill switch;
  - target берётся только из resolved lab profile, не из case/user input;
  - безопасная обработка errors без утечки URL credentials, cookies или тела.
- `oracles.py`
  - baseline-aware classification;
  - не выводить WAF verdict только из HTTP status;
  - приоритет: signed lab correlation event → normalized WAF event → explicit lab header → `uncertain`;
  - backend parsed определяется typed manifest, а не поиском маркера в произвольном HTML;
  - состояния: `blocked`, `allowed_not_parsed`, `parsed_canary`, `parse_error`, `challenge`, `uncertain`, `runner_error`.
- `minimizer.py`
  - удаляет по одному безопасному operator и повторяет только в пределах оставшегося run budget;
  - deterministic, cancellable, bounded;
  - не генерирует новые типы мутаций.
- `artifacts.py`
  - canonical JSON evidence bundle;
  - SHA-256 hashes, provenance, timestamps, profile/catalog versions;
  - redaction до MinIO;
  - совместимость с существующей chain-of-custody/evidence инфраструктурой.
- `service.py`
  - orchestration/use-case слой;
  - API router не содержит бизнес-логики;
  - tenant isolation, idempotency и run state transitions.
- `metrics.py`
  - Prometheus counters/histograms с bounded labels;
  - никаких target URLs, canaries, raw rule messages или tenant secrets в labels.
- `waf_events.py`
  - vendor-neutral ingestion schema и normalizer;
  - v1 поддерживает JSON/JSONL file/object ingestion и deterministic mock stream;
  - cloud-specific live credentials/connectors не добавлять в этот change.

## Безопасный каталог seed и mutation profiles

Создай `backend/config/waf_validation/`:

```text
backend/config/waf_validation/
  seeds/
  mutation_profiles/
  lab_profiles/
  _keys/
  SIGNATURES
  catalog_index.json
```

Используй существующий signing abstraction и отдельный скрипт `backend/scripts/waf_validation_sign.py`, повторяющий интерфейс уже существующих signing scripts. Не коммить private key.

Разрешённые mutation families для v1:

- регистр имён обычных headers, когда RFC semantics не меняется;
- допустимый optional whitespace в header values через IR, без raw CR/LF;
- порядок и quoting стандартных параметров `Content-Type`;
- JSON insignificant whitespace и порядок ключей;
- дополнительная заранее описанная wrapper-структура, которую lab backend явно умеет распаковать;
- порядок полей `application/x-www-form-urlencoded`;
- строго валидные quoted/unquoted multipart boundary forms без control bytes, parameter continuations и конфликтующих boundary;
- порядок безопасных multipart fields;
- XML namespace prefix equivalence и attribute ordering при полностью отключённых DTD/entities/external resources;
- canonical path operations только на лабораторных benign segments.

Запрещённые mutation families должны быть отклонены schema validation:

- duplicate/conflicting `Content-Length` или `Transfer-Encoding`;
- malformed chunking, alternate line endings, obs-fold, CR/LF/NUL/control bytes;
- conflicting duplicate headers;
- duplicate JSON keys;
- nested/double decoding, path traversal tokens или ambiguous percent encodings;
- oversized body/padding;
- spoofed client-IP/trusted-proxy headers;
- attack strings или executable content.

Начальные seeds должны покрывать только:

- `application/json`;
- `application/x-www-form-urlencoded`;
- `multipart/form-data`;
- `application/xml` с `defusedxml` и запретом DTD/entities;
- один `GET` query canary и по одному безопасному `POST` seed на body content type.

## Lab environment

Добавь изолированный профиль `infra/docker-compose.waf-lab.yml` без публикации backend parser наружу и без внешнего egress из lab network.

Минимальный состав:

- deterministic mock WAF для обязательных unit/integration tests;
- опциональный ModSecurity + OWASP CRS lab service, только если образ можно закрепить digest, лицензия совместима и SBOM/renovate policy соблюдены;
- `argus-waf-echo` на FastAPI, который:
  - имеет фиксированные endpoints для четырёх content types;
  - проверяет correlation token;
  - возвращает allowlisted parse manifest: endpoint id, parser id/version, field paths, scalar type, canary hash/present, parse status;
  - не отражает полный body;
  - не обращается к файлам, shell, database, metadata endpoints или внешней сети;
  - ограничивает body, headers, fields, nesting и processing time.

Если ModSecurity image нельзя безопасно закрепить и воспроизводимо проверить, оставь его documented opt-in, а CI строй на deterministic mock WAF.

## Сетевые и resource guardrails

Установи консервативные defaults и hard maxima:

- default 2 requests/sec, hard max 5 requests/sec;
- default concurrency 1, hard max 2;
- default run budget 100 cases, hard max 500;
- body default max 16 KiB, hard max 64 KiB;
- response preview max 4 KiB после redaction;
- per-request total timeout 10 seconds;
- run timeout 10 minutes;
- redirects: 0;
- retries: максимум 1 только для idempotent transport errors и с тем же case id;
- no cookies, no auth headers, no proxy environment inheritance;
- user-agent фиксированный: `ARGUS-Authorized-WAF-Validation/1.0`;
- обязательные correlation/run/case ids без секретов.

Все maxima должны проверяться и на API boundary, и в planner, и в worker. Tenant policy может только ужесточать их, но не повышать выше hard max.

## Scope, ownership, policy и approval

Не создавай альтернативный safety engine.

- Используй `TargetSpec`, `ScopeEngine`, `OwnershipProofStore`, `PolicyContext`, `PolicyEngine`, `ApprovalService`, `PreflightChecker`.
- Заведи отдельный deterministic action/tool id `waf_validation_lab` и risk `LOW` для offline/log modes, `MEDIUM` для сетевого lab differential mode.
- Даже lab mode должен быть связан с tenant, scan/engagement и audit trail.
- Target URL строится сервером из signed `lab_profile`; клиент передаёт только profile id.
- Проверяй resolved address на каждом соединении; запрещай userinfo, fragments, non-http(s), wildcard host и нестандартные ports вне profile.
- Любой out-of-scope redirect/DNS change/correlation mismatch вызывает cancellation remaining cases и audit deny event.
- Никакой успешный результат preflight нельзя кэшировать между runs без проверки срока ownership proof и policy version.

## API и Celery

Добавь тонкий tenant-scoped router в стиле существующего API:

- `POST /api/v1/waf-validation/runs/dry-run`;
- `POST /api/v1/waf-validation/runs`;
- `GET /api/v1/waf-validation/runs/{run_id}`;
- `GET /api/v1/waf-validation/runs/{run_id}/findings`;
- `POST /api/v1/waf-validation/runs/{run_id}/cancel`;
- `POST /api/v1/waf-validation/events/import` для bounded JSON/JSONL ingestion;
- `GET /api/v1/waf-validation/runs/{run_id}/export` для redacted JSON evidence.

Требования:

- существующая auth dependency, tenant isolation и ABAC/RBAC;
- Pydantic request/response schemas, `extra="forbid"`;
- idempotency key для create/import;
- async `202 Accepted` для run;
- закрытая taxonomy ошибок без stack traces;
- audit create/start/case-result/cancel/complete/deny/export;
- Celery queue `argus.waf_validation`, worker concurrency 1;
- run state machine: `draft -> preflight -> queued -> running -> minimizing -> completed|cancelled|failed|denied`;
- невозможны обратные или пропущенные переходы;
- cancellation проверяется между каждым case и до minimization retry.

## Persistence и tenant isolation

Добавь SQLAlchemy models и Alembic migration в существующем стиле:

- `waf_validation_runs`;
- `waf_validation_cases`;
- `waf_validation_observations`;
- `waf_validation_findings`;
- `waf_event_imports`.

Обязательно:

- `String(36)` UUID convention;
- `tenant_id` на каждой tenant-scoped таблице;
- RLS enable + tenant policies;
- immutable evidence hash/provenance fields;
- timestamps в UTC;
- unique constraints для idempotency и deterministic case hash;
- bounded indexed columns, без индексирования raw payload/body;
- retention metadata и cleanup job;
- audit log не должен содержать raw body/canary/credentials.

## Differential oracle

Oracle должен быть доказательным и консервативным.

Для каждого case храни:

- baseline case hash и mutation chain;
- WAF observation source и confidence;
- backend parser id/version;
- backend parse manifest hash;
- canary presence/hash;
- status/timing;
- normalization IR hash;
- каталог/profile version;
- policy/preflight decision id;
- error taxonomy.

Finding `parser_disagreement` создаётся только если:

1. baseline успешно прошёл полный контрольный путь;
2. mutated case соответствует signed safe profile;
3. WAF observation достоверно `allow` или `log-only`;
4. backend typed manifest показывает canary в ожидаемом logical field;
5. WAF/backend parse manifests различаются предсказуемым образом;
6. результат воспроизведён минимум два раза в том же lab profile;
7. minimizer получил непустой bounded mutation subset;
8. evidence hashes и correlation ids согласованы.

Если хотя бы одного условия нет, результат — `uncertain`, а не finding.

Не используй формулировку «WAF bypass confirmed». Используй:

- `parser disagreement observed in authorized lab`;
- `normalization coverage gap`;
- `WAF/backend interpretation mismatch`.

## WAF events и monitoring

Введи vendor-neutral `WafEventV1`:

- event id, timestamp, tenant/app/profile ids;
- vendor/source type;
- action `allow|block|challenge|log|unknown`;
- rule/ruleset ids и redacted labels;
- method, normalized path template, response code;
- correlation/run/case ids;
- body/header field names без значений;
- encrypted-payload reference как opaque id, без дешифрования в модуле;
- ingestion provenance и schema version.

Метрики:

- runs/cases by state;
- allow/block/challenge/unknown counts;
- parse agreement rate;
- normalization coverage by safe mutation family;
- false-positive candidates;
- uncertain/error rate;
- request latency and minimization attempts;
- rejected-by-preflight/scope/policy counters.

Labels должны быть low-cardinality. Нельзя использовать target host, full path, rule message, canary, IP или tenant-provided value как Prometheus label.

## Findings, remediation и reports

Интегрируй с существующей evidence/report инфраструктурой, не создавая отдельный report engine.

Для доказанного lab disagreement включай:

- безопасное описание без attack payload;
- affected content type и safe mutation family;
- baseline/mutated canonical diff на уровне IR, без raw wire recipe;
- WAF/backend observation matrix;
- confidence и limitations;
- рекомендации:
  - strict parse → canonicalize → reserialize;
  - reject ambiguous/malformed input;
  - allowlist реально используемых content types;
  - единая duplicate-field policy;
  - согласованный decode/normalization order;
  - application-layer validation как второй слой;
  - staged log-only rollout и контроль false positives;
- retest criteria.

Valhalla показывает только evidence-backed findings. `uncertain`, неполные и log-only anomalies идут в отдельный limitations/observations блок и не повышают severity.

## Admin UI

После backend и tests добавь минимальный экран в существующем admin frontend, если это укладывается без нарушения текущих контрактов:

- список runs, state, progress, profile, mode и timestamps;
- create dry-run и start только из allowlisted profiles;
- cancel action;
- матрица baseline/mutated observations;
- charts по action и agreement rate;
- redacted finding detail и export link;
- RBAC, accessibility и существующие design patterns.

UI не должен показывать raw request bytes, attack payload editor, arbitrary URL field или кнопку отключения guardrails.

## Тестовая стратегия

Сделай tests first для safety invariants, затем функциональные тесты.

### Unit tests

- strict Pydantic schemas и bounds;
- canary rejects control/attack syntax;
- catalog signature valid/invalid/missing/duplicate/unknown operator;
- deterministic planner and hashes;
- bounded expansion/dedup/budget;
- normalizer purity/idempotence;
- reject-on-ambiguity;
- oracle positive/negative/uncertain matrix;
- minimizer boundedness/cancellation;
- redaction and log safety;
- state machine transition table.

### Policy/security tests

- arbitrary public URL невозможно передать через API;
- unknown lab profile denied;
- scope, ownership, policy или approval denial не enqueue-ит job;
- worker rechecks preflight;
- expired ownership proof denied;
- out-of-scope redirect/DNS change stops run;
- TLS disable/proxy/auth header/custom raw header impossible by schema;
- hard maxima cannot be increased by tenant config;
- kill switch stops remaining cases;
- no raw bodies/canaries/secrets in logs, metrics, DB previews или exports;
- no env/config switch disables safeguards;
- tenant A cannot read/cancel/export tenant B run;
- signed catalog fail-closed under tampering.

### Integration tests

- deterministic mock WAF: allow/block/challenge/unknown;
- instrumented backend parse manifests for JSON/form/multipart/XML;
- correlation and evidence hash chain;
- Celery cancellation/idempotency/retry behavior;
- MinIO artifact redaction;
- PostgreSQL RLS and migration upgrade/downgrade where project policy permits;
- report evidence gate.

### Docker e2e

- отдельный marker `requires_docker_e2e` или совместимый существующий marker;
- WAF lab network без external egress;
- baseline pass;
- один safe parser disagreement fixture;
- one false positive fixture;
- cancellation and request-budget assertion;
- cleanup containers/artifacts.

Не делай реальные внешние HTTP-запросы в unit/integration CI.

## Фазы реализации

Выполняй последовательно. После каждой фазы запускай узкий test set и исправляй regressions.

### Phase 0 — inventory и ADR

- составь короткий gap analysis существующих policy/sandbox/report components;
- создай ADR с trust boundaries, data flow, abuse cases и явным non-goals;
- зафиксируй, какие существующие классы переиспользуются.

### Phase 1 — contracts, signed catalog, offline engine

- models, canary, IR, catalog, normalizers, safe mutators, planner;
- signing script и drift tests;
- только offline tests.

### Phase 2 — lab runner и oracle

- mock WAF + parser backend;
- runner, observations, oracle, minimizer;
- network/resource guardrails и correlation.

### Phase 3 — persistence, service, Celery, API

- models/migration/RLS;
- state machine, service, worker, endpoints, auth/audit/idempotency;
- API contract tests.

### Phase 4 — event ingestion, evidence и reporting

- `WafEventV1`, JSON/JSONL import;
- artifacts/MinIO, metrics;
- Valhalla integration и remediation mapping.

### Phase 5 — UI и e2e

- admin UI;
- isolated Docker e2e;
- accessibility/security regression tests.

### Phase 6 — hardening и documentation

- ruff, targeted mypy if supported, bandit;
- dependency/license/SBOM review;
- operator runbook, data retention, threat model, API docs;
- final test matrix and known limitations.

## Definition of Done

Работа готова только когда:

- все новые сетевые пути проходят full preflight и worker-side recheck;
- произвольная внешняя цель конструктивно невозможна в v1;
- каталоги подписаны и fail-closed;
- только inert canaries проходят materialization;
- request/rate/concurrency/body/time limits покрыты тестами;
- lab network не имеет external egress;
- raw bodies/secrets отсутствуют в logs/metrics/default artifacts;
- tenant isolation/RLS протестированы;
- findings требуют baseline + reliable WAF observation + backend typed manifest + reproduction + minimization;
- existing tests не сломаны;
- документация объясняет lawful/authorized-only назначение и non-goals;
- нет vendored offensive payloads, bypass recipes или runtime dependencies из исключённого списка.

## Команды проверки

Адаптируй команды к фактическим путям, но минимум выполни:

```bash
cd backend
python -m pytest tests/unit/recon/waf_validation -q
python -m pytest tests/integration/recon/waf_validation -q
python -m pytest tests/unit/policy tests/unit/payloads -q
python -m ruff check src/recon/waf_validation tests/unit/recon/waf_validation tests/integration/recon/waf_validation
python -m bandit -r src/recon/waf_validation
```

Docker e2e запускай только если Docker доступен; иначе явно отметь `not run` с причиной. Не маскируй failing tests как skipped без документированной инфраструктурной причины.

## Формат финального отчёта Cursor

В конце выдай:

1. краткий outcome;
2. список созданных/изменённых файлов по подсистемам;
3. ключевые safety invariants и где они enforced;
4. migrations/API/contracts;
5. выполненные команды и точные результаты;
6. что не запускалось и почему;
7. known limitations и безопасные следующие шаги;
8. подтверждение, что unrelated dirty-worktree changes не затронуты.

Не останавливайся на плане или псевдокоде: реализуй, протестируй и документируй весь безопасный scope. Если существующая архитектура противоречит предположению из этого промпта, сохрани security invariant, адаптируй интеграцию к реальному коду и зафиксируй решение в ADR.
