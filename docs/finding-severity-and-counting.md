# Severity, доказанность, жизненный цикл и приоритет: как ARGUS назначает и считает findings

Документ описывает нормативную основу и внутреннюю политику ARGUS для назначения
severity и подсчёта «Findings by severity» на всём пути
`ingestion → persistence → API → report snapshot → frontend/exports`.

Цель: **одинаковые проверенные данные дают одинаковые severity, счётчики и
диаграммы независимо от формата отчёта, тарифа, пагинации и способа получения
данных.**

---

## 1. Четыре независимых оси

Severity — это **только про impact**. Она не смешивается с тремя другими осями:

| Ось | Значения | Где живёт |
|-----|----------|-----------|
| **Severity (band)** | `critical`, `high`, `medium`, `low`, `informational`, `unknown` | `src/findings/severity.py` (`SeverityBand`); фронт `SeverityKey` |
| **Validation / confidence** | `confirmed`, `suspected`/`likely`, `inconclusive`, `rejected` (существующие `ConfidenceLevel` / `EvidenceTier` / `validation_status`) | `pipeline/contracts/finding_dto.py` |
| **Lifecycle** | `open`(`new`/`validated`), `fixed`, `accepted_risk`, `false_positive` | `FindingStatus` |
| **Remediation priority** | `P0`–`P4` | `src/findings/prioritizer.py` (`PriorityTier`) |

Правила разделения:

- **Отсутствие доказательств не понижает severity.** Меняется validation, а не
  severity. Неподтверждённый Critical остаётся Critical (с `suspected`), но
  показывается в отдельной population (см. §6).
- **Пересчёт severity разрешён**, только если новые факты меняют реальный impact
  или предпосылки эксплуатации — с сохранением истории и обоснования, а не
  «за недостаток доказательств».
- **Priority ≠ severity.** На фронте `CheckPriority` (remediation) и
  `SeverityKey` (impact) — разные поля. Диаграмма severity больше не
  восстанавливается из priority.

---

## 2. CVSS-политика и источники

Нормативная шкала — FIRST.org CVSS v3.1 §5 (и v4.0 для v4-векторов):

| Округлённый балл | CVSS-номенклатура | Band в ARGUS |
|------------------|-------------------|--------------|
| `0.0` | None | `informational` (документированное отображение) |
| `0.1–3.9` | Low | `low` |
| `4.0–6.9` | Medium | `medium` |
| `7.0–8.9` | High | `high` |
| `9.0–10.0` | Critical | `critical` |
| нет балла | — | `unknown` (**никогда не 0.0**) |

Реализация:

- Разбор и оценка векторов — только через сторонний пакет `cvss`
  (`src/findings/cvss.py::parse_cvss_vector`). Второй самописный калькулятор в
  авторитетном пути не используется.
- `severity_label(score)` — единственный маппинг «балл → CVSS-метка». Отклоняет
  `bool`, `NaN`, `±Inf` и значения вне `[0, 10]`.
- `band_from_cvss_score(score)` (`src/findings/severity.py`) — маппинг
  «балл → отображаемый band»: `None → unknown`, `0.0 → informational`, далее по
  стандартной шкале; невалидный ввод → `unknown`.
- v3.x и v4.0 не конвертируются между версиями автоматически; версия, вектор и
  тип оценки сохраняются как есть. CVSS 4.0 не кладётся в поля `cvss_v3_*`.

**Что запрещено** (ARGUS policy):

- Не выдавать vendor/rule severity за рассчитанный CVSS.
- Если источник дал только severity — сохранить её, `cvss_score`/`cvss_vector`
  оставить `null`, не подставлять `7.5`/`9.0`/шаблонный вектор.
- Если источник дал только число — хранить как reported/unverified с
  происхождением, не изобретать вектор.
- При конфликте — сохранить конфликт, пересчитать балл валидного вектора,
  применить явную политику выбора; **не** удалять исходный вектор ради
  подгонки под объявленную severity.

---

## 3. Non-CVSS assessments и запрет keyword-autoscoring

Не требуется CVSS для каждого hardening-наблюдения и не требуется CVE для
обоснованной severity.

- `CVSSAutoScorer` / `_SEVERITY_TO_CVSS` больше **не** создают авторитетную
  оценку по названию / CWE / OWASP-категории / готовой severity.
- Keyword-эвристика (`src/findings/cvss_auto_score.py`) осталась только как
  **provisional-предложение**: пишет `cvss_suggested_{score,vector,severity}` и
  флаг `cvss_provisional=True`, никогда не трогает авторитетные
  `severity`/`cvss`/`cvss_vector`. При отсутствии совпадения возвращает `None`
  (никакого catch-all `0.0`-вектора).
- Продвижение provisional-оценки в авторитетную — это авторизованное действие
  через существующие права приложения (analyst override) с сохранением
  предыдущей оценки; не автоматический выбор максимума среди источников.
- Hardening оценивается прозрачными versioned-правилами с предусловиями и
  rationale; rule-based severity не выдаётся за CVSS.
- LLM может предложить оценку, но не меняет авторитетные поля/агрегаты через
  генерацию текста.

Примеры, которые **не** назначаются автоматически: SQLi → Critical,
XSS → High, отсутствие CSP → доказанный XSS, отсутствие HSTS → одинаковый impact
на любой цели.

---

## 4. Единица подсчёта и дедупликация

Каноническая агрегация — `src/findings/severity.py::aggregate_severity`
(и делегирующий к ней `data_collector.executive_severity_totals_*`).

- **Единица счёта — уникальная каноническая finding.** Повтор одного результата
  не увеличивает total (дедуп по
  `sha256(asset|category|root_cause|parameter)` в `normalizer._deduplicate`).
- Независимые дефекты не объединяются только по `title`/`CWE`/`severity`; разные
  assets/parameters учитываются раздельно.
- `occurrences` и `affected assets` считаются отдельно от количества findings.
- Passed checks **не** входят в findings: `totalFindings` на фронте =
  число `status == "fail"`; успешные проверки — отдельный блок. Info ≠ pass;
  fixed finding ≠ успешно выполненная проверка без retest.

**Инвариант:** сумма всех бакетов, включая `unknown`, равна размеру population:
`sum(counts_by_severity) == total`. `unknown` — первоклассный бакет и никогда не
теряется и не сливается в `low`/`info`.

---

## 5. Populations и denominators

Явно именованные populations (одинаковые для API / MCP / report / UI):

- **confirmed findings** — подтверждённые;
- **unconfirmed findings** — suspected/inconclusive;
- **all non-rejected findings**;
- **active findings** — operational view.

Executive-view по умолчанию: подтверждённые findings + заметный отдельный блок
неподтверждённых (с их severity). Suspected Critical **не** прячется за общим
нулём. Info/hardening показываются отдельно либо явно включаются в выбранную
population — и не называются подтверждёнными уязвимостями.

**Denominator один и явный.** Диаграмма severity (`SeverityDonut`) и плитки
executive-заголовка читают **один** backend-агрегат; проценты считаются от
`totalFindings` выбранной population. Тариф может менять набор выполненных
проверок и доступность деталей, но **не** правила классификации: одинаковый
набор данных классифицируется одинаково на любом тарифе.

---

## 6. Frontend-модель

- `finding.severity` (`SeverityKey`) отделён от `finding.priority`
  (`CheckPriority`). `CheckPriority` больше не используется как хранилище
  severity.
- Диаграмма severity: `High` (не «Important»), отдельные `Medium` и `Low`,
  добавлены `Informational` и `Unknown`. «Important findings» как список
  приоритетных действий (если понадобится) — это priority policy, а не
  severity distribution.
- Карточки и donut читают один агрегат; total не пересчитывается из
  урезанной тарифом/пагинацией таблицы.
- Ошибка API отличается от «чистого скана»: `ScanResults.dataStatus`
  (`loaded` / `empty` / `error`) — `loaded-empty` ≠ `not-loaded`.
- `riskScore` не смешивает `adversarial_score` и `cvss` в одну недокументированную
  шкалу; CVSS и remediation priority показываются раздельно (см. §8 Ограничения).

---

## 7. Historical / live semantics

- **Live operational state** и **immutable historical report snapshot** —
  разные вещи; после retest могут отличаться, но всегда имеют время/версию.
- Сборка/чтение отчёта **не** мутируют исходную severity в БД.
- WS/live-путь (`Frontend/src/lib/live-findings.ts`) использует ту же
  каноническую агрегацию (`censusFromFindings`), `info` считается как
  informational-находки, а не как fallback к числу passed-проверок.

---

## 8. Legacy handling

- Исторические CVSS не «чинятся» по внешнему виду числа: `7.5` может быть как
  реальным, так и синтетическим. Используются флаги происхождения
  (`cvss_auto_scored`, `cvss_provisional`); при неизвестном происхождении —
  пометка legacy_unverified.
- Старые snapshots остаются читаемыми и не переписываются автоматически под
  новую политику.
- `unknown`-бакет добавлен в `executive_severity_totals_*` совместимо:
  потребители, читающие явные ключи (`ReportSummary`, шаблоны), не ломаются;
  cross-format gate нормализует обе стороны к каноническому набору бакетов.

---

## 9. EPSS / KEV / SSVC и priority

Механизмы threat-intel используются для **remediation priority**, отдельно от
severity:

- EPSS **probability** и **percentile** — разные поля; percentile не
  подменяется вероятностью в общей шкале сортировки.
- Отсутствие EPSS ≠ вероятность 0; отсутствие данных KEV ≠ проверенное
  отсутствие в каталоге. Non-CVE findings не понижаются за отсутствие EPSS.
- KEV не меняет CVSS Base.
- Внутренний weighted priority score (`Prioritizer`) не называется CVSS или
  вероятностью риска.

---

## 10. Ограничения (осознанно вне текущего среза)

- Отдельная таблица провенанса `SeverityAssessment` (assessment_id, method,
  source_ref, policy_version, rationale, supersedes, конфликтующие оценки) и
  соответствующие миграции — спроектированы, но не внедрены в этом изменении;
  требуют запущенного стека и совместимых миграций.
- Полное переключение MCP / websocket summaries / snapshot_builder / exports на
  единый aggregation-service — стадийно; здесь канонизированы `severity.py`,
  `data_collector` executive totals, cross-format gate и весь severity-путь
  фронтенда (scan/live).
- Frontend `dataStatus=error` поддержан на уровне модели; проброс ошибки fetch в
  страницу scan (различение `error` vs `empty` в server component) — следующий
  шаг.
- `riskScore` во фронте оставлен как есть для сортировки; разнесение
  CVSS и adversarial по разным шкалам — отдельная задача.

Неоценённые находки честно остаются `unknown` / source-rated. Не требуется
автоматически рассчитывать CVSS для всех findings.
