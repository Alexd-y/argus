Доработка отчёта Valhalla в форматах `.json`, `.md`, `.xml`, `.html`

> **Скоуп:** четыре машиночитаемых и текстовых формата канонического отчёта Valhalla. PDF затрагивается только там, где он противоречит четвёрке.
> **Основание:** разбор реально выгруженного комплекта отчёта `c8042766-edd3-42e6-b9ff-ea0f178d63dc` по скану `d6fdd027-ecec-4791-aed2-ef21025d1c7f` (target `alleksy.com`, tenant `00000000-…-0001`).
> **Связанный документ:** `CURSOR_VALHALLA_REPORT_FIX_PROMPT.md` — фазы A–V, контракт доказуемости, эталонный макет. Этот документ не дублирует его, а уточняет по итогам новой выгрузки. Где здесь сказано «см. фазу X» — читай там.

> **Примечание.** Веб-интерфейс `http://34.220.253.106:5000/scan/d6fdd027-…` из моей песочницы недоступен (egress-allowlist), поэтому разбор сделан по приложенным файлам. Если на странице отчёт выглядит иначе, чем в выгрузке — это само по себе дефект, и его надо добавить к списку ниже.

---

## 0. Что разобрано

| Файл | Размер | Producer / заголовок | Содержание |
|---|---|---|---|
| `….canonical_json` | 142 682 | — | канонический снапшот `schema_version: v2`, 46 полей верхнего уровня |
| `….canonical_md` | 13 903 | — | 10 разделов, 9 карточек находок |
| `….canonical_xml` | 20 513 | — | `<argus_report schema_version="v2">`, 9 `<finding>` |
| `….canonical_html` | 21 873 | — | 10 `<h2>`, карточки находок с PoC |
| `….canonical_pdf` | 59 286 | WeasyPrint 70.0, «ARGUS Report — alleksy.com» | **8 страниц, обложка в стиле эталонного макета** |
| `….pdf` | 218 875 | WeasyPrint 70.0, «Svalbard Security Inc. Report - alleksy.com» | **48 страниц, legacy-шаблон Valhalla** |

---

## 1. Что уже исправлено — не переделывай

Прогресс с прошлой итерации существенный, это надо зафиксировать:

- **Пагинация PDF починена.** Основной PDF — 48 страниц с колонтитулом `Page N / 48`. Дефект `D1` (flex + WeasyPrint) снят.
- **Каноническая схема поднята до `v2`.** В находке появились `claims`, `poc`, `remediation`, `closure`, `acceptance_criteria`, `retest_plan`, `cvss_score/vector/version`, `asset/ip/port/protocol/scheme/url/path/parameter/component`, `observed_impact/potential_impact/blast_radius`, `confirmation_class`, `downgrade_reason`, `established_or_hypothesis`, `priority_rationale`, `review_status`, `reviewer`, `wstg_test_ids`.
- **Паспорт релиза заведён.** `generation_status`, `llm_analysis_status`, `assessment_completeness`, `evidence_integrity`, `review_status`, `verification_kit_ref` — шесть независимых полей, как требовалось.
- **Появились контейнеры** `claims`, `attack_narrative`, `methodology`, `test_executions`, `unconfirmed_observations`, `surface_inventory`, `exploit_chains`, `conclusions`, `limitations`.
- **`tool_runs` получили время и честный статус.** `started_at`, `finished_at` заполнены; появился статус `completed_no_output` вместо ложного `success`.
- **Четыре канонических формата между собой согласованы.** Проверено попарно: 9 находок в каждом, одинаковые `finding_id`, `severity`, `cvss_score`, `owasp_category` в JSON, XML, MD и HTML.
- **`canonical_pdf` получил обложку эталонного макета:** вордмарк, `PREPARED FOR` / `DATE` / `SCAN ID`, плитки метрик, плашка `CONFIDENTIAL`, `Page N of M`, строка `snapshot_hash · schema v2 · generation_status`.
- **HTML экранирует содержимое** (`&#x27;` вместо сырой кавычки).

Дальше — то, что осталось.

---

## 2. Доказательная таблица нестыковок

Каждый пункт подтверждён значением из выгруженных файлов. Все должны стать регресс-тестами `C-01`…`C-24`.

### Группа A — два конкурирующих отчёта в одном комплекте

| ID | Нестыковка | Доказательство |
|---|---|---|
| **C-01** | **В комплекте два разных PDF с разным брендом, вёрсткой и данными.** `….pdf` — 48 страниц, «Svalbard Security Inc. Report», legacy-шаблон. `….canonical_pdf` — 8 страниц, «ARGUS Report», макет по образцу. Разные `md5`. Заказчик не может понять, какой из них отчёт | `pypdf`: 48 против 8 страниц; разные `/Title` |
| **C-02** | **Счётчики находок противоречат друг другу.** `canonical_pdf` обложка: `9 FINDINGS / 0 CRITICAL / 0 HIGH / 3 MEDIUM`. Основной `.pdf`, таблица «Vulnerability Count by Severity Level»: `Critical 0, High 0, Medium 1, Low 0, Info 0` | обе цифры напечатаны в одном комплекте |
| **C-03** | **Три разных набора счётчиков на одной странице основного PDF.** Текст: «recorded 9 finding(s) (critical=0, high=0, **medium=3, low=4, info=2**)». Строкой ниже: «Findings summary (per table data): Critical 0, High 0, **Medium 1**, Low 0, Info 0; total **1** provable finding(s), plus 8 unconfirmed». Таблица: `Medium 1` | стр. 1 основного PDF |
| **C-04** | **Раздел «Unconfirmed Observations» есть в PDF (8 записей) и пуст в четвёрке** | `canonical_json`: `"unconfirmed_observations": []`; PDF, стр. 27–33: таблица с 8 строками |
| **C-05** | **Выводы LLM есть в PDF и отсутствуют в четвёрке.** PDF печатает Executive Summary, Key Business Risks, Priority Tasks | `canonical_json`: `conclusions.executive_summary = null`, `conclusions.business_risk = null`, `conclusions.priority_plan = []` |
| **C-06** | **Цепочки: PDF отрицает, четвёрка утверждает.** PDF: «No validated multi-step exploit chain was demonstrated». Четвёрка: 4 цепочки `CH-hyp-1…4` | `canonical_json`: `exploit_chains: list[4]` |
| **C-07** | **Покрытие WSTG двумя значениями.** Четвёрка: `coverage_pct: 2.0833`, `counted: 2`, `catalog_total: 96`. Основной PDF трижды: «WSTG coverage: 17%» | `canonical_json.wstg` против стр. 1, 34 PDF |
| **C-08** | **OWASP-категория одной находки различается между PDF и четвёркой.** `a9caa12d` (заголовки): четвёрка — `A02`, PDF — `A05:2021 — Security Misconfiguration`. При этом OWASP-таблица PDF помечает `A02` как `Not assessed`, хотя четвёрка относит к `A02` две находки | `canonical_json/xml/md/html`: `owasp_category: A02`; PDF стр. 2 и 25 |
| **C-09** | **Два измерения смешаны: `confidence` печатается как статус верификации.** PDF в колонке `CONFIDENCE` пишет `confirmed` для `a9caa12d`; четвёрка даёт `verification_status: suspected`, `confidence: 0.95`. Ни одна из 9 находок не имеет `confirmed` | прямое нарушение `EVD-01` |

### Группа B — контейнеры `v2` объявлены и не наполнены

| ID | Нестыковка | Доказательство |
|---|---|---|
| **C-10** | `claims: []` на уровне отчёта и `claims: []` у каждой находки. Контракт утверждения объявлен, но ни одного claim не создано — значит прослеживаемость «утверждение → claim → evidence» не работает | `canonical_json` |
| **C-11** | `limitations: []` при `assessment_completeness: "incomplete"`, `coverage_gate_passed: false`, `counted: 2 / 96`, `not_started: 94`, `unknown: 50`. В MD раздел «Limitations» печатает `_none_`, в PDF «Limitations: none» | это уже не пробел, а неверное утверждение |
| **C-12** | `test_executions: []` при 23 `coverage`-записях и 10 `tool_runs`. Раздела «выполненные проверки без находок» нет ни в одном формате | |
| **C-13** | `methodology: []` — раздел методики в четвёрке отсутствует, хотя в PDF он есть (NIST SP 800-115, CWE, WSTG, SANS CWE Top 25) | |
| **C-14** | `attack_narrative: []` — хода работ в четвёрке нет | |
| **C-15** | `tested_capabilities: []` при `not_assessed_capabilities: 23` | |
| **C-16** | `surface_inventory` — одна запись, всё кроме хоста `null`: `{"host":"alleksy.com","port":null,"service":null,"technology":null,"version":null}`. Инвентарь поверхности пуст, хотя recon запускал `naabu` и `nmap` | |
| **C-17** | Паспорт снапшота: `execution_mode`, `scan_profile`, `resolved_scan_mode`, `nuclei_profile`, `quick_profile`, `started_at`, `engagement`, `client_impact` = `null`; `registry_versions`, `prompt_model_versions`, `scope_summary`, `budget_usage`, `profile_limits` = `{}` | |
| **C-18** | `generation_status: "unknown"` и `evidence_integrity: "unknown"` в выпущенном отчёте. Неизвестный статус генерации в готовом артефакте — противоречие | |

### Группа C — семантика данных

| ID | Нестыковка | Доказательство |
|---|---|---|
| **C-19** | **OWASP-классификация перемешана.** TLS-наблюдение → `A04` (Insecure Design); «Line Finding» → `A05`; отпечаток WhatWeb → `A02` (Cryptographic Failures); отсутствующие заголовки → `A02`. Правильно: TLS → `A02`, заголовки → `A05`. Плюс у 5 из 9 находок `owasp_category: null` | `canonical_json`, все 9 находок |
| **C-20** | **CVSS есть у всех, вектор — у одной.** `cvss_score` заполнен у всех 9 (`5.0, 0.0, 0.0, 3.9, 3.1, 3.1, 3.1, 5.5, 5.3`), `cvss_vector` — только у `a9caa12d`, `cvss_version` = `null` у всех. Балл без вектора недоказуем; `0.0` у двух находок печатается как значение | |
| **C-21** | **`discriminator: "http_reflection"` у находки об отсутствующих заголовках** (CWE-693). Из-за этого PDF печатает в карточке блок `XSS DETAILS` и `verification_method: HTTP reflection`. PoC заполняется по XSS-шаблону независимо от класса находки | `canonical_json.findings[…].poc.discriminator`; PDF стр. 26 |
| **C-22** | **«Доказательство» — страница ошибки Cloudflare.** `poc.http_response: "HTTP 530"`, а в PDF приведён сниппет `<title>Cloudflare Tunnel error \| alleksy.com \| Cloudflare</title>`. По ответу 530 (origin недоступен) нельзя судить о заголовках безопасности приложения — но находке присвоены CVSS 5.3 и `Evidence Classification: observed` | стр. 26–27 PDF; `canonical_*` |
| **C-23** | **`evidence_references`: новые поля есть, все `null`.** `sha256`, `collected_at_utc`, `collector`, `mime`, `size`, `producer_tool_run_id`, `redaction_applied`, `chain_hash` — `null` во всех 9 записях. `evidence_id` равен `object_key`, то есть идентификатор — это путь в хранилище. Остались псевдо-ID `tool:testssl`, `tool:web_vuln_heuristics`, `recon:asnmap` | |
| **C-24** | **`tool_run_id` и `validator_id` = `null` у всех 9 находок** при 10 заполненных `tool_runs`. Цепочка `finding → tool_run → артефакт` по-прежнему разорвана. В `tool_runs` также `null`: `argv`, `exit_code`, `parser_status`, `raw_artifact_ref`, `sandbox_id`, `source_ip` | |

### Группа D — качество самих четырёх форматов

| ID | Нестыковка | Доказательство |
|---|---|---|
| **C-25** | **XML без namespace и без XSD.** `src/reports/renderers/xml_renderer.py:17-18`: `root = Element("argus_report")` + `root.set("schema_version", …)` — ни `xmlns`, ни ссылки на схему. Требование «типизированный XML с namespace и XSD» не выполнено. При этом в репозитории уже есть образец: `VALHALLA_LLM_XML_NS = "urn:argus:valhalla-llm:v1"` в `llm_remediation/render.py:39` | `canonical_xml`, первые две строки |
| **C-26** | **XML теряет данные, которые есть в JSON.** У `9cad7f6a` в XML `<cvss_vector />` пуст и `<cvss_version />` пуст — при том что структура для них есть. Пустые элементы не отличимы от `null` и от «не применимо» | |
| **C-27** | **Битая разметка Markdown — точная причина найдена.** `src/reports/renderers/markdown_renderer.py:31`: `f"- cvss: \`{f.cvss_score}\` \`{f.cvss_version or ''}\` \`{f.cvss_vector}\`"`. Поскольку `cvss_version` равен `None`, во вторую пару обратных кавычек попадает пустая строка, и в выводе появляется `` `` `` | `canonical_md:149` |
| **C-28** | **MD и HTML — дамп полей, а не документ.** Карточка начинается со списка `severity / verification_status / confidence / cwe / owasp_category / tool_run_id / validator_id / raw_artifact_ref / evidence_ids`, включая `not_assessed` для пустых. Нет блоков `WHAT WE FOUND` / `WHY THIS MATTERS` / `RECOMMENDED REMEDIATION` / `VALIDATION` из эталонного макета; вместо них `Metrics` / `What We Found` / `Evidence` | `canonical_md`, `canonical_html` |
| **C-29** | **`raw_artifact_ref` с внутренним путём хранилища печатается в клиентских форматах.** `00000000-…-0001/d6fdd027-…/poc/a9caa12d-….json` — это tenant_id и внутренняя структура бакета. Основной PDF явно декларирует «Raw storage paths and internal API endpoints are omitted from the customer report», а четвёрка их печатает | |
| **C-30** | **Псевдо-цепочки.** Каждая из 4 `exploit_chains` — один шаг, который дословно повторяет заголовок находки; `evidence_ids: []`, `claim_ids: []`, `outcome: null`, `preconditions: null`, `breaks_at: null`, а `to_verify` — литеральная инструкция «Reproduce with a discriminator and a negative control before asserting». Это не цепочка воздействия | |
| **C-31** | **`Findings` в таблице severity не связаны с находками.** В PDF колонка `FINDINGS` содержит `—` во всех строках; в четвёрке связи severity → список ID тоже нет | |

### Группа E — LLM

| ID | Нестыковка | Доказательство |
|---|---|---|
| **C-32** | `llm_analysis_status: "failed"` — обязательный per-finding анализ снова не выполнен. У всех 9 находок `remediation: null`, `closure: null`, `acceptance_criteria: []`, `retest_plan: []`, `priority_rationale: null` | `canonical_json` |
| **C-33** | **Утечка плейсхолдеров промта сохранилась.** Секция `HARDENING RECOMMENDATIONS (AI)` в PDF содержит ровно: `[Layer] [Config/file] → Change: [specific value] → Verify: [curl command]` | стр. 34 PDF |
| **C-34** | **Секции AI перепутаны местами.** `REMEDIATION STEPS (AI)` содержит текст executive summary («Structured results: 9 finding(s) recorded. Severity totals… Narrative aligned to verified metrics above»), а `PRIORITIZATION ROADMAP (AI)` содержит текст рекомендаций по заголовкам | стр. 34 PDF |
| **C-35** | **Блок «Vulnerability Remediation Stages» напечатан дважды подряд** — идентичные TIER 1/2/3 | стр. 34–35 PDF |
| **C-36** | **План устранения адресован находкам, которых нет в реестре подтверждённых.** TIER 1 — `9cad7f6a` («Update TLS/SSL configuration»), TIER 2 — `d188ac46`, TIER 3 — `55dc0dc8`. Единственная находка, попавшая в валидированный реестр PDF (`a9caa12d`), не упомянута ни в одном тире | стр. 34–35 PDF |

---

## 3. ФАЗА 1 — Один отчёт, а не два

`C-01`…`C-09` — это один системный дефект: в системе два независимых генератора отчёта Valhalla, и оба выпускаются.

1. **Выбрать единственный источник.** Канонический снапшот `ReportDocumentV1 v2` + рендереры `src/reports/renderers/` — единственный путь для всех форматов Valhalla, включая PDF. Legacy-путь `generators.generate_pdf` → `valhalla.html.j2` для tier=valhalla выводится из эксплуатации.
2. **Перенести в канонический путь то, что есть только в legacy:** разделы «Unconfirmed Observations», OWASP-таблица с оценкой применимости, HIBP, robots/sitemap, TLS-анализ, «Active Web Scanning», «Risk Matrix», методика и стандарты, «Evidence Inventory». Без этого переключение потеряет содержание.
3. **Удалить конкурирующий артефакт.** В комплекте остаётся один PDF. Пока перенос не завершён — держать legacy за флагом с именем `valhalla_legacy_pdf` и **не** включать его в обязательный набор и в UI.
4. **Пересчитывать счётчики из одного места.** Функция, считающая распределение severity, — одна, и все форматы и все секции вызывают её. Текст LLM не содержит чисел, вставленных моделью: числа подставляются приложением в готовый шаблон.
5. **Разделить два измерения окончательно.** Колонка/поле `verification_status` (`observed` / `suspected` / `confirmed` / `inconclusive` / `false_positive`) и поле `confidence` (число) никогда не печатаются под одной подписью. Слово `confirmed` в отчёте означает только `verification_status == confirmed`.
6. **Одно значение покрытия.** Значение WSTG вычисляется один раз, попадает в снапшот и подставляется везде. Строка «WSTG coverage: 17%» внутри LLM-текста заменяется подстановкой из снапшота.

---

## 4. ФАЗА 2 — Наполнить контейнеры `v2`

`C-10`…`C-18`. Правило: **объявленный и пустой контейнер хуже отсутствующего**, потому что он читается как «данных нет», а не «не реализовано».

| Контейнер | Чем наполнить | Правило блокировки |
|---|---|---|
| `claims` | по одному claim на каждое существенное утверждение: наблюдение, подтверждённая уязвимость, вывод, гипотеза, рекомендация. Поля — по фазе I связанного документа | находка с `severity >= medium` без ни одного claim блокирует выпуск |
| `limitations` | автоматически из quality gate: покрытие ниже порога, `blocked`/`tool_error` инструменты, отсутствие аутентифицированного тестирования, отсутствие эксплуатации, деградация LLM, недоступность цели (здесь — `HTTP 530`) | `coverage_gate_passed == false` и `limitations == []` → блок |
| `test_executions` | журнал выполненных проверок: контроль, метод, время, результат (`passed`/`failed`/`blocked`/`tool_failed`/`not_applicable`/`inconclusive`), ссылка на evidence. Источник — `coverage` (23 записи) + `tool_runs` (10) | пусто при непустом `coverage` → блок |
| `methodology` | применённые методики с редакциями (NIST SP 800-115, OWASP WSTG v4.2, PTES, CWE, CVSS) и перечень фактически применённых техник | обязателен всегда |
| `attack_narrative` | хронология работ по фазам с временными метками; при отсутствии подтверждённых шагов — явная запись «подтверждённых шагов продвижения не получено» | обязателен всегда |
| `tested_capabilities` | из `coverage` со статусом `covered_no_finding` и подобными | пусто при непустом `coverage` → блок |
| `surface_inventory` | хосты, IP, порты, сервисы, версии, технологии, методы обнаружения — из recon-артефактов (`naabu`, `nmap`, `whatweb`) | запись, где заполнен только `host`, считается незаполненной |
| `unconfirmed_observations` | 8 записей, которые сейчас есть только в PDF | расхождение числа с PDF → блок |
| `conclusions` | `executive_summary`, `business_risk`, `priority_plan`, `closure_summary` — из LLM (фаза 8) | `null` при `llm_analysis_status == completed` → блок |
| паспорт | `execution_mode`, `scan_profile`, `resolved_scan_mode`, `nuclei_profile`, `started_at`, `registry_versions`, `prompt_model_versions`, `scope_summary`, `budget_usage`, `profile_limits` | `{}` или `null` в обязательном поле → ошибка валидации |
| `generation_status`, `evidence_integrity` | реальные значения; `unknown` допустим только до завершения генерации | `unknown` в выпущенном артефакте → блок |

---

## 5. ФАЗА 3 — JSON

Сейчас это самый полный формат, и именно он должен стать нормативным контрактом.

1. **Опубликовать JSON Schema.** Каталога `backend/config/schemas/` сейчас нет — создай его (рядом с существующими `config/prompts/`, `config/tools/`, `config/llm/`) и положи `valhalla_report_v2.schema.json` с `$id`, `title`, `required`, `additionalProperties: false`. В сам документ добавить `"$schema"` и `"schema_version": "v2"`. Если решишь хранить схемы иначе — зафиксируй решение в `docs/report-service.md`, но схема обязана быть версионированным файлом в репозитории, а не строкой в коде.
2. **Политика пустых значений.** Три разных смысла нельзя кодировать одним `null`:
   - `null` — «значение не определено, потому что не собиралось»;
   - `"not_applicable"` — «неприменимо по природе объекта»;
   - `"unknown"` — «собиралось, но установить не удалось».
   Зафиксировать в схеме перечислением и применять единообразно. Сейчас `not_assessed` появляется только в рендерерах MD/HTML как подстановка, а в JSON стоит `null` — это разные утверждения.
3. **Стабильный порядок и детерминированность.** Ключи сортируются, списки имеют детерминированный порядок (находки — по severity, затем по CVSS, затем по ID). `canonical_payload()` должен давать байт-в-байт одинаковый результат при одинаковом входе — на этом держится `snapshot_hash`.
4. **Не печатать внутренние пути.** `raw_artifact_ref` и `object_key` в клиентской проекции заменяются на непрозрачный `evidence_id` + `sha256`; полный путь остаётся во внутренней проекции и в комплекте независимой проверки (`C-29`).
5. **Числа как числа.** `cvss_score` — число или `null`, но не `0.0` в значении «нет оценки». `0.0` у двух находок сейчас читается как валидный балл.

---

## 6. ФАЗА 4 — XML

1. **Namespace и версия.** `<report xmlns="urn:argus:valhalla-report:v2" schema_version="v2" snapshot_hash="…">`. Зарегистрировать URN рядом с существующим `urn:argus:valhalla-llm:v1`.
2. **XSD.** `backend/config/schemas/valhalla_report_v2.xsd` с типизацией: `xs:dateTime` для времени, `xs:decimal` для CVSS, перечисления для `severity`, `verification_status`, `confirmation_class`, `status` покрытия. Валидация в тесте и в гейте выпуска.
3. **Различать пустое и отсутствующее.** `<cvss_vector />` сейчас не отличается от «не применимо». Использовать `xsi:nil="true"` для «не определено» и не выводить элемент вовсе для «не применимо», зафиксировав правило в XSD (`C-26`).
4. **Паритет с JSON по полям.** Тест, который сверяет: каждое непустое поле находки в JSON имеет соответствующий непустой элемент в XML. Сейчас `cvss_vector` теряется.
5. **Безопасность парсера.** Валидация только через парсер с отключёнными внешними entity и DTD. Никаких `resolve_entities`.
6. **Не JUnit.** Формат `xml` Valhalla не должен пересекаться с `junit_generator.py`; оба остаются, но `format=xml` для Valhalla — это отчёт.

---

## 7. ФАЗА 5 — Markdown

1. **Исправить разметку CVSS** (`C-27`): строка должна быть `- CVSS: **5.3** (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N)`, без пустых пар обратных кавычек. Пройти весь `markdown_renderer.py` на такие артефакты и добавить тест, проверяющий отсутствие последовательностей `` `` `` и `` ` ` ``.
2. **Структура по эталонному макету**, а не дамп полей (`C-28`). Порядок карточки:
   ```markdown
   ### 01 · MEDIUM · suspected — Missing or incomplete HTTP security response headers
   `a9caa12d-55d8-5857-a001-c1f0710e3781`

   | | |
   |---|---|
   | CVSS | 5.3 (CVSS:3.1/…) |
   | CWE | CWE-693 |
   | OWASP | A05:2021 — Security Misconfiguration |
   | Актив | alleksy.com:443 (https) |
   | Статус верификации | suspected |
   | Уверенность | 0.95 |

   **Что обнаружено.** …
   **Почему это важно.** …

   #### Доказательство
   - Инструмент: `web_vuln_heuristics`
   - Запрос: `GET https://alleksy.com`
   - Ответ: `HTTP 530`
   - Дискриминатор: …
   - Негативный контроль: …
   - Evidence: `E-004` (sha256 `…`, собрано `…`)

   #### План устранения
   #### Критерии приёмки
   #### Ретест
   #### Вывод о закрытии
   ```
3. **Убрать `not_assessed` из карточки.** Поле, для которого нет значения, не печатается; факт его отсутствия отражается в разделе полноты. Печать девяти строк `not_assessed` подряд создаёт вид отчёта без содержания.
4. **Экранирование.** Символы `|`, `` ` ``, `*`, `_`, `<` внутри значений экранируются; многострочные значения (HTTP-ответ) — в fenced-блоке с указанием языка.
5. **Раздел «Limitations» не печатает `_none_`**, если ограничения есть (`C-11`).

---

## 8. ФАЗА 6 — HTML

1. **Макет эталона.** Применить к `canonical_html` то, что уже применено к `canonical_pdf`: обложка с плитками метрик, оглавление, разрядённые подзаголовки секций карточки, группировка находок по активу, приложения. Один набор content-блоков, print-CSS меняет только раскладку (см. фазу B связанного документа).
2. **Self-contained.** Никаких внешних ресурсов: шрифты и логотип — data-URI из `backend/templates/reports/_fonts/` и `logo.svg`, CSS — инлайн. Рендерер не подтягивает произвольные URL.
3. **HTML как текст, а не как код.** Сниппеты ответов (здесь — страница ошибки Cloudflare с `<!doctype html>` и условными комментариями IE) выводятся в `<pre><code>` с полным экранированием. Сейчас экранирование работает — закрепить тестом, который подаёт в PoC строку `<script>alert(1)</script>` и проверяет, что в выводе нет исполняемого тега.
4. **Навигация.** Оглавление со ссылками на секции и на карточки находок по `finding_id`; обратные ссылки из инвентаря доказательств к находкам.
5. **Печать.** `@media print` без flex/grid на контейнерах контента, `@page` с колонтитулом и `counter(page)` — чтобы HTML и PDF давали один документ.
6. **Один и тот же набор секций, что в MD.** Сейчас в обоих 10 разделов, но после фазы 2 их станет больше; тест на равенство набора заголовков между MD и HTML.

---

## 9. ФАЗА 7 — Семантика данных

1. **OWASP-классификатор** (`C-19`). Разобраться, почему TLS → `A04`, а заголовки → `A02`. Правильные соответствия для этих классов: TLS/шифрование → `A02:2021`, конфигурация и заголовки → `A05:2021`, раскрытие технологий → `A01`/`A05` как информационное. Категория выводится из `confirmation_class`/CWE по явной таблице, а не эвристикой. `null` допустим, но тогда в отчёте печатается «не сопоставлено», а не пустая ячейка. Формат кода единый: `A05:2021` везде, включая четвёрку.
2. **CVSS** (`C-20`). Балл без вектора не публикуется как CVSS: либо есть вектор и версия, либо поле `severity_basis: "heuristic"` и явная пометка «оценка без вектора». `0.0` → `null`. Обоснование метрик вектора — обязательное поле для `severity >= medium`.
3. **Дискриминатор по классу** (`C-21`). `poc.discriminator` заполняется из таблицы правил класса находки (фаза J связанного документа). `http_reflection` для CWE-693 — ошибка маппинга; для отсутствующих заголовков дискриминатор — «в финальном ответе (после редиректов, код 2xx) отсутствуют заголовки X, Y, Z», и обязателен негативный контроль в виде ответа, где они присутствуют.
4. **Недостижимость цели — это ограничение, а не доказательство** (`C-22`). Ответ `HTTP 530` от Cloudflare Tunnel означает, что origin недоступен. Правило: ответ с кодом `5xx` от инфраструктурного слоя не может служить доказательством свойств приложения. Находка, чей единственный PoC — такой ответ, получает `verification_status: inconclusive`, `downgrade_reason: "target_unreachable_during_test"`, CVSS обнуляется, и в `limitations` добавляется запись о недоступности цели в окне тестирования.
5. **Целостность evidence** (`C-23`). Заполнить `sha256`, `size`, `mime`, `collected_at_utc`, `collector`, `producer_tool_run_id`, `chain_hash`. Ввести короткие непрозрачные `evidence_id` (`E-001`…) отдельно от `object_key`. Псевдо-ID `tool:*` / `recon:*` перенести в поле `producer_hint` и не считать доказательством; находка только с ними — не выше `suspected`.
6. **Связь с запуском** (`C-24`). `tool_run_id` обязателен для инструментальных находок. Заполнить `argv` (обезличенный), `exit_code`, `parser_status`, `raw_artifact_ref`, `source_ip` в `tool_runs`.
7. **Цепочки** (`C-30`). Одношаговая «цепочка», повторяющая находку, не создаётся. Раздел цепочек либо содержит реальные многошаговые пути с evidence на каждом переходе, либо честную запись об их отсутствии. `to_verify` — не литеральная инструкция из шаблона, а конкретный перечень того, что нужно проверить.
8. **Связь severity → находки** (`C-31`). В таблице распределения severity колонка со списком `finding_id`, а не `—`.

---

## 10. ФАЗА 8 — LLM

`C-32`…`C-36` повторяют дефекты предыдущей итерации. Действия — в фазах S (диагностика) и T (валидация выхода) связанного документа. Кратко, что обязательно закрыть здесь:

1. Выяснить и **сохранить** причину `llm_analysis_status: failed`; `errors[]` не может быть пустым при `failed`.
2. Снять утечку плейсхолдеров: секция, содержащая `[Layer]`, `[Config/file]`, `[specific value]`, `[curl command]`, не публикуется.
3. Исправить маппинг секций: `remediation_step` не содержит executive summary, `prioritization_roadmap` не содержит текст рекомендаций.
4. Убрать дублирование блока «Remediation Stages».
5. План устранения строится по находкам из реестра, с их реальными ID; находка из валидированного реестра не может отсутствовать в плане.
6. Числа в LLM-тексте подставляются приложением, а не генерируются моделью.

---

## 11. ФАЗА 9 — Гейты паритета «4 + 1»

Существующий гейт слишком слабый, и это видно по коду. `src/reports/canonical_bundle.py:150` задаёт `REQUIRED_CANONICAL_FORMATS = ("json", "md", "xml", "html")` — ровно наша четвёрка, — а `assert_canonical_parity` (строка 153) проверяет **только два условия**: все требуемые форматы присутствуют и у них одинаковый `snapshot_hash`. Содержание не сравнивается вообще, и PDF в проверку не входит. Поэтому `C-01`…`C-09` прошли мимо. Расширить:

| Проверка | Ловит |
|---|---|
| Число находок одинаково в JSON, MD, XML, HTML **и** в PDF | `C-02`, `C-03` |
| Набор `finding_id` идентичен во всех форматах | |
| `severity`, `verification_status`, `cvss_score`, `owasp_category` каждой находки идентичны во всех форматах | `C-08` |
| Распределение severity в тексте, в таблице и на обложке — из одного вычисления | `C-03` |
| Число `unconfirmed_observations` одинаково во всех форматах | `C-04` |
| Наличие/отсутствие цепочек согласовано | `C-06` |
| Значение покрытия WSTG одинаково во всех вхождениях, включая текст LLM | `C-07` |
| Набор заголовков секций одинаков в MD и HTML | |
| Каждое непустое поле JSON имеет непустое соответствие в XML | `C-26` |
| В комплекте ровно один PDF | `C-01` |
| Ни один клиентский формат не содержит `tenant_id`, `object_key` или внутренний путь | `C-29` |

Гейт блокирующий: несоответствие не переводит релиз в `ready`.

---

## 12. ФАЗА 10 — Тесты

**Паритет и счётчики:**
`test_finding_count_parity_json_md_xml_html_pdf`, `test_finding_id_set_identical_across_formats`, `test_severity_distribution_single_source`, `test_unconfirmed_count_parity`, `test_wstg_coverage_single_value`, `test_exactly_one_pdf_in_bundle`, `test_owasp_category_identical_across_formats`.

**Контейнеры v2:**
`test_claims_populated_for_medium_and_above`, `test_limitations_nonempty_when_gate_failed`, `test_test_executions_nonempty_when_coverage_present`, `test_methodology_always_present`, `test_surface_inventory_not_host_only`, `test_passport_required_fields_not_empty`, `test_generation_status_not_unknown_in_release`.

**JSON:**
`test_json_matches_published_schema`, `test_json_key_order_deterministic`, `test_canonical_payload_byte_stable`, `test_null_vs_not_applicable_vs_unknown_distinct`, `test_cvss_zero_is_null`, `test_no_internal_paths_in_client_json`.

**XML:**
`test_xml_has_namespace_and_validates_against_xsd`, `test_xml_field_parity_with_json`, `test_xml_nil_vs_absent_semantics`, `test_xml_parser_rejects_external_entities`, `test_xml_is_not_junit`.

**Markdown:**
`test_md_no_empty_backtick_pairs` (регресс на `C-27`), `test_md_escapes_pipes_and_backticks`, `test_md_card_structure_matches_layout`, `test_md_omits_not_assessed_fields`, `test_md_limitations_not_none_when_present`.

**HTML:**
`test_html_is_self_contained_no_external_refs`, `test_html_escapes_script_in_poc`, `test_html_section_set_equals_md`, `test_html_has_toc_and_anchors`, `test_html_print_css_has_no_flex_containers`.

**Семантика:**
`test_owasp_mapping_table_covers_known_classes` (параметризованный: TLS→A02, headers→A05), `test_cvss_score_requires_vector_or_marked_heuristic`, `test_discriminator_matches_finding_class`, `test_5xx_infrastructure_response_downgrades_to_inconclusive` (регресс на `C-22`), `test_evidence_reference_has_hash_and_timestamp`, `test_pseudo_evidence_moved_to_producer_hint`, `test_finding_requires_tool_run_link`, `test_single_step_chain_not_emitted`, `test_severity_table_lists_finding_ids`.

**LLM:**
`test_errors_populated_when_llm_failed`, `test_prompt_placeholder_leak_blocked`, `test_ai_section_keys_not_swapped`, `test_remediation_stages_not_duplicated`, `test_plan_covers_validated_registry_findings`, `test_numbers_in_llm_text_are_substituted_not_generated`.

Сквозной сценарий: фикстура, воспроизводящая разобранную выгрузку (9 находок, покрытие 2%, цель отвечает 530, LLM недоступна, evidence без хешей), проходит конвейер и **не выпускается как готовый релиз** — вместо этого выдаётся honest draft с перечнем ровно тех нарушений, что перечислены в `C-01`…`C-36`.

---

## 13. Критерии приёмки

- [ ] Регресс-тесты `C-01`…`C-36` зелёные.
- [ ] В комплекте один PDF; legacy-генератор Valhalla выведен из обязательного набора и из UI.
- [ ] Число находок, набор ID, severity, `verification_status`, CVSS и OWASP совпадают в `.json`, `.md`, `.xml`, `.html` и PDF.
- [ ] Распределение severity считается в одном месте; трёх разных наборов чисел на странице быть не может.
- [ ] `unconfirmed_observations`, `conclusions`, `limitations`, `test_executions`, `methodology`, `attack_narrative`, `tested_capabilities`, `claims`, `surface_inventory` наполнены; пустой обязательный контейнер блокирует выпуск.
- [ ] Паспорт снапшота заполнен; `generation_status` и `evidence_integrity` не `unknown` в выпущенном артефакте.
- [ ] Опубликованы `valhalla_report_v2.schema.json` и `valhalla_report_v2.xsd`; JSON и XML валидируются против них в CI.
- [ ] XML имеет namespace, различает `nil` и «отсутствует», не теряет поля относительно JSON, валидируется парсером без внешних entity.
- [ ] Markdown без артефактов разметки, с карточками по эталонному макету, без `not_assessed`-простыней.
- [ ] HTML self-contained, с оглавлением и якорями, экранирует payload, имеет тот же набор секций, что MD, и печатается без flex-контейнеров.
- [ ] OWASP-категории семантически корректны и записаны единым форматом `Axx:2021`; CVSS-балл публикуется только с вектором либо помечен как эвристический.
- [ ] Ответ `5xx` от инфраструктурного слоя переводит находку в `inconclusive` с `downgrade_reason` и добавляет запись в `limitations`.
- [ ] `evidence_references` содержат `sha256`, время, производителя и размер; клиентские форматы не содержат `tenant_id`, `object_key` и внутренних путей.
- [ ] Одношаговые «цепочки» не создаются.
- [ ] `llm_analysis_status: failed` сопровождается непустым `errors[]`; плейсхолдеры промта, перепутанные секции и дубли блоков не публикуются.
- [ ] `ruff check src/`, `black --check src/`, `bandit -r src/` чисты; существующие тесты не сломаны.
- [ ] Обновлены `docs/reporting.md`, `docs/report-service.md`, `CHANGELOG.md`.

---

## 14. Порядок работы

1. Прочитай связанный документ `CURSOR_VALHALLA_REPORT_FIX_PROMPT.md` — разделы 13–32 (контракт доказуемости, PoC-дисциплина, эталонный макет, диагностика LLM, стоп-лист артефактов промта).
2. Прочитай код: `src/reports/report_document.py` (схема `v2`), `snapshot_builder.py`, `canonical_bundle.py` (`assert_canonical_parity`), `renderers/{json,markdown,xml,html}_renderer.py`, `valhalla_completeness.py`, `report_pipeline.py`, `report_service.py`, `generators.py` (legacy-путь PDF), `templates/reports/valhalla*.j2`, `llm_remediation/` (образец namespace и XSD).
3. Положи рядом разобранную выгрузку `c8042766-…` — раздел 2 цитирует из неё конкретные значения. При расхождении с твоей копией сообщи, а не подгоняй код под описание.
4. Выполняй фазы 1 → 10 по порядку. Фаза 1 (один отчёт вместо двух) первая: пока в комплекте два конкурирующих PDF, любые правки четвёрки будут сравниваться с недостоверным эталоном.
5. Каждая фаза — отдельный коммит с зелёными тестами.
6. Не создавай пятый путь генерации. В репозитории уже было два цикла удаления мёртвого кода (`2c13fa8`, `80614cf`) — двигайся в ту же сторону: один снапшот, один набор рендереров.
