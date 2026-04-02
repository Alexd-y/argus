# Fix Valhalla Report Quality

> Вставь этот промпт в Cursor Agent (claude-sonnet или gpt-4o) с включённым доступом к кодовой базе.

---

## Контекст задачи

В проекте ARGUS есть tier отчёта `valhalla` (leadership_technical).
Отчёт генерируется Python-бэкендом (`backend/`), шаблоны — Jinja2.
AI-секции вызываются отдельными LLM-промптами и вставляются в `<div class="ai-slot-body">` как сырой текст.

Нужно исправить **6 проблем** в порядке приоритета.

---

## Проблема 1 — КРИТИЧЕСКАЯ: Markdown не рендерится в HTML

**Симптом:** В секциях Executive Summary, Threat Modeling, Remediation, Zero-day виден сырой Markdown:
`**Low Security Posture**: The assessment...`, `### Scenario 1:...`

**Что найти:**
- Найди все места, где AI-текст вставляется в Jinja2-шаблон в `div.ai-slot-body`
- Найди функцию/helper, которая формирует содержимое этих div-ов

**Что сделать:**

Вариант A — конвертировать Markdown → HTML перед вставкой в шаблон (предпочтительно):
```python
# Добавить зависимость: pip install markdown
import markdown as md_lib

def render_ai_slot(text: str) -> str:
    """Convert markdown AI output to safe HTML for report slots."""
    if not text or not text.strip():
        return ""
    html = md_lib.markdown(
        text,
        extensions=["extra", "nl2br"],
        output_format="html"
    )
    return html
```
Затем в Jinja2-шаблоне заменить:
```jinja2
{# БЫЛО: #}
<div class="ai-slot-body">{{ ai_text }}</div>

{# СТАЛО: #}
<div class="ai-slot-body">{{ ai_text | render_ai_slot | safe }}</div>
```
Зарегистрировать фильтр в Jinja2 Environment.

Вариант B — если шаблон рендерится на стороне клиента (JS):
Подключить `marked.js` или `showdown.js` и конвертировать `innerHTML` всех `.ai-slot-body` при загрузке страницы.

**Проверить:** CSS для `.ai-slot-body` сейчас содержит `white-space: pre-wrap` — убрать или сделать условным после перехода на HTML-рендер.

---

## Проблема 2 — КРИТИЧЕСКАЯ: Дублирование findings

**Симптом:** Finding `7339b334` и `34ea3d1a` — одна и та же уязвимость (missing security headers). Аналогично `36d1a94b` и `fd35f2f7` — rate limiting. Дубли попадают в Executive Summary, матрицу рисков и счётчики.

**Что найти:**
- Найди модуль/сервис, который агрегирует findings перед генерацией отчёта
- Найди, как генерируются findings типа `web_vuln_heuristics` и `confirmed` — похоже, один finding создаётся инструментом, второй — LLM-эвристикой на основе того же сигнала

**Что сделать:**
```python
from difflib import SequenceMatcher

def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """
    Remove duplicate findings before report generation.
    Two findings are duplicates if they share the same CWE and target URL,
    OR if their titles are >85% similar (handles LLM paraphrase duplicates).
    Keep the one with richer data (non-empty description, PoC, CVSS score).
    """
    seen: list[Finding] = []
    for candidate in findings:
        is_dup = False
        for existing in seen:
            # Hard dedup: same CWE + same affected URL
            same_cwe = candidate.cwe and candidate.cwe == existing.cwe
            same_url = _normalize_url(candidate.affected_url) == _normalize_url(existing.affected_url)
            if same_cwe and same_url:
                is_dup = True
                # Keep the richer one
                if _richness_score(candidate) > _richness_score(existing):
                    seen.remove(existing)
                    seen.append(candidate)
                break
            # Soft dedup: similar titles
            ratio = SequenceMatcher(None, candidate.title.lower(), existing.title.lower()).ratio()
            if ratio > 0.85:
                is_dup = True
                if _richness_score(candidate) > _richness_score(existing):
                    seen.remove(existing)
                    seen.append(candidate)
                break
        if not is_dup:
            seen.append(candidate)
    return seen

def _richness_score(f: Finding) -> int:
    score = 0
    if f.description: score += 2
    if f.poc: score += 3
    if f.cvss and f.cvss > 0: score += 1
    if f.cwe: score += 1
    return score
```
Вызвать `deduplicate_findings()` в pipeline до передачи данных в генератор отчёта.

---

## Проблема 3 — КРИТИЧЕСКАЯ: CVSS/Severity несоответствие не валидируется

**Симптом:** Finding `7339b334` имеет CVSS **7.2** но severity = `low`. CVSS 7.0–8.9 = High по стандарту.

**Что найти:**
- Найди модель Finding (Pydantic) и место, где severity назначается

**Что сделать:**
```python
CVSS_TO_SEVERITY = {
    (0.0, 0.0): "info",
    (0.1, 3.9): "low",
    (4.0, 6.9): "medium",
    (7.0, 8.9): "high",
    (9.0, 10.0): "critical",
}

def normalize_severity_from_cvss(severity: str, cvss: float | None) -> str:
    """
    If CVSS score contradicts the assigned severity, log a warning and
    return the CVSS-derived severity. Original severity is preserved as
    'severity_override' for audit trail.
    """
    if cvss is None:
        return severity
    for (low, high), expected in CVSS_TO_SEVERITY.items():
        if low <= cvss <= high:
            if expected != severity:
                logger.warning(
                    f"Severity mismatch: assigned={severity}, "
                    f"cvss={cvss} implies={expected}. Using CVSS-derived."
                )
            return expected
    return severity
```
Вызвать при парсинге/нормализации findings, до записи в БД или передачи в отчёт.

---

## Проблема 4 — ВЫСОКАЯ: "unknown finding" с пустыми полями попадает в отчёт

**Симптом:** Finding `80bf6b14` — title=`"unknown finding"`, description=`""`, без CWE/OWASP/CVSS — засоряет таблицу findings, матрицу рисков и счётчики.

**Что найти:**
- Найди валидацию/фильтрацию findings перед включением в отчёт

**Что сделать:**
```python
def is_valid_finding_for_report(f: Finding) -> bool:
    """Filter out degenerate/incomplete findings before report generation."""
    if not f.title or f.title.strip().lower() in ("unknown finding", "unknown", ""):
        return False
    if not f.description or len(f.description.strip()) < 10:
        return False
    return True

# В pipeline отчёта:
findings_for_report = [f for f in all_findings if is_valid_finding_for_report(f)]
```

---

## Проблема 5 — ВЫСОКАЯ: AI-секции повторяют одно и то же содержимое

**Симптом:** Секции "Zero-day потенциал", "Дорожная карта", "Threat Modeling" содержат одинаковый пересказ findings вместо специфичного анализа. Zero-day секция вообще не анализирует zero-day потенциал.

**Что найти:**
- Найди промпты для каждой AI-секции (скорее всего в файлах типа `prompts.py`, `ai_slots.py` или константах рядом с генератором отчёта)

**Что сделать — переписать промпты для каждой секции:**

**Executive Summary промпт:**
```
You are a senior penetration tester writing an executive summary for a security report.
Write in {language}. Do NOT use Markdown formatting (no **, no ##, no -).
Write plain prose paragraphs only.

Data:
- Total findings: {total_count} ({severity_breakdown})
- Findings: {findings_summary}
- OWASP gaps: {owasp_gaps}

Write 3–4 paragraphs:
1. Overall security posture assessment (1 sentence verdict)
2. Most significant findings and their business impact
3. What was NOT found (scope confirmation)
4. Immediate priority actions

Be specific. Do NOT repeat finding IDs or technical details verbatim — synthesize.
```

**Threat Modeling промпт:**
```
You are a threat modeling expert. Write in {language}. Plain prose, no Markdown.

Given these confirmed vulnerabilities on {target_url}:
{findings_detail}

And this threat context: {threat_model_context}

Describe 2–3 realistic attack CHAINS (not individual vulnerabilities):
- Each chain must combine multiple findings or weaknesses
- Name a realistic attacker persona (opportunistic scanner / targeted attacker / insider)
- Estimate likelihood (Low/Medium/High) with reasoning
- Describe the damage scenario if the chain succeeds

If threat_model_context is empty, acknowledge the limited recon data and base scenarios on findings alone.
Do NOT summarize individual findings — the reader already has the findings table.
```

**Zero-day потенциал промпт:**
```
You are a vulnerability researcher. Write in {language}. Plain prose, no Markdown.

Review these findings for zero-day or novel exploitation potential:
{findings_detail}

Answer specifically:
1. Do any findings suggest non-standard attack surfaces that standard scanners miss?
2. Are there chaining opportunities that could elevate low-severity findings to critical impact?
3. What additional manual testing would be highest-value given this attack surface?
4. Assign a zero-day potential rating: None / Low / Medium / High with a one-sentence justification.

Be honest if the findings are standard and zero-day potential is low.
Do NOT repeat the findings list.
```

**Remediation промпт:**
```
You are a DevSecOps engineer writing a remediation plan. Write in {language}. Plain prose, no Markdown.

Findings to remediate (deduplicated):
{deduplicated_findings}

Write a prioritized remediation plan with 3 tiers:
1. Fix immediately (within 48 hours): findings with confirmed exploit or CVSS >= 7.0
2. Fix within 2 weeks: medium-priority findings
3. Architectural / SDLC improvements: structural issues

For each item specify: what to change, where (file/config/service), and how to verify the fix.
Reference finding IDs. Do NOT invent findings not in the list above.
```

---

## Проблема 6 — СРЕДНЯЯ: MinIO presigned links указывают на внутренний хост

**Симптом:** Все ссылки в разделе "Сырые артефакты" ведут на `http://minio:9000` — internal Docker hostname, недоступный снаружи.

**Что найти:**
- Найди генерацию presigned URLs для MinIO в `backend/`

**Что сделать:**
```python
import os
from urllib.parse import urlparse, urlunparse

def rewrite_minio_url_for_report(presigned_url: str) -> str:
    """
    Replace internal MinIO hostname with public-facing URL for report delivery.
    Falls back to original if env var not set (development mode).
    """
    public_base = os.environ.get("MINIO_PUBLIC_URL")  # e.g. "https://storage.example.com"
    if not public_base:
        return presigned_url  # dev mode: keep internal URL
    parsed = urlparse(presigned_url)
    public_parsed = urlparse(public_base)
    rewritten = parsed._replace(
        scheme=public_parsed.scheme,
        netloc=public_parsed.netloc
    )
    return urlunparse(rewritten)
```
Добавить переменную окружения `MINIO_PUBLIC_URL` в `docs/env-vars.md` и `infra/`.

---

## Порядок реализации

1. **Проблема 1** (Markdown рендер) — визуальный эффект максимальный, правка минимальная
2. **Проблема 2** (дедупликация) — влияет на счётчики, OWASP таблицу, все AI-секции
3. **Проблема 4** (unknown finding) — чистка мусора, 5 минут
4. **Проблема 3** (CVSS/severity) — корректность данных
5. **Проблема 5** (AI промпты) — самая объёмная, делать после того как данные чистые
6. **Проблема 6** (MinIO URLs) — конфигурационная, не блокирующая

## После правок — что проверить

```bash
# Запустить существующие тесты
pytest tests/ -v

# Сгенерировать тестовый отчёт Valhalla и проверить:
# 1. В ai-slot-body нет ** и ## символов
# 2. Количество findings = количеству уникальных уязвимостей (не дублей)
# 3. CVSS 7.x findings не имеют severity=low
# 4. Нет finding с title="unknown finding"
# 5. Presigned links не содержат "minio:9000" в prod-режиме
```
