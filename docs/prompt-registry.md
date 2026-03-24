# ARGUS Prompt Registry

**Version:** 0.1  
**Source:** `backend/src/orchestration/prompt_registry.py`, `ai_prompts.py`

---

## 1. Overview

Централизованный реестр промптов и JSON-схем для LLM-фаз оркестрации сканирования. Все промпты проходят санитизацию для снижения риска prompt injection.

---

## 2. Структура

```
src/orchestration/
├── prompt_registry.py   # PHASE_PROMPTS, PHASE_SCHEMAS, get_prompt, get_fixer_prompt, get_schema
└── ai_prompts.py        # ai_recon, ai_threat_modeling, ai_vuln_analysis, ai_exploitation,
                         # ai_post_exploitation, ai_reporting — вызов LLM с retry/fixer
```

**Константы фаз** (соответствуют `ScanPhase`):

| Phase | Константа |
|-------|-----------|
| recon | `RECON` |
| threat_modeling | `THREAT_MODELING` |
| vuln_analysis | `VULN_ANALYSIS` |
| exploitation | `EXPLOITATION` |
| post_exploitation | `POST_EXPLOITATION` |
| reporting | `REPORTING` |

---

## 3. Промпты по фазам

### 3.0a — `active_scan_planning` (VA / sandbox)

Используется **не** как ключ в `PHASE_PROMPTS`, а напрямую в `plan_active_scan_with_ai` (`src/recon/vulnerability_analysis/active_scan_planner.py`) при `VA_AI_PLAN_ENABLED=true`.

| Константа | Назначение |
|-----------|------------|
| `ACTIVE_SCAN_PLANNING_SYSTEM` | Системное сообщение: только JSON-массив объектов `{tool, args}`; allowlist инструментов (dalfox, xsstrike, ffuf, sqlmap, nuclei, gobuster, wfuzz, commix). |
| `ACTIVE_SCAN_PLANNING_USER_TEMPLATE` | User-часть с плейсхолдером `{bundle_summary_json}` — сжатый контекст бандла (см. `build_active_scan_bundle_summary`). |
| `build_active_scan_planning_user_prompt(summary)` | Сборка user-prompt с санитизацией JSON. |
| `ACTIVE_SCAN_PLANNING_JSON_ARRAY_FIXER_USER` | Fixer, если ответ не распарсился как JSON-массив. |

Запрос/ответ LLM дополнительно сохраняются в MinIO (`ai_active_scan_planning_request` / `ai_active_scan_planning_response`, фаза `vuln_analysis`).

### 3.1 Базовый системный промпт

```
You are a security pentest AI assistant. Respond only with valid JSON.
No markdown, no explanation, only the JSON object.
```

### 3.2 Фаза RECON

**Шаблон user prompt:** `Given pentest target: {target}. Options: {options}. Return JSON: {"assets": ["string"], "subdomains": ["string"], "ports": [number]}.`

**Плейсхолдеры:** `target`, `options`

### 3.3 Фаза THREAT_MODELING

**Шаблон user prompt:** `Given assets: {assets}. Return JSON: {"threat_model": {"threats": ["string"], "attack_surface": ["string"]}}.`

**Плейсхолдеры:** `assets`

### 3.4 Фаза VULN_ANALYSIS

**Шаблон user prompt:** `Given threat_model: {threat_model}, assets: {assets}. Return JSON: {"findings": [{"severity": "string", "title": "string", "cwe": "string"}]}}.`

**Плейсхолдеры:** `threat_model`, `assets`

### 3.5 Фаза EXPLOITATION

**Шаблон user prompt:** `Given findings: {findings}. Return JSON: {"exploits": [{"finding_id": "string", "status": "attempted", "title": "string"}], "evidence": [{"type": "string", "path": "string", "finding_id": "string"}]}}.`

**Плейсхолдеры:** `findings`

### 3.6 Фаза POST_EXPLOITATION

**Шаблон user prompt:** `Given exploits: {exploits}. Return JSON: {"lateral": [], "persistence": [{"type": "string", "description": "string"}]}}.`

**Плейсхолдеры:** `exploits`

### 3.7 Фаза REPORTING

**Шаблон user prompt:** `Given pentest summary: {summary}. Return JSON: {"report": {"summary": {"critical": 0, "high": 0, "medium": 0}, "sections": ["string"], "ai_insights": ["string"]}}}.`

**Плейсхолдеры:** `summary`

---

## 4. JSON-схемы по фазам

### RECON_SCHEMA

```json
{
  "type": "object",
  "required": ["assets", "subdomains", "ports"],
  "properties": {
    "assets": {"type": "array", "items": {"type": "string"}},
    "subdomains": {"type": "array", "items": {"type": "string"}},
    "ports": {"type": "array", "items": {"type": "integer"}}
  }
}
```

### THREAT_MODEL_SCHEMA

```json
{
  "type": "object",
  "required": ["threat_model"],
  "properties": {
    "threat_model": {
      "type": "object",
      "properties": {
        "threats": {"type": "array", "items": {"type": "string"}},
        "attack_surface": {"type": "array", "items": {"type": "string"}}
      }
    }
  }
}
```

### VULN_ANALYSIS_SCHEMA

```json
{
  "type": "object",
  "required": ["findings"],
  "properties": {
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "severity": {"type": "string"},
          "title": {"type": "string"},
          "cwe": {"type": "string"}
        }
      }
    }
  }
}
```

### EXPLOITATION_SCHEMA

```json
{
  "type": "object",
  "required": ["exploits", "evidence"],
  "properties": {
    "exploits": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "finding_id": {"type": "string"},
          "status": {"type": "string"},
          "title": {"type": "string"}
        }
      }
    },
    "evidence": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "type": {"type": "string"},
          "path": {"type": "string"},
          "finding_id": {"type": "string"}
        }
      }
    }
  }
}
```

### POST_EXPLOITATION_SCHEMA

```json
{
  "type": "object",
  "required": ["lateral", "persistence"],
  "properties": {
    "lateral": {"type": "array", "items": {"type": "object"}},
    "persistence": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "type": {"type": "string"},
          "description": {"type": "string"}
        }
      }
    }
  }
}
```

### REPORTING_SCHEMA

```json
{
  "type": "object",
  "required": ["report"],
  "properties": {
    "report": {
      "type": "object",
      "properties": {
        "summary": {
          "type": "object",
          "properties": {
            "critical": {"type": "integer"},
            "high": {"type": "integer"},
            "medium": {"type": "integer"}
          }
        },
        "sections": {"type": "array", "items": {"type": "string"}},
        "ai_insights": {"type": "array", "items": {"type": "string"}}
      }
    }
  }
}
```

---

## 5. Retry и Fixer-промпты

### 5.1 Логика retry

В `ai_prompts.py`:

- `MAX_JSON_RETRIES = 1` — одна дополнительная попытка при невалидном JSON
- `_call_llm_with_json_retry` вызывает LLM, парсит ответ; при `JSONDecodeError` — retry с fixer-промптом

### 5.2 Fixer-промпт

**Системный промпт:**

```
You are a JSON repair assistant. The previous response contained invalid JSON.
Return ONLY the corrected JSON object, nothing else. No markdown, no explanation.
```

**User-промпт (шаблон):**

```
The following response is invalid JSON. Fix it to match this schema.

Expected schema:
{expected_schema}

Invalid response:
{invalid_json}

Return ONLY the corrected JSON object.
```

**API:** `get_fixer_prompt(invalid_json: str, expected_schema: dict) -> tuple[str, str]` — возвращает `(system_prompt, user_prompt)`.

### 5.3 Парсинг JSON из ответа

- Поддержка блоков ` ```json ... ``` ` — извлечение содержимого перед парсингом
- `_parse_llm_json(text)` — возвращает `dict | None`

---

## 6. Санитизация (prompt injection mitigation)

### 6.1 Ограничения длины

| Тип | Макс. длина |
|-----|-------------|
| Строка | `MAX_PROMPT_STRING_LENGTH = 512` |
| Объект (dict/list) | `MAX_PROMPT_OBJECT_LENGTH = 1024` |

### 6.2 Подозрительные паттерны

Перед вставкой в промпт текст обрезается при первом совпадении (case-insensitive):

- `ignore (previous|all|the above|prior) instructions?`
- `ignore everything`
- `disregard (previous|all|instructions?)`
- `you are now`
- `new (instruction|role|persona)`
- `system:`, `assistant:`, `human:`
- `jailbreak`
- `override (instructions?|system)`
- `<|im_end|>`, `<|im_start|>`

### 6.3 Функции

- `_sanitize_for_prompt(text, max_length)` — нормализация пробелов, обрезка по паттернам, truncate
- `_sanitize_kwargs_for_prompt(kwargs)` — санитизация всех kwargs перед `template.format()`

---

## 7. API

| Функция | Описание |
|---------|----------|
| `get_prompt(phase, **kwargs)` | Возвращает `(system_prompt, user_prompt)` с подставленными kwargs |
| `get_schema(phase)` | Возвращает JSON-схему для фазы |
| `get_fixer_prompt(invalid_json, expected_schema)` | Возвращает `(system_prompt, user_prompt)` для retry |

**Исключения:** `ValueError` при неизвестной фазе.
