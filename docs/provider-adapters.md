# ARGUS Provider Adapters

**Version:** 0.1  
**Source:** `backend/src/llm/adapters.py`, `router.py`, `base.py`

---

## 1. Overview

Унифицированный слой адаптеров для LLM-провайдеров. Роутер вызывает первый доступный провайдер; при сбое — fallback на следующий в цепочке.

---

## 2. Архитектура

```
src/llm/
├── base.py      # LLMAdapter (Protocol)
├── adapters.py  # OpenAICompatibleAdapter, GeminiAdapter, get_available_adapters
├── router.py    # call_llm, is_llm_available
├── errors.py    # LLMProviderUnavailableError, LLMAllProvidersFailedError
└── __init__.py
```

**Поток вызова:**

1. `call_llm(prompt, system_prompt=..., model=...)` → `get_available_adapters()`
2. Итерация по адаптерам в порядке приоритета
3. Первый успешный ответ возвращается
4. При ошибке — логирование, переход к следующему
5. Если все провайдеры упали → `LLMAllProvidersFailedError`

---

## 3. Поддерживаемые провайдеры

### 3.1 OpenAI-compatible (единый адаптер)

| Провайдер | Env-ключ | Base URL | Модель по умолчанию |
|-----------|----------|----------|---------------------|
| OpenAI | `OPENAI_API_KEY` | `https://api.openai.com` | `gpt-4o-mini` |
| DeepSeek | `DEEPSEEK_API_KEY` | `https://api.deepseek.com` | `deepseek-chat` |
| OpenRouter | `OPENROUTER_API_KEY` | `https://openrouter.ai/api/v1` | `openai/gpt-4o-mini` |
| Kimi (Moonshot) | `KIMI_API_KEY` | `https://api.moonshot.ai/v1` | `moonshot-v1-8k` |
| Perplexity | `PERPLEXITY_API_KEY` | `https://api.perplexity.ai` | `sonar` |

**Endpoint:** `/v1/chat/completions` (OpenAI Chat Completions API)

**Формат запроса:**

```json
{
  "model": "<model>",
  "messages": [
    {"role": "system", "content": "<system_prompt>"},
    {"role": "user", "content": "<prompt>"}
  ],
  "temperature": 0.3
}
```

### 3.2 Google Gemini

| Провайдер | Env-ключ | Модель по умолчанию |
|-----------|----------|---------------------|
| Gemini | `GOOGLE_API_KEY` | `gemini-1.5-flash` |

**Endpoint:** `https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}`

**Особенности:** system prompt объединяется с user prompt в один текст (Gemini не поддерживает отдельную роль system).

---

## 4. Активация через env

Провайдер считается доступным, если соответствующий env-ключ задан и не пустой.

**Порядок приоритета** (первый настроенный используется первым):

1. OpenAI
2. DeepSeek
3. OpenRouter
4. Kimi
5. Perplexity
6. Gemini

**Пример `.env`:**

```bash
# Один или несколько ключей — достаточно одного для работы AI
OPENAI_API_KEY=sk-...
# DEEPSEEK_API_KEY=...
# OPENROUTER_API_KEY=...
# GOOGLE_API_KEY=...
# KIMI_API_KEY=...
# PERPLEXITY_API_KEY=...
```

---

## 5. API

### 5.1 `is_llm_available() -> bool`

Возвращает `True`, если хотя бы один провайдер настроен.

### 5.2 `call_llm(prompt, *, system_prompt=None, model=None) -> str`

- `prompt` — текст запроса
- `system_prompt` — системный промпт (опционально)
- `model` — переопределение модели (опционально)

**Исключения:**

- `LLMProviderUnavailableError` — ни один провайдер не настроен
- `LLMAllProvidersFailedError` — все провайдеры вернули ошибку

### 5.3 `get_available_adapters() -> list`

Возвращает список адаптеров с настроенными ключами (для внутреннего использования).

---

## 6. Протокол LLMAdapter

```python
class LLMAdapter(Protocol):
    def is_available(self) -> bool: ...
    async def call(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
        model: str | None = None,
    ) -> str: ...
```

---

## 7. Конфигурация

Ключи читаются из `os.environ`. Пустые строки и пробелы считаются «не заданными».

**Таймаут HTTP:** 60 секунд (httpx.AsyncClient).
