# Recon — краткое руководство оператора

**Область:** фаза **`recon`** state machine, backend `src/recon/`, env **`RECON_*`**. Подробная схема фаз: [scan-state-machine.md](./scan-state-machine.md). Переменные Compose: [deployment.md](./deployment.md) § 3.1b, полный список — [`infra/.env.example`](../infra/.env.example).

---

## 1. Режимы

| Режим | Что запускается |
|--------|------------------|
| **passive** | DNS (dig, dns_depth), whois, crt.sh, passive subdomains (subfinder и др. в sandbox при opt-in), Shodan, опционально KAL DNS bundle |
| **active** | passive + nmap (см. цикл KAL/nmap в state machine), **http_surface** (httpx, whatweb, nuclei tech-only), лёгкий fetch manifestов (`dependency_manifests`) |
| **full** | active + опциональные шаги по флагам (см. § 3) |

**Принудительно только passive:** `RECON_PASSIVE_ONLY=true` (перекрывает `RECON_MODE`).

---

## 2. Opt-in шаги (только `RECON_MODE=full`)

| Флаг env | Логический шаг | Инструменты / смысл |
|----------|----------------|---------------------|
| `RECON_ENABLE_CONTENT_DISCOVERY=true` | `content_discovery` | gau, waybackurls, katana; дедуп/скоуп |
| `RECON_JS_ANALYSIS=true` | `js_analysis` | параметры URL, вытягивание JS, linkfinder / unfurl (KAL policy) |
| `RECON_DEEP_PORT_SCAN=true` | `deep_port_scan` | naabu (если включено) + nmap -sV; лимиты `RECON_DEEP_*` |
| `RECON_ASNMAP_ENABLED=true` (default) | `asn_map` | asnmap по apex |
| `RECON_SCREENSHOTS=true` | `screenshots` | gowitness; лимиты `RECON_GOWITNESS_*` |

Пассивный DNS-пакет в sandbox: флаги скана **`kal.recon_dns_enumeration_opt_in`** (и согласованные поля в `scan.options`) + **`SANDBOX_ENABLED=true`**. Категории KAL для JS/скриншотов/ASN — см. `src/recon/mcp/policy.py` и [mcp-server.md](./mcp-server.md).

**Подмножество шагов:** `RECON_TOOL_SELECTION` — csv идентификаторов (`nmap_port_scan`, `dns_depth`, …); алиасы `url_history`, `js_analysis`, `asnmap`, `screenshots`.

---

## 3. Троттлинг и таймауты

- **`RECON_RATE_LIMIT`** (приоритет) или **`RECON_RATE_LIMIT_PER_SECOND`** — ограничение запросов/сек в пайплайне.
- Таймауты инструментов: общие **`RECON_TOOLS_TIMEOUT`** (если заданы в проекте), специализированные **`RECON_*_TIMEOUT_SEC`** — см. `backend/.env.example` и `infra/.env.example`.

---

## 4. MinIO (primary bucket, обычно `MINIO_BUCKET`)

Префикс скана:

```text
{tenant_id}/{scan_id}/recon/raw/
```

Примеры:

- Потоки инструментов: `tool_<name>_stdout`, `tool_<name>_stderr`
- Агрегат пайплайна (стабильное имя): **`recon_summary.json`** (перезапись; RECON-009)
- Прочие типы артефактов (dns_records, скриншоты и т.д.) — по типам, которые выставляет `RawPhaseSink`

Отчётный bucket **`MINIO_REPORTS_BUCKET`** для PDF/HTML/JSON отчётов не смешивать с raw recon.

---

## 5. Сводка для LLM и отчётов

В памяти handler после сбора: `tool_results["recon_pipeline_summary"]` = нормализованный JSON (`_schema_version`, subdomains, ports, URLs, technologies_combined, security headers, …). Он загружается в MinIO как **`recon_summary.json`** и должен оказаться в **`recon_results.json`** (stage1) для **`build_valhalla_report_context`** — см. [reporting.md](./reporting.md) (Valhalla + recon pipeline summary).

---

## 6. Быстрый чеклист перед «тяжёлым» full

1. Право на цель и scope (RoE).
2. `SANDBOX_ENABLED=true` для CLI в sandbox; worker/backend с одинаковым env.
3. Осознанно включить `RECON_DEEP_PORT_SCAN`, `RECON_JS_ANALYSIS`, content discovery (нагрузка на цель и сеть).
4. KAL/opt-in в `scan.options` согласно политике тенанта.
