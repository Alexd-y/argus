# Plan: ARGUS v5-followup-2 — Intel adapters, ExploitDB, tests

**Created:** 2026-04-04  
**Orchestration:** `orch-argus-v5-followup-2`  
**Workspace:** `d:\Developer\Pentest_test\.cursor\workspace\active\orch-argus-v5-followup-2\`  
**Spec:** `ARGUS/argus_v5_followup_2_cursor_prompt.md`  
**Goal:** Реализовать 9 intel-адаптеров (data_sources или httpx), полный `exploitdb_client.py`, `test_intel_adapters.py`, минимальные правки Block 4.  
**Tasks:** 7 (T01–T07, лимит ≤10 соблюдён)

## Предпроверка

- **`GitHubClient`:** есть в `ARGUS/backend/src/data_sources/github_client.py` — отдельная задача на клиент **не требуется**. При ревью: ответ advisories может быть `list` — адаптер обрабатывает по спецификации.

## Маппинг задач → блоки спецификации

| ID | Блок | Содержание |
|----|------|------------|
| **T01** | **1** | `censys_adapter.py`, `securitytrails_adapter.py`, `virustotal_adapter.py` — `CensysClient`, `SecurityTrailsClient`, `VirusTotalClient`. |
| **T02** | **2** | `otx_adapter.py`, `greynoise_adapter.py`, `abuseipdb_adapter.py` — httpx. |
| **T03** | **2** | `urlscan_adapter.py`, `github_adapter.py`, `exploitdb_adapter.py` — httpx / `GitHubClient` / httpx. |
| **T04** | **3** | `exploitdb_client.py` — полная реализация по спеку. |
| **T05** | **4** | `va_orchestrator.py` ~168 — минимальный текст (Step vs Phase по спеку). |
| **T06** | **5** | `test_intel_adapters.py`. |
| **T07** | — | ruff, pytest, при необходимости registry / `.env.example`. |

## Зависимости

```
T01,T02,T03,T04,T05 → T06 → T07
```

Статусы: `.cursor/workspace/active/orch-argus-v5-followup-2/tasks.json`.
