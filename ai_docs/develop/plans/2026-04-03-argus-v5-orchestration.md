# ARGUS v5 — краткий план оркестрации (2026-04-03)

**Orchestration ID:** `orch-argus-v5`  
**Workspace:** `Pentest_test/.cursor/workspace/active/orch-argus-v5/`  
**Полный план:** `plan.md` в workspace (T01–T10).

## Задачи по порядку

1. **T01** — `scan_knowledge_base.py`, VA orchestrator, `main.py` warm.  
2. **T02** — `tool_recovery.py`, интеграция sandbox + executor, удаление stub.  
3. **T03** — `api/routers/cache.py`, 10 endpoints, `require_admin`.  
4. **T04** — sandbox processes/kill/python.  
5. **T05** — scans memory-summary + report UX без 501.  
6. **T06** — findings PoC/validate/generate.  
7. **T07** — миграция 017.  
8. **T08** — MCP `_build_scan_request` / create_scan.  
9. **T09** — MCP только на существующие routes + `argus-mcp.json` + `.cursor/rules/argus-mcp.md`.  
10. **T10** — тесты KB/recovery/cache + ruff/pytest.

## Отложено (v5-followup)

Полные 150+ явных MCP tools для несуществующих REST-маршрутов; расширенный `test_mcp_tools.py`; доп. эндпоинты из v5 блока 6 (timeline, statistics, …) при отсутствии в текущем цикле.
