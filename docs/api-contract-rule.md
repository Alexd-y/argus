# ARGUS: Правило API Contract First

## Основное правило

**Frontend — источник истины. Backend реализуется строго по API контрактам. Никаких изменений names/paths/status codes/payload shape без совместимости с frontend.**

## Применение

1. Перед реализацией endpoint — проверить контракт в [api-contracts.md](./api-contracts.md).
2. Изменения API — только после обновления Frontend или явного согласования.
3. Contract tests — проверка совместимости backend с ожиданиями Frontend.

## Референс

- ARGUS/Frontend — основной источник
- test/pentagi/frontend — референс при пустом ARGUS/Frontend

## Документация

- **[api-contracts.md](./api-contracts.md)** — полная таблица REST endpoints, request/response/error schemas
- **[architecture-decisions.md](./architecture-decisions.md)** — ADR, ключевые архитектурные решения
