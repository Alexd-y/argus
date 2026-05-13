# Alembic Migration Chain — Notes

## Migration 018 Gap

Migration `018` is intentionally absent from the chain. The gap was introduced during
**Cycle 4 ARG-031** when the 18/18 ReportService matrix was implemented. The migration
was squashed into the work of migration `019` (`019_reports_table.py`).

**Evidence:**
- Migration `017` has `down_revision = "016"`
- Migration `019` has `revises: 017` — explicitly bridging the gap
- Chain verification (`python scripts/verify_alembic_chain.py`) passes successfully
- All 37 migrations (001→037) form a continuous chain

This is standard Alembic practice: when a migration is squashed or abandoned during
development, subsequent migrations reference the pre-gap revision directly. The gap
does not affect runtime behavior and all database state is correctly captured.
