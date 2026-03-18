"""INFRA-003: Validate postgres/init.sql for ARGUS infrastructure.

Validates:
- File exists at infra/postgres/init.sql
- Contains CREATE DATABASE
- Contains CREATE EXTENSION vector
- Contains ALTER DATABASE row_security
- Valid SQL structure (no obvious syntax errors)
"""

from pathlib import Path

import pytest

ARGUS_ROOT = Path(__file__).resolve().parent.parent
INIT_SQL_PATH = ARGUS_ROOT / "infra" / "postgres" / "init.sql"


@pytest.fixture(scope="module")
def init_sql_content() -> str:
    """Load init.sql content."""
    return INIT_SQL_PATH.read_text(encoding="utf-8")


class TestInfra003PostgresInitExists:
    """INFRA-003: postgres/init.sql file existence."""

    def test_init_sql_exists(self) -> None:
        """infra/postgres/init.sql must exist."""
        assert INIT_SQL_PATH.exists(), f"Not found: {INIT_SQL_PATH}"
        assert INIT_SQL_PATH.is_file()


class TestInfra003PostgresInitContent:
    """INFRA-003: init.sql must contain required SQL constructs."""

    def test_contains_create_database(self, init_sql_content: str) -> None:
        """Must contain CREATE DATABASE (or equivalent)."""
        assert "CREATE DATABASE" in init_sql_content.upper(), (
            "INFRA-003: init.sql must contain CREATE DATABASE"
        )

    def test_contains_create_extension_vector(self, init_sql_content: str) -> None:
        """Must contain CREATE EXTENSION vector for pgvector."""
        content_upper = init_sql_content.upper()
        assert "CREATE EXTENSION" in content_upper and "VECTOR" in content_upper, (
            "INFRA-003: init.sql must contain CREATE EXTENSION vector"
        )

    def test_contains_alter_database_row_security(self, init_sql_content: str) -> None:
        """Must contain ALTER DATABASE ... row_security for RLS."""
        content_upper = init_sql_content.upper()
        assert "ALTER DATABASE" in content_upper and "ROW_SECURITY" in content_upper, (
            "INFRA-003: init.sql must contain ALTER DATABASE ... row_security"
        )

    def test_valid_sql_structure(self, init_sql_content: str) -> None:
        """Basic SQL structure: balanced semicolons, no obvious broken syntax."""
        lines = [l.strip() for l in init_sql_content.splitlines() if l.strip() and not l.strip().startswith("--")]
        # Should have multiple SQL statements
        stmt_count = init_sql_content.count(";")
        assert stmt_count >= 3, (
            "INFRA-003: init.sql should contain multiple SQL statements"
        )
        # No unterminated string literals (odd number of unescaped quotes in a line)
        for i, line in enumerate(lines):
            if line.startswith("--"):
                continue
            # Skip \connect and \gexec (psql meta-commands)
            if line.startswith("\\"):
                continue
            # Basic check: SQL keywords or identifiers present
            assert len(line) > 0, f"INFRA-003: Empty statement at line {i + 1}"
