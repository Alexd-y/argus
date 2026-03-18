"""INFRA-002: Validate .env.example for ARGUS infrastructure.

Validates:
- File exists at infra/.env.example
- Required keys: POSTGRES_*, REDIS_*, MINIO_*, DATABASE_URL, JWT_SECRET, LLM keys
- No real secrets (placeholders only)
"""

import re
from pathlib import Path

import pytest

ARGUS_ROOT = Path(__file__).resolve().parent.parent
ENV_EXAMPLE_PATH = ARGUS_ROOT / "infra" / ".env.example"

# Required key prefixes/names per INFRA-002
REQUIRED_POSTGRES_KEYS = ["POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_PORT"]
REQUIRED_REDIS_KEYS = ["REDIS_PORT", "REDIS_PASSWORD", "REDIS_URL"]
REQUIRED_MINIO_KEYS = [
    "MINIO_ROOT_USER",
    "MINIO_ROOT_PASSWORD",
    "MINIO_ACCESS_KEY",
    "MINIO_SECRET_KEY",
    "MINIO_BUCKET",
    "MINIO_ENDPOINT",
]
REQUIRED_OTHER_KEYS = ["DATABASE_URL", "JWT_SECRET"]
REQUIRED_LLM_KEYS = [
    "OPENAI_API_KEY",
    "DEEPSEEK_API_KEY",
    "OPENROUTER_API_KEY",
    "GOOGLE_API_KEY",
    "KIMI_API_KEY",
    "PERPLEXITY_API_KEY",
]

# Patterns that indicate real secrets (must NOT appear in .env.example)
FORBIDDEN_SECRET_PATTERNS = [
    (r"sk-[a-zA-Z0-9]{20,}", "OpenAI-style API key (sk-...)"),
    (r"sk-proj-[a-zA-Z0-9]{20,}", "OpenAI project key"),
    (r"[a-f0-9]{64}", "64-char hex (likely real secret)"),
    (r"Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+", "JWT token"),
]


def _parse_env_content(content: str) -> dict[str, str]:
    """Parse KEY=VALUE pairs from env file, ignoring comments and empty lines."""
    result: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            result[key.strip()] = value.strip()
    return result


@pytest.fixture(scope="module")
def env_content() -> str:
    """Load .env.example content."""
    return ENV_EXAMPLE_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def env_vars(env_content: str) -> dict[str, str]:
    """Parse .env.example into key-value dict."""
    return _parse_env_content(env_content)


class TestInfra002EnvExampleExists:
    """INFRA-002: .env.example file existence."""

    def test_env_example_exists(self) -> None:
        """infra/.env.example must exist."""
        assert ENV_EXAMPLE_PATH.exists(), f"Not found: {ENV_EXAMPLE_PATH}"
        assert ENV_EXAMPLE_PATH.is_file()


class TestInfra002EnvExampleRequiredKeys:
    """INFRA-002: All required keys must be present."""

    @pytest.mark.parametrize("key", REQUIRED_POSTGRES_KEYS)
    def test_postgres_keys_present(self, env_vars: dict[str, str], key: str) -> None:
        """POSTGRES_* keys must be defined."""
        assert key in env_vars, f"INFRA-002: Missing required key {key}"

    @pytest.mark.parametrize("key", REQUIRED_REDIS_KEYS)
    def test_redis_keys_present(self, env_vars: dict[str, str], key: str) -> None:
        """REDIS_* keys must be defined."""
        assert key in env_vars, f"INFRA-002: Missing required key {key}"

    @pytest.mark.parametrize("key", REQUIRED_MINIO_KEYS)
    def test_minio_keys_present(self, env_vars: dict[str, str], key: str) -> None:
        """MINIO_* keys must be defined."""
        assert key in env_vars, f"INFRA-002: Missing required key {key}"

    @pytest.mark.parametrize("key", REQUIRED_OTHER_KEYS)
    def test_other_keys_present(self, env_vars: dict[str, str], key: str) -> None:
        """DATABASE_URL and JWT_SECRET must be defined."""
        assert key in env_vars, f"INFRA-002: Missing required key {key}"

    @pytest.mark.parametrize("key", REQUIRED_LLM_KEYS)
    def test_llm_keys_present(self, env_vars: dict[str, str], key: str) -> None:
        """LLM provider keys must be defined (can be empty)."""
        assert key in env_vars, f"INFRA-002: Missing required LLM key {key}"


class TestInfra002EnvExampleNoRealSecrets:
    """INFRA-002: .env.example must not contain real secrets."""

    def test_no_openai_style_keys(self, env_content: str) -> None:
        """No sk-... style API keys (OpenAI)."""
        for pattern, desc in FORBIDDEN_SECRET_PATTERNS:
            matches = re.findall(pattern, env_content)
            assert not matches, (
                f"INFRA-002: .env.example must not contain real secrets. "
                f"Found {desc}: {matches[:3]}"
            )

    def test_jwt_secret_is_placeholder(self, env_vars: dict[str, str]) -> None:
        """JWT_SECRET must be a placeholder, not a real 32-byte hex."""
        jwt = env_vars.get("JWT_SECRET", "")
        # Real secret: 64 hex chars
        real_hex = re.match(r"^[a-f0-9]{64}$", jwt)
        assert not real_hex, (
            "INFRA-002: JWT_SECRET must be placeholder (e.g. use-openssl-rand-hex-32), "
            "not a real 64-char hex"
        )

    def test_postgres_password_is_placeholder(self, env_vars: dict[str, str]) -> None:
        """POSTGRES_PASSWORD must be placeholder."""
        pwd = env_vars.get("POSTGRES_PASSWORD", "")
        assert pwd in ("", "change-me", "placeholder", "your-password"), (
            "INFRA-002: POSTGRES_PASSWORD must be placeholder, not real password"
        )

    def test_redis_password_is_placeholder(self, env_vars: dict[str, str]) -> None:
        """REDIS_PASSWORD must be placeholder."""
        pwd = env_vars.get("REDIS_PASSWORD", "")
        assert pwd in ("", "change-me", "placeholder", "your-password"), (
            "INFRA-002: REDIS_PASSWORD must be placeholder, not real password"
        )
