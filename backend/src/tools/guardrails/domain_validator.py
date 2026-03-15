"""DomainValidator — blocks localhost, .local and similar."""

import re


class DomainValidator:
    """Validates domain names; blocks localhost and .local."""

    BLOCKED_PATTERNS = (
        r"^localhost$",
        r"^localhost\.localdomain$",
        r"\.local$",
        r"^127\.\d+\.\d+\.\d+$",
        r"^\[?::1\]?$",
        r"^0\.0\.0\.0$",
    )

    _compiled = None

    @classmethod
    def _get_patterns(cls) -> list[re.Pattern]:
        if cls._compiled is None:
            cls._compiled = [re.compile(p, re.IGNORECASE) for p in cls.BLOCKED_PATTERNS]
        return cls._compiled

    @classmethod
    def is_blocked(cls, value: str) -> bool:
        """
        Return True if domain/host is blocked (localhost, .local, etc.).
        """
        if not value or not isinstance(value, str):
            return False

        host = cls._extract_host(value)
        if not host:
            return False

        host = host.lower().strip()

        for pattern in cls._get_patterns():
            if pattern.search(host):
                return True

        return False

    @staticmethod
    def _extract_host(value: str) -> str | None:
        """Extract hostname from URL or plain host."""
        value = value.strip()
        if not value:
            return None

        if "://" in value:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(value)
                host = parsed.hostname or parsed.netloc.split(":")[0]
                return host or value
            except Exception:
                return value

        if ":" in value and not value.startswith("["):
            return value.split(":")[0]
        return value
