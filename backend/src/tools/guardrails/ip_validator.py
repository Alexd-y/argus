"""IPValidator — blocks private/loopback IPs (10.x, 172.16-31.x, 192.168.x, 127.x)."""

import ipaddress


class IPValidator:
    """Validates IP addresses; blocks private and loopback ranges."""

    PRIVATE_PREFIXES = (
        "10.",           # 10.0.0.0/8
        "172.16.",       # 172.16.0.0/12 (172.16.x - 172.31.x)
        "172.17.",
        "172.18.",
        "172.19.",
        "172.20.",
        "172.21.",
        "172.22.",
        "172.23.",
        "172.24.",
        "172.25.",
        "172.26.",
        "172.27.",
        "172.28.",
        "172.29.",
        "172.30.",
        "172.31.",
        "192.168.",      # 192.168.0.0/16
        "127.",          # 127.0.0.0/8 loopback
    )

    @classmethod
    def is_private_or_loopback(cls, value: str) -> bool:
        """
        Return True if value is a private or loopback IP.
        Handles: 10.x, 172.16-31.x, 192.168.x, 127.x.
        """
        if not value or not isinstance(value, str):
            return False

        value = value.strip()

        # Extract host from URL if present (e.g. https://192.168.1.1/path -> 192.168.1.1)
        host = cls._extract_host(value)
        if not host:
            return False

        # Quick prefix check for common cases
        for prefix in cls.PRIVATE_PREFIXES:
            if host.startswith(prefix):
                return True

        # Full validation via ipaddress
        try:
            ip = ipaddress.ip_address(host)
            return ip.is_private or ip.is_loopback
        except ValueError:
            pass

        return False

    @staticmethod
    def _extract_host(value: str) -> str | None:
        """Extract hostname or IP from value (URL or plain host)."""
        value = value.strip()
        if not value:
            return None

        # URL-like: http(s)://host or host:port
        if "://" in value:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(value)
                host = parsed.hostname or parsed.netloc.split(":")[0]
                return host or value
            except Exception:
                return value

        # host:port
        if ":" in value and not value.startswith("["):
            return value.split(":")[0]
        return value
