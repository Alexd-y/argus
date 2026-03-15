"""Redis connection — cache and Celery broker.

Uses redis_url from config. Connection is lazy-initialized.
"""

import logging
from typing import Any

from src.core.config import settings

logger = logging.getLogger(__name__)

_redis_client: Any = None


def get_redis():
    """Lazy-init Redis client. Returns None if redis not available."""
    global _redis_client
    if _redis_client is None:
        try:
            import redis

            _redis_client = redis.from_url(
                settings.redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
            )
        except ImportError as e:
            logger.warning("redis package not installed", extra={"error": str(e)})
            return None
        except Exception as e:
            logger.warning("Redis connection failed", extra={"error": str(e)})
            return None
    return _redis_client


def redis_ping() -> bool:
    """Check Redis connectivity. Returns True if reachable."""
    client = get_redis()
    if not client:
        return False
    try:
        return client.ping()
    except Exception:
        return False
