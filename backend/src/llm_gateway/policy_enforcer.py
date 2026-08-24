"""LLM Gateway Policy Enforcer — validates JSON policy against request.

Checks: budget caps, compliance flags (airgapped_only, no_cloud_llm_for_source_code),
route limits (max_calls, max_tokens, max_cost), OSINT enablement, token cap enforcement.

Per-role call counters are backed by Redis when available; falls back to in-process dicts.
"""

from typing import Any

from src.llm_gateway.router import PolicyDeniedError

# Per-role accumulated call counters (in-process fallback; Redis preferred).
_role_call_counters: dict[str, dict[str, int]] = {}
# Per-role accumulated token usage.
_role_token_usage: dict[str, dict[str, int]] = {}


def _redis_key(role: str, scan_id: str, field: str) -> str:
    return f"argus:llm:counter:{role}:{scan_id}:{field}"


def _get_redis():
    """Lazy get Redis client. Returns None if unavailable."""
    try:
        from src.core.redis_client import get_redis
        return get_redis()
    except Exception:
        return None


def _ensure_role_ctr(role: str, scan_id: str) -> dict[str, int]:
    key = f"{role}:{scan_id}"
    if key not in _role_call_counters:
        _role_call_counters[key] = {"calls": 0, "input_tokens": 0, "output_tokens": 0}
    return _role_call_counters[key]


def _incr_redis(role: str, scan_id: str, field: str, amount: int = 1) -> int:
    """Atomically increment a Redis counter. Returns new value or -1 on failure."""
    redis_client = _get_redis()
    if redis_client is None:
        return -1
    try:
        key = _redis_key(role, scan_id if scan_id else "global", field)
        new_val = redis_client.incrby(key, amount)
        # Set TTL of 24h so stale counters don't accumulate forever
        redis_client.expire(key, 86400)
        return int(new_val)
    except Exception:
        return -1


def _get_counter(role: str, scan_id: str, field: str) -> int:
    """Get current counter value, trying Redis first, then in-process fallback."""
    val = _incr_redis(role, scan_id, field, 0)  # incrby 0 = read
    if val < 0:
        ctr = _ensure_role_ctr(role, scan_id)
        return ctr.get(field, 0)
    return val


def _record_call(role: str, scan_id: str, input_tokens: int = 0, output_tokens: int = 0) -> None:
    _incr_redis(role, scan_id, "calls", 1)
    if input_tokens:
        _incr_redis(role, scan_id, "input_tokens", input_tokens)
    if output_tokens:
        _incr_redis(role, scan_id, "output_tokens", output_tokens)
    # Always update in-process fallback too
    ctr = _ensure_role_ctr(role, scan_id)
    ctr["calls"] += 1
    ctr["input_tokens"] += input_tokens
    ctr["output_tokens"] += output_tokens


class PolicyEnforcer:
    def evaluate(self, policy: dict[str, Any], request: Any) -> None:
        if not policy:
            return

        compliance = policy.get("compliance", {})
        budget = policy.get("budget", {})
        routing = policy.get("routing", {})
        safety = policy.get("safety", {})
        telemetry = policy.get("telemetry", {})

        model_alias = getattr(request, "model", "")
        metadata = getattr(request, "metadata", {}) or {}
        scan_id = metadata.get("scan_id", policy.get("scan_id", ""))
        content_class = metadata.get("content_class", "")

        # airgapped_only — все cloud провайдеры запрещены
        if compliance.get("airgapped_only"):
            if model_alias not in ("argus-pentest-primary", "argus-code-local", "argus-devsecops-local"):
                raise PolicyDeniedError(
                    "Airgapped mode blocks all cloud providers",
                    {"reason": "airgapped_only_blocks_cloud", "alias": model_alias},
                )

        # no_cloud_llm_for_source_code — запрет cloud для source_code
        if compliance.get("no_cloud_llm_for_source_code") and content_class == "source_code":
            if model_alias != "argus-pentest-primary":
                raise PolicyDeniedError(
                    "Source code cannot be sent to cloud LLM",
                    {"reason": "no_cloud_llm_for_source_code", "alias": model_alias},
                )

        # OSINT enabled check
        osint_cfg = policy.get("osint", {})
        if model_alias == "argus-osint" and not osint_cfg.get("enabled", True):
            raise PolicyDeniedError(
                "OSINT enrichment disabled by policy",
                {"reason": "osint_disabled"},
            )

        # Budget enforcement — only when a budget is explicitly configured.
        # A policy carrying only compliance/routing flags (no ``budget`` key)
        # must not be denied as "budget exhausted"; budget is opt-in and also
        # enforced at runtime by the CostRouter.
        if budget:
            max_cost = budget.get("max_cost_usd", 0)
            if max_cost <= 0:
                raise PolicyDeniedError(
                    "LLM budget exhausted",
                    {"reason": "budget_exceeded", "max_cost_usd": max_cost},
                )

        # Per-role route limits
        role_mapping = {
            "argus-pentest-primary": "pentest",
            "argus-planner-fast": "planner",
            "argus-planner-deep": "planner",
            "argus-code-cloud": "code",
            "argus-code-local": "code",
            "argus-devsecops-local": "devsecops",
            "argus-report": "report",
            "argus-osint": "osint",
        }
        role = role_mapping.get(model_alias, "planner")
        route_cfg = routing.get(role, {})

        if route_cfg.get("local_only") and model_alias != "argus-pentest-primary":
            if not model_alias.startswith("argus-code-local") and not model_alias.startswith("argus-devsecops"):
                raise PolicyDeniedError(
                    f"Route {role} requires local-only provider",
                    {"reason": "local_only_required", "role": role},
                )

        # max_calls enforcement (Redis-backed with in-process fallback)
        max_calls = route_cfg.get("max_calls", 0)
        if max_calls > 0:
            current = max(
                _get_counter(role, scan_id if scan_id else "global", "calls"),
                _ensure_role_ctr(role, scan_id if scan_id else "global").get("calls", 0),
            )
            if current >= max_calls:
                raise PolicyDeniedError(
                    f"Route {role} call limit reached ({current}/{max_calls})",
                    {"reason": "max_calls_exceeded", "role": role, "current": current, "max": max_calls},
                )

    def record_usage(self, policy: dict[str, Any], request: Any, input_tokens: int, output_tokens: int) -> None:
        """Record token/call usage after successful LLM call."""
        role_mapping = {
            "argus-pentest-primary": "pentest",
            "argus-planner-fast": "planner",
            "argus-planner-deep": "planner",
            "argus-code-cloud": "code",
            "argus-code-local": "code",
            "argus-devsecops-local": "devsecops",
            "argus-report": "report",
            "argus-osint": "osint",
        }
        model_alias = getattr(request, "model", "")
        role = role_mapping.get(model_alias, "planner")
        metadata = getattr(request, "metadata", {}) or {}
        scan_id = metadata.get("scan_id", policy.get("scan_id", ""))
        _record_call(role, scan_id if scan_id else "global", input_tokens, output_tokens)

    def check_token_caps(self, route_cfg: dict[str, Any], estimated_input: int, estimated_output: int) -> None:
        """Enforce per-request token caps before sending to provider."""
        max_in = route_cfg.get("max_input_tokens", 0)
        max_out = route_cfg.get("max_output_tokens", 0)
        if max_in > 0 and estimated_input > max_in:
            raise PolicyDeniedError(
                f"Request input tokens ({estimated_input}) exceed route cap ({max_in})",
                {"reason": "input_tokens_exceeded", "estimated": estimated_input, "max": max_in},
            )
        if max_out > 0 and estimated_output > max_out:
            raise PolicyDeniedError(
                f"Requested output tokens ({estimated_output}) exceed route cap ({max_out})",
                {"reason": "output_tokens_exceeded", "estimated": estimated_output, "max": max_out},
            )
