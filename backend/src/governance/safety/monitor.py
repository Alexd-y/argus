"""Safety Anomaly Detection — monitors LLM behaviour for policy violations.

Detects: prompt injection attempts, disallowed content generation,
hallucinated findings, abuse patterns, budget abuse.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SafetyAlert:
    id: str = ""
    alert_type: str = ""         # prompt_injection | disallowed_content | hallucination | abuse
    severity: str = "medium"
    description: str = ""
    detected_at: str = ""
    model: str = ""
    task: str = ""
    prompt_hash: str = ""
    evidence: str = ""


class SafetyMonitor:
    """Real-time safety monitoring for LLM calls.

    Tracks prompt/response patterns, maintains sliding windows for anomaly detection.
    """

    def __init__(self, alert_callback=None) -> None:
        self._injection_history: deque[dict[str, Any]] = deque(maxlen=500)
        self._hallucination_history: deque[dict[str, Any]] = deque(maxlen=500)
        self._alert_callback = alert_callback
        self._recent_alerts: list[SafetyAlert] = []

    def check_prompt(self, prompt: str, task: str = "") -> SafetyAlert | None:
        """Check prompt for injection patterns."""
        cleaned = _sanitize_for_check(prompt)

        patterns = [
            (r"ignore (?:all )?previous (?:instructions?|prompts?)", "prompt_injection_ignore"),
            (r"you are now\b", "prompt_injection_role_change"),
            (r"\[system\]", "prompt_injection_system_tag"),
            (r"<\|im_end\|>", "prompt_injection_token"),
            (r"jailbreak", "prompt_injection_jailbreak"),
            (r"disregard (?:all )?(?:previous )?(?:instructions?|rules?)", "prompt_injection_disregard"),
            (r"reveal (?:your )?(?:system )?prompt", "prompt_injection_reveal"),
            (r"bypass (?:the )?safety", "prompt_injection_bypass"),
        ]

        for pattern, alert_type in patterns:
            if re.search(pattern, cleaned):
                alert = SafetyAlert(
                    id=hashlib.blake2b(f"{alert_type}:{time.time()}".encode(), digest_size=8).hexdigest(),
                    alert_type=alert_type,
                    severity="high",
                    description=f"Prompt injection pattern detected: {pattern}",
                    detected_at=str(time.time()),
                    task=task,
                    prompt_hash=hashlib.blake2b(prompt.encode(), digest_size=12).hexdigest(),
                    evidence=cleaned[:200],
                )
                self._record(alert)
                return alert
        return None

    def check_response(self, response: str, task: str = "") -> SafetyAlert | None:
        """Check LLM response for dangerous content."""
        cleaned = response.lower()

        dangerous_patterns = [
            (r"rm\s+-rf\s+/", "dangerous_command"),
            (r"DROP\s+TABLE", "dangerous_sql"),
            (r"delete\s+from\s+(users|accounts|customers)", "dangerous_sql"),
            (r"shellcode|nop sled|\x90\x90", "exploit_generation"),
            (r"meterpreter|msfvenom", "offensive_tool"),
            (r"curl.*\|\s*sh\b", "dangerous_pipe"),
        ]

        for pattern, alert_type in dangerous_patterns:
            if re.search(pattern, cleaned, re.IGNORECASE):
                alert = SafetyAlert(
                    id=hashlib.blake2b(f"{alert_type}:{time.time()}".encode(), digest_size=8).hexdigest(),
                    alert_type=alert_type,
                    severity="critical",
                    description=f"Dangerous content in LLM response: {pattern}",
                    detected_at=str(time.time()),
                    task=task,
                    prompt_hash="",
                    evidence=response[:200],
                )
                self._record(alert)
                return alert
        return None

    def check_hallucination(
        self, claimed_cve: str, known_cves: set[str],
    ) -> SafetyAlert | None:
        """Detect hallucinated CVEs."""
        cve = claimed_cve.upper().strip()
        if cve.startswith("CVE-") and cve not in known_cves:
            alert = SafetyAlert(
                id=hashlib.blake2b(f"hallucination:{cve}:{time.time()}".encode(), digest_size=8).hexdigest(),
                alert_type="hallucinated_cve",
                severity="high",
                description=f"LLM referenced non-existent CVE: {cve}",
                detected_at=str(time.time()),
                evidence=cve,
            )
            self._record(alert)
            return alert
        return None

    def abuse_rate(self, user_id: str, window_seconds: int = 300) -> int:
        """Count abuse alerts for a user in time window."""
        cutoff = time.time() - window_seconds
        total = 0
        for entry in self._injection_history:
            if float(entry.get("ts", 0)) > cutoff and entry.get("user_id") == user_id:
                total += 1
        return total

    def _record(self, alert: SafetyAlert) -> None:
        self._recent_alerts.append(alert)
        if len(self._recent_alerts) > 100:
            self._recent_alerts = self._recent_alerts[-100:]
        self._injection_history.append({
            "ts": time.time(),
            "alert_type": alert.alert_type,
            "severity": alert.severity,
        })
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass


def _sanitize_for_check(text: str) -> str:
    """Normalize text for pattern matching."""
    return re.sub(r"\s+", " ", text.lower().strip())


# Singleton
_safety_monitor: SafetyMonitor | None = None


def get_safety_monitor() -> SafetyMonitor:
    global _safety_monitor
    if _safety_monitor is None:
        _safety_monitor = SafetyMonitor()
    return _safety_monitor
