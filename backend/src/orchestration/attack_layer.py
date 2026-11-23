"""Purple-team ATT&CK layer + Attack Replay Ledger (WP E.7).

Two defensive (blue-team) deliverables, built deterministically from the engagement:

* :func:`build_attack_navigator_layer` — a MITRE ATT&CK Navigator layer JSON mapping a
  technique list (e.g. the FBI FLASH-20261113-001 techniques) to ARGUS coverage, so a
  defender can load exactly which techniques the engagement exercised.
* :class:`AttackReplayLedger` — a hash-chained, tamper-evident timeline of
  ``ARGUS action → ATT&CK technique → observable``. Like the verification kit it uses a
  SHA-256 chain, not a cryptographic signature (no signing key); any edit to an earlier
  entry changes the ``root_hash``.

Pure module: stdlib only, no DB/LLM/network. Complements the existing LLM-driven Sigma
autogen in :mod:`src.orchestration.detection_engineering`.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from typing import Any

__all__ = [
    "AttackReplayLedger",
    "build_attack_navigator_layer",
]

_OBSERVED_SCORE = 100
_UNOBSERVED_SCORE = 25


def build_attack_navigator_layer(
    techniques: Iterable[Mapping[str, Any]],
    *,
    name: str = "ARGUS ATT&CK Coverage",
    domain: str = "enterprise-attack",
    description: str | None = None,
) -> dict[str, Any]:
    """Build a MITRE ATT&CK Navigator layer (schema 4.5) from a technique list.

    Each item is a mapping with ``technique_id`` and optional ``observed`` (bool),
    ``score`` (explicit override) and ``comment``. Observed techniques score higher so
    they stand out on the heatmap. The result is a plain dict ready to ``json.dumps``
    and upload to the ATT&CK Navigator.
    """
    entries: list[dict[str, Any]] = []
    for item in techniques:
        tid = str(item["technique_id"])
        observed = bool(item.get("observed", False))
        score = item.get("score")
        if score is None:
            score = _OBSERVED_SCORE if observed else _UNOBSERVED_SCORE
        entries.append(
            {
                "techniqueID": tid,
                "score": score,
                "color": "",  # Navigator derives the colour from score + gradient.
                "comment": str(item.get("comment", "")),
                "enabled": True,
                "metadata": [],
                "showSubtechniques": False,
            }
        )
    return {
        "name": name,
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": domain,
        "description": description
        or "ARGUS coverage of FBI FLASH-20261113-001 techniques (purple-team layer).",
        "techniques": entries,
        "gradient": {
            "colors": ["#ffffff", "#ff6666"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [{"label": "observed by ARGUS", "color": "#ff6666"}],
        "sorting": 0,
        "hideDisabled": False,
    }


class AttackReplayLedger:
    """Append-only, hash-chained ledger of ARGUS action → technique → observable."""

    def __init__(self) -> None:
        self._entries: list[dict[str, Any]] = []

    def record(
        self,
        *,
        action: str,
        technique_id: str,
        observable: str,
        timestamp: str | None = None,
    ) -> None:
        """Append one replay step (kept verbatim; determinism is the caller's to seed)."""
        self._entries.append(
            {
                "action": action,
                "technique_id": technique_id,
                "observable": observable,
                "timestamp": timestamp,
            }
        )

    def signed_timeline(self) -> dict[str, Any]:
        """Return the ordered entries with a SHA-256 chain + ``root_hash``.

        Each entry's ``chain_hash`` folds in the previous hash and the entry content,
        so editing any earlier entry changes every later hash and the ``root_hash`` —
        tamper-evident. This is a hash chain, not a cryptographic signature.
        """
        entries: list[dict[str, Any]] = []
        prev = ""
        for index, entry in enumerate(self._entries):
            payload = json.dumps(
                {"index": index, "prev": prev, **entry},
                sort_keys=True,
                separators=(",", ":"),
            )
            chain = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            entries.append({**entry, "index": index, "prev_hash": prev, "chain_hash": chain})
            prev = chain
        return {
            "entries": entries,
            "root_hash": prev,
            "count": len(entries),
            "integrity_note": "SHA-256 hash chain; tamper-evident, not a signature.",
        }
