"""WP E.7 — purple-team ATT&CK Navigator layer + signed Attack Replay Ledger.

Pure/offline. The Navigator layer is a deterministic JSON artefact mapping the FBI
FLASH technique list to ARGUS coverage; the Replay Ledger is a hash-chained timeline
of ARGUS action → technique → observable (tamper-evident, like the verification kit).
"""

from __future__ import annotations

import json

from src.orchestration.attack_layer import (
    AttackReplayLedger,
    build_attack_navigator_layer,
)


def test_navigator_layer_has_valid_structure() -> None:
    layer = build_attack_navigator_layer(
        [{"technique_id": "T1190", "observed": True, "comment": "exposed admin API"}],
        name="ARGUS FBI-FLASH coverage",
    )
    assert layer["domain"] == "enterprise-attack"
    assert layer["name"] == "ARGUS FBI-FLASH coverage"
    assert "attack" in layer["versions"] and "navigator" in layer["versions"]
    tech = layer["techniques"][0]
    assert tech["techniqueID"] == "T1190"
    assert tech["comment"] == "exposed admin API"
    # Serialises cleanly (a real Navigator layer is uploaded as JSON).
    assert json.loads(json.dumps(layer))["techniques"][0]["techniqueID"] == "T1190"


def test_observed_vs_unobserved_scored_differently() -> None:
    layer = build_attack_navigator_layer(
        [
            {"technique_id": "T1190", "observed": True},
            {"technique_id": "T1059", "observed": False},
        ]
    )
    by_id = {t["techniqueID"]: t for t in layer["techniques"]}
    assert by_id["T1190"]["score"] > by_id["T1059"]["score"]


def test_ledger_records_in_order() -> None:
    led = AttackReplayLedger()
    led.record(action="nuclei scan", technique_id="T1190", observable="HTTP 200 on /admin")
    led.record(action="sqlmap", technique_id="T1505.003", observable="stacked query ok")
    timeline = led.signed_timeline()
    assert [e["technique_id"] for e in timeline["entries"]] == ["T1190", "T1505.003"]
    assert timeline["root_hash"]


def test_ledger_hash_chain_is_tamper_evident() -> None:
    led = AttackReplayLedger()
    led.record(action="a", technique_id="T1", observable="o1")
    led.record(action="b", technique_id="T2", observable="o2")
    original_root = led.signed_timeline()["root_hash"]

    tampered = AttackReplayLedger()
    tampered.record(action="a", technique_id="T1", observable="o1-TAMPERED")
    tampered.record(action="b", technique_id="T2", observable="o2")
    assert tampered.signed_timeline()["root_hash"] != original_root


def test_ledger_is_deterministic_for_same_input() -> None:
    def _make() -> str:
        led = AttackReplayLedger()
        led.record(action="a", technique_id="T1", observable="o1", timestamp="2026-11-23T00:00:00Z")
        led.record(action="b", technique_id="T2", observable="o2", timestamp="2026-11-23T00:01:00Z")
        return led.signed_timeline()["root_hash"]

    assert _make() == _make()
