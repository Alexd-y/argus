"""Regression tests for CVSS reconciliation and PoC command generation.

* ``reconcile_findings_cvss`` — severity/cvss/cvss_score/cvss_vector must end up
  internally consistent; a vector that contradicts a rule-assigned severity is
  dropped rather than inflating the finding.
* ``_generate_poc`` — an already-runnable ``poc`` command must not be re-wrapped
  in ``curl -v '...'``; only bare URLs get a synthesised curl invocation.
"""

from __future__ import annotations

from src.orchestration.handlers import _generate_poc, _is_bare_url
from src.reports.finding_severity_normalizer import reconcile_findings_cvss


class TestReconcileFindingsCvss:
    def test_contradicting_vector_is_dropped_severity_wins(self) -> None:
        # "No CAA record": rule says low, but a garbage vector scores 7.4 (high).
        f = {
            "title": "No CAA record",
            "severity": "low",
            "cvss": 3.1,
            "cvss_score": 7.4,
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        }
        reconcile_findings_cvss([f])
        assert f["severity"] == "low"
        assert f["cvss"] == f["cvss_score"]
        assert 0.1 <= f["cvss_score"] <= 3.9  # low band
        assert f["cvss_vector"] is None  # contradicting vector dropped

    def test_consistent_vector_is_authoritative(self) -> None:
        # High-scoring vector with matching declared severity is kept and drives score.
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # base 7.5 → high
        f = {
            "title": "SQLi",
            "severity": "high",
            "cvss_score": 5.0,  # stale/low — vector should win
            "cvss_vector": vector,
        }
        reconcile_findings_cvss([f])
        assert f["severity"] == "high"
        assert f["cvss_score"] == f["cvss"]
        assert 7.0 <= f["cvss_score"] <= 8.9
        assert f["cvss_vector"] == vector

    def test_score_only_derives_severity(self) -> None:
        f = {"title": "x", "cvss_score": 5.3}
        reconcile_findings_cvss([f])
        assert f["severity"] == "medium"
        assert f["cvss"] == 5.3

    def test_no_cvss_signal_left_untouched(self) -> None:
        f = {"title": "info only", "severity": "info"}
        reconcile_findings_cvss([f])
        # info has representative 0.0 → score set, severity stays info
        assert f["severity"] == "info"
        assert f["cvss_score"] == 0.0


class TestGeneratePoc:
    def test_bare_url_detection(self) -> None:
        assert _is_bare_url("https://alleksy.com/login")
        assert not _is_bare_url("curl -sI 'https://alleksy.com'")
        assert not _is_bare_url("for i in $(seq 1 5); do curl ...; done")

    def test_command_poc_not_rewrapped(self) -> None:
        data = {"poc": "curl -sI 'https://alleksy.com'"}
        assert _generate_poc(data) == "curl -sI 'https://alleksy.com'"

    def test_bash_loop_poc_preserved_verbatim(self) -> None:
        loop = "for i in $(seq 1 5); do curl -s -o /dev/null -w '%{http_code}\\n' 'https://x/login'; done"
        assert _generate_poc({"poc": loop}) == loop
        assert "curl -v '" not in _generate_poc({"poc": loop})

    def test_bare_url_gets_curl_wrapper(self) -> None:
        out = _generate_poc({"url": "https://alleksy.com/x"})
        assert out == "curl -v 'https://alleksy.com/x'"

    def test_empty_returns_empty(self) -> None:
        assert _generate_poc({}) == ""
