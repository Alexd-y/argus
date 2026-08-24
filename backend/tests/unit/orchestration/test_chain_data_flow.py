"""Chain data-flow fixes: quick_fuzz recon endpoints + structured exploitation_queue (G1/G4)."""

from __future__ import annotations

from src.orchestration.exploitation_queue import ExploitationQueue, ExploitHypothesis
from src.orchestration.handlers import _recon_seed_urls
from src.pipeline.contracts.finding_dto import FindingCategory
from src.recon.quick_fuzz.quick_fuzzer import _MAX_FUZZ_TARGETS, _build_fuzz_targets


class TestBuildFuzzTargets:
    def test_target_first_and_dedup(self):
        out = _build_fuzz_targets(
            "https://x.test/",
            ["https://x.test/a", "https://x.test/a", "https://x.test/b"],
        )
        assert out[0] == "https://x.test/"
        assert out == ["https://x.test/", "https://x.test/a", "https://x.test/b"]

    def test_non_http_filtered(self):
        out = _build_fuzz_targets("https://x.test", ["ftp://x", "javascript:alert(1)", "  ", None])  # type: ignore[list-item]
        assert out == ["https://x.test"]

    def test_capped(self):
        seeds = [f"https://x.test/{i}" for i in range(100)]
        out = _build_fuzz_targets("https://x.test", seeds)
        assert len(out) == _MAX_FUZZ_TARGETS

    def test_empty_falls_back_to_target(self):
        out = _build_fuzz_targets("https://x.test", None)
        assert out == ["https://x.test"]


class TestReconSeedUrls:
    def test_extracts_from_assets_and_endpoints(self):
        recon = {
            "assets": ["https://x.test/login", "notaurl", "https://x.test/api"],
            "endpoints": [{"url": "https://x.test/search"}, {"endpoint": "http://x.test/z"}],
            "subdomains": ["x.test"],  # bare host, not http → ignored
        }
        urls = _recon_seed_urls(recon, "https://x.test")
        assert "https://x.test/login" in urls
        assert "https://x.test/api" in urls
        assert "https://x.test/search" in urls
        assert "http://x.test/z" in urls
        assert "notaurl" not in urls

    def test_dedup_preserves_order(self):
        recon = {"assets": ["https://x.test/a", "https://x.test/a", "https://x.test/b"]}
        assert _recon_seed_urls(recon, "https://x.test") == ["https://x.test/a", "https://x.test/b"]

    def test_none_returns_empty(self):
        assert _recon_seed_urls(None, "https://x.test") == []
        assert _recon_seed_urls({}, "https://x.test") == []


def _hyp(finding_id: str, cat: FindingCategory, location: str, conf: float = 0.6) -> ExploitHypothesis:
    return ExploitHypothesis(
        finding_id=finding_id,
        vuln_type=cat,
        location=location,
        confidence=conf,
    )


class TestExtendFromQueues:
    def test_merges_structured_queue_hypotheses(self):
        base = ExploitationQueue(
            target="https://x.test",
            scan_id="s-1",
            hypotheses=[_hyp("F-1", FindingCategory.SQLI, "https://x.test/login")],
        )
        va_queue = ExploitationQueue(
            target="https://x.test",
            scan_id="s-1",
            hypotheses=[
                _hyp("F-2", FindingCategory.XSS, "https://x.test/search"),
                _hyp("F-3", FindingCategory.SSRF, "https://x.test/fetch"),
            ],
        )
        added = base.extend_from_queues([va_queue])
        assert added == 2
        fids = {h.finding_id for h in base.hypotheses}
        assert fids == {"F-1", "F-2", "F-3"}

    def test_dedup_on_merge(self):
        base = ExploitationQueue(
            target="https://x.test",
            scan_id="s-1",
            hypotheses=[_hyp("F-1", FindingCategory.SQLI, "https://x.test/login")],
        )
        dup_queue = ExploitationQueue(
            target="https://x.test",
            scan_id="s-1",
            hypotheses=[_hyp("F-1", FindingCategory.SQLI, "https://x.test/login")],
        )
        added = base.extend_from_queues([dup_queue])
        assert added == 0
        assert len(base.hypotheses) == 1

    def test_merged_hypotheses_reach_exploitation_input(self):
        base = ExploitationQueue(target="https://x.test", scan_id="s-1", hypotheses=[])
        va_queue = ExploitationQueue(
            target="https://x.test",
            scan_id="s-1",
            hypotheses=[_hyp("F-9", FindingCategory.XSS, "https://x.test/q")],
        )
        base.extend_from_queues([va_queue])
        payload = base.to_exploitation_input()
        finding_ids = {f.get("finding_id") for f in payload["findings"]}
        assert "F-9" in finding_ids
