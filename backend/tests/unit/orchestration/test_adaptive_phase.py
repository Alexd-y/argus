"""Unit tests for the flag-gated adaptive-coverage integration seam (overhaul §6).

Covers the contract that makes it safe to wire into the live scan loop:
* strict no-op when the flag is off,
* ``None`` (record nothing) when no injectable surface is derivable,
* a serializable coverage snapshot when a phase output carries surfaces,
* tolerant, non-raising extraction over malformed / heterogeneous inputs,
* Step 2 — tested surfaces feed real tested/total %-coverage (not a constant 0.0).
"""

from __future__ import annotations

from typing import Any

from src.orchestration.adaptive_phase import (
    adaptive_coverage_snapshot,
    inventory_from_output,
)
from src.orchestration.adaptive_phase import (
    # Aliased: the real name starts with "test", which pytest would collect as a test.
    tested_surface_ids_from_output as get_tested_surface_ids,
)


def _va_output_with_findings() -> dict[str, Any]:
    return {
        "findings": [
            {"url": "https://target.tld/search", "parameter": "q", "method": "GET"},
            {
                "url": "https://target.tld/login",
                "parameter": "user",
                "method": "POST",
                "input_location": "form",
            },
        ],
        "hypotheses": [
            {
                "target": "https://target.tld/api/item",
                "param": "id",
                "method": "GET",
                "location": "query",
            },
        ],
    }


def _universe_gt_tested() -> dict[str, Any]:
    """3 discovered surfaces, only 1 exercised (via findings) -> coverage 1/3."""
    return {
        "input_surfaces": [
            {"url": "https://t.tld/a", "param_name": "x", "method": "GET"},
            {"url": "https://t.tld/b", "param_name": "y", "method": "GET"},
            {"url": "https://t.tld/c", "param_name": "z", "method": "GET"},
        ],
        "findings": [
            {"url": "https://t.tld/a", "parameter": "x", "method": "GET"},
        ],
    }


class TestInventoryFromOutput:
    def test_none_for_non_dict(self) -> None:
        assert inventory_from_output(None) is None
        assert inventory_from_output(["not", "a", "dict"]) is None
        assert inventory_from_output("nope") is None

    def test_none_when_no_surface_lists(self) -> None:
        assert inventory_from_output({"summary": "nothing injectable here"}) is None

    def test_none_when_rows_lack_url_or_param(self) -> None:
        # url without param and param without url -> both skipped -> empty -> None.
        out = {
            "findings": [
                {"url": "https://target.tld/x"},
                {"parameter": "q"},
                {"title": "informational"},
            ]
        }
        assert inventory_from_output(out) is None

    def test_builds_surfaces_from_findings_and_hypotheses(self) -> None:
        inv = inventory_from_output(_va_output_with_findings())
        assert inv is not None
        # 2 findings + 1 hypothesis, all with url+param.
        assert len(inv.items) == 3
        params = {item.param_name for item in inv.items}
        assert params == {"q", "user", "id"}
        methods = {item.method for item in inv.items}
        assert methods == {"GET", "POST"}

    def test_location_honored_and_defaulted(self) -> None:
        out = {
            "input_surfaces": [
                {"url": "https://t.tld/a", "param_name": "c", "location": "cookie"},
                {"url": "https://t.tld/b", "param_name": "h", "location": "header"},
                {"url": "https://t.tld/c", "param_name": "weird", "location": "banana"},
                {"url": "https://t.tld/d", "param_name": "none"},
            ]
        }
        inv = inventory_from_output(out)
        assert inv is not None
        by_param = {item.param_name: item.location for item in inv.items}
        assert by_param["c"] == "cookie"
        assert by_param["h"] == "header"
        assert by_param["weird"] == "query"  # unknown -> default
        assert by_param["none"] == "query"  # absent -> default

    def test_tolerates_non_dict_rows(self) -> None:
        out = {"findings": ["string", 42, None, {"url": "https://t.tld/x", "param": "q"}]}
        inv = inventory_from_output(out)
        assert inv is not None
        assert len(inv.items) == 1
        assert inv.items[0].param_name == "q"

    def test_surface_ids_are_stable_and_deterministic(self) -> None:
        out = {"findings": [{"url": "https://t.tld/x", "parameter": "q", "method": "get"}]}
        inv1 = inventory_from_output(out)
        inv2 = inventory_from_output(out)
        assert inv1 is not None and inv2 is not None
        assert inv1.items[0].surface_id == inv2.items[0].surface_id
        assert inv1.items[0].method == "GET"  # normalized upper

    def test_row_surface_id_is_preserved(self) -> None:
        out = {
            "input_surfaces": [
                {"surface_id": "surf_custom", "url": "https://t.tld/x", "param": "q"}
            ]
        }
        inv = inventory_from_output(out)
        assert inv is not None
        assert inv.items[0].surface_id == "surf_custom"


class TestTestedSurfaceIds:
    def test_empty_for_non_dict(self) -> None:
        assert get_tested_surface_ids(None) == set()
        assert get_tested_surface_ids("x") == set()

    def test_findings_count_as_tested(self) -> None:
        tested = get_tested_surface_ids(_va_output_with_findings())
        # 2 findings -> 2 tested ids; the hypothesis is not tested.
        assert len(tested) == 2

    def test_explicit_tested_dict_rows(self) -> None:
        out = {"tested_surfaces": [{"url": "https://t.tld/a", "param": "x", "method": "GET"}]}
        tested = get_tested_surface_ids(out)
        assert len(tested) == 1

    def test_explicit_tested_surface_id_strings(self) -> None:
        out = {"surfaces_tested": ["surf_aaa", "surf_bbb", "  ", ""]}
        tested = get_tested_surface_ids(out)
        assert tested == {"surf_aaa", "surf_bbb"}

    def test_explicit_row_surface_id_preferred(self) -> None:
        out = {
            "probed_surfaces": [{"surface_id": "surf_zzz", "url": "https://t.tld/a", "param": "x"}]
        }
        assert get_tested_surface_ids(out) == {"surf_zzz"}

    def test_tested_ids_align_with_inventory_ids(self) -> None:
        # A finding's derived id must match the same surface in the discovered universe.
        out = _universe_gt_tested()
        inv = inventory_from_output(out)
        assert inv is not None
        tested = get_tested_surface_ids(out)
        inv_ids = {item.surface_id for item in inv.items}
        assert tested.issubset(inv_ids)


class TestAdaptiveCoverageSnapshot:
    def test_disabled_is_strict_noop(self) -> None:
        assert adaptive_coverage_snapshot(_va_output_with_findings(), enabled=False) is None

    def test_enabled_but_no_surfaces_returns_none(self) -> None:
        assert adaptive_coverage_snapshot({"summary": "x"}, enabled=True) is None

    def test_partial_coverage_reflects_tested_fraction(self) -> None:
        snap = adaptive_coverage_snapshot(_universe_gt_tested(), enabled=True)
        assert snap is not None
        assert snap["kind"] == "adaptive_coverage"
        assert snap["surfaces"] == 3
        assert snap["tested_surfaces"] == 1
        cov = snap["coverage"]
        assert set(cov) == {
            "parameter_coverage",
            "endpoint_coverage",
            "node_count",
            "edge_count",
            "untested_inputs",
        }
        # 1 of 3 parameters exercised.
        assert abs(cov["parameter_coverage"] - (1 / 3)) < 1e-9
        assert cov["untested_inputs"] == 2
        # Marked at least the tested param + its endpoint (coverage propagation).
        assert snap["marked_nodes"] >= 2

    def test_snapshot_from_findings_and_hypotheses(self) -> None:
        # 3 surfaces total (2 findings + 1 hypothesis); only findings are tested.
        snap = adaptive_coverage_snapshot(_va_output_with_findings(), enabled=True)
        assert snap is not None
        assert snap["surfaces"] == 3
        assert snap["tested_surfaces"] == 2
        cov = snap["coverage"]
        assert abs(cov["parameter_coverage"] - (2 / 3)) < 1e-9
        assert cov["untested_inputs"] == 1

    def test_full_coverage_when_universe_equals_tested(self) -> None:
        out = {"findings": [{"url": "https://t.tld/a", "parameter": "x", "method": "GET"}]}
        snap = adaptive_coverage_snapshot(out, enabled=True)
        assert snap is not None
        assert snap["surfaces"] == 1
        assert snap["tested_surfaces"] == 1
        assert snap["coverage"]["parameter_coverage"] == 1.0
        assert snap["coverage"]["untested_inputs"] == 0

    def test_never_raises_on_garbage(self) -> None:
        for bad in (None, 123, "x", [], {}, {"findings": None}, {"findings": [1, 2]}):
            assert adaptive_coverage_snapshot(bad, enabled=True) is None

    def test_serializable_snapshot(self) -> None:
        import json

        snap = adaptive_coverage_snapshot(_va_output_with_findings(), enabled=True)
        assert snap is not None
        # Must round-trip as JSON (it is persisted in a ScanTimeline.entry JSON column).
        assert json.loads(json.dumps(snap)) == snap
