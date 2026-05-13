"""Tests for Attack Path Builder and Risk Scoring."""

import pytest
from src.analysis.attack_paths.builder import (
    AttackPath,
    RiskScore,
    PathNode,
    PathEdge,
    PathNodeType,
    ImpactCategory,
    build_attack_path,
    calculate_risk_score,
    to_mermaid,
    to_d3_json,
    _classify_impact,
    _estimate_likelihood,
    _estimate_impact,
    _calculate_business_impact,
)


class TestAttackPath:
    def test_build_minimal_path(self):
        finding = {
            "id": "f1", "title": "SQLi in login", "severity": "critical",
            "cwe": "CWE-89", "description": "Unsanitized input", "file_path": "login.py",
            "line_start": 10, "param": "username",
        }
        path = build_attack_path(finding)
        assert path.finding_id == "f1"
        assert len(path.nodes) >= 3
        assert path.severity == "critical"

    def test_path_has_entry_and_sink(self):
        finding = {"id": "f2", "title": "XSS", "severity": "high", "url": "https://app.com/search?q=", "param": "q"}
        path = build_attack_path(finding)
        entry_nodes = [n for n in path.nodes if n.node_type == PathNodeType.ENTRY_POINT]
        sink_nodes = [n for n in path.nodes if n.node_type == PathNodeType.SINK]
        assert len(entry_nodes) >= 1
        assert len(sink_nodes) >= 1

    def test_path_has_impact_node(self):
        finding = {"id": "f3", "title": "RCE", "severity": "critical", "description": "remote code execution"}
        path = build_attack_path(finding)
        impact_nodes = [n for n in path.nodes if n.node_type == PathNodeType.IMPACT]
        assert len(impact_nodes) >= 1

    def test_edges_connect_nodes(self):
        finding = {"id": "f4", "title": "Auth bypass", "severity": "high"}
        path = build_attack_path(finding)
        assert len(path.edges) == len(path.nodes) - 1
        for i, edge in enumerate(path.edges):
            assert edge.source_id == path.nodes[i].id
            assert edge.target_id == path.nodes[i + 1].id


class TestRiskScore:
    def test_calculate_with_cvss(self):
        finding = {"id": "f1", "cvss": 9.8, "severity": "critical", "exploitability": "high"}
        score = calculate_risk_score(finding)
        assert score.cvss_base == 9.8
        assert score.priority == "p1_critical"

    def test_calculate_without_cvss(self):
        finding = {"id": "f2", "severity": "medium"}
        score = calculate_risk_score(finding)
        assert score.cvss_base >= 4.0
        assert score.priority in ("p2_high", "p3_medium")

    def test_business_context_affects_score(self):
        finding = {"id": "f3", "cvss": 8.0, "severity": "high"}
        ctx = {"data_classification": "restricted", "exposure": "internet", "user_base": 1000000}
        score_high = calculate_risk_score(finding, ctx)

        ctx_low = {"data_classification": "public", "exposure": "internal", "user_base": 10}
        score_low = calculate_risk_score(finding, ctx_low)

        assert score_high.business_impact > score_low.business_impact


class TestMermaidOutput:
    def test_generates_valid_mermaid(self):
        finding = {"id": "f1", "title": "Test", "severity": "low"}
        path = build_attack_path(finding)
        mermaid = to_mermaid(path)
        assert "graph LR" in mermaid
        assert "-->" in mermaid  # edges


class TestD3Output:
    def test_generates_d3_json(self):
        finding = {"id": "f1", "title": "Test", "severity": "low"}
        path = build_attack_path(finding)
        d3 = to_d3_json(path)
        assert "nodes" in d3
        assert "edges" in d3
        assert "metadata" in d3
        assert len(d3["nodes"]) == len(path.nodes)
        assert len(d3["edges"]) == len(path.edges)


class TestImpactClassification:
    def test_sqli_classifies_as_data_breach(self):
        finding = {"description": "SQL injection in login form"}
        impacts = _classify_impact(finding)
        assert ImpactCategory.DATA_BREACH in impacts

    def test_rce_classifies_correctly(self):
        finding = {"description": "Remote code execution via command injection"}
        impacts = _classify_impact(finding)
        assert ImpactCategory.REMOTE_CODE_EXECUTION in impacts

    def test_xss_classifies_as_info_disclosure(self):
        finding = {"description": "Reflected XSS in search parameter"}
        impacts = _classify_impact(finding)
        assert ImpactCategory.INFORMATION_DISCLOSURE in impacts

    def test_default_fallback(self):
        finding = {"description": "Some unknown issue"}
        impacts = _classify_impact(finding)
        assert len(impacts) >= 1


class TestEstimationFunctions:
    def test_likelihood_confirmed(self):
        assert _estimate_likelihood({"confidence": "confirmed"}) == 0.9

    def test_likelihood_advisory(self):
        assert _estimate_likelihood({"confidence": "advisory"}) == 0.2

    def test_impact_critical(self):
        assert _estimate_impact({"severity": "critical"}) == 10.0

    def test_impact_low(self):
        assert _estimate_impact({"severity": "low"}) == 2.5
