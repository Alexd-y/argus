"""Tests for Knowledge Graph — code property graph builder."""

from src.knowledge_graph.graph.builder import (
    CodePropertyGraph,
    GraphNode,
    GraphEdge,
    NodeType,
    EdgeType,
    build_python_cpg,
    build_cpg,
    _detect_language,
)


class TestDetectLanguage:
    def test_python_detected(self):
        assert _detect_language("app/main.py") == "python"
        assert _detect_language("tests/test.py") == "python"

    def test_javascript_detected(self):
        assert _detect_language("src/App.js") == "javascript"
        assert _detect_language("index.ts") == "javascript"
        assert _detect_language("Component.tsx") == "javascript"

    def test_go_detected(self):
        assert _detect_language("main.go") == "go"

    def test_java_detected(self):
        assert _detect_language("Main.java") == "java"

    def test_unknown_returns_empty(self):
        assert _detect_language("Makefile") == ""
        assert _detect_language("Dockerfile") == ""


class TestPythonCPG:
    def test_builds_file_node(self):
        source = "def hello(): return 'world'"
        cpg = build_python_cpg("test.py", source)
        assert len(cpg.nodes) >= 1
        file_nodes = [n for n in cpg.nodes if n.node_type == NodeType.FILE]
        assert len(file_nodes) == 1

    def test_detects_function(self):
        source = "def calculate(x, y): return x + y"
        cpg = build_python_cpg("calc.py", source)
        fn_nodes = [n for n in cpg.nodes if n.node_type == NodeType.FUNCTION]
        assert len(fn_nodes) == 1
        assert fn_nodes[0].name == "calculate"

    def test_detects_class(self):
        source = "class UserService:\n    def get_user(self): pass"
        cpg = build_python_cpg("service.py", source)
        class_nodes = [n for n in cpg.nodes if n.node_type == NodeType.CLASS]
        assert len(class_nodes) == 1
        assert class_nodes[0].name == "UserService"

    def test_detects_sensitive_sink(self):
        source = "import os\nos.system('ls -la')"
        cpg = build_python_cpg("exec.py", source)
        sink_nodes = [n for n in cpg.nodes if n.node_type == NodeType.SENSITIVE_SINK]
        assert len(sink_nodes) >= 1
        assert any("os.system" in n.name for n in sink_nodes)

    def test_detects_entry_point(self):
        source = "from flask import request\ndata = request.args.get('q')"
        cpg = build_python_cpg("app.py", source)
        ep_nodes = [n for n in cpg.nodes if n.node_type == NodeType.ENTRY_POINT]
        assert len(ep_nodes) >= 1
        assert any("request.args" in n.name for n in ep_nodes)

    def test_skip_comments(self):
        """Comments should not be flagged as sensitive sinks."""
        source = "# os.system('hello') — this is commented out"
        cpg = build_python_cpg("comments.py", source)
        sink_nodes = [n for n in cpg.nodes if n.node_type == NodeType.SENSITIVE_SINK]
        assert len(sink_nodes) == 0

    def test_empty_source(self):
        cpg = build_python_cpg("empty.py", "")
        assert len(cpg.nodes) >= 1  # at least file node

    def test_syntax_error_graceful(self):
        cpg = build_python_cpg("broken.py", "def broken( {{{ ")
        assert len(cpg.nodes) == 0  # graceful on syntax error


class TestGraphNodes:
    def test_node_id_deterministic(self):
        n1 = GraphNode(node_type=NodeType.FUNCTION, name="test", file_path="a.py", line_start=1)
        n2 = GraphNode(node_type=NodeType.FUNCTION, name="test", file_path="a.py", line_start=1)
        assert n1.compute_id() == n2.compute_id()

    def test_node_id_different_for_different_inputs(self):
        n1 = GraphNode(node_type=NodeType.FUNCTION, name="test", file_path="a.py", line_start=1)
        n2 = GraphNode(node_type=NodeType.FUNCTION, name="test", file_path="b.py", line_start=1)
        assert n1.compute_id() != n2.compute_id()


class TestCodePropertyGraph:
    def test_add_node_sets_id(self):
        cpg = CodePropertyGraph()
        node = GraphNode(node_type=NodeType.FILE, name="test.py")
        cpg.add_node(node)
        assert node.id != ""

    def test_add_edge_sets_id(self):
        cpg = CodePropertyGraph()
        edge = GraphEdge(source_id="a", target_id="b", edge_type=EdgeType.CALLS)
        cpg.add_edge(edge)
        assert edge.id != ""


class TestBuildCpgRouter:
    def test_routes_to_python_builder(self):
        cpg = build_cpg("app/main.py", "def main(): pass")
        assert cpg.language == "python"
        assert len(cpg.nodes) >= 2  # file + function

    def test_unknown_language_returns_empty_cpg(self):
        cpg = build_cpg("config/makefile", "all: build")
        assert cpg.language == ""
        assert len(cpg.nodes) == 0
