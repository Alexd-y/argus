"""Code Property Graph builder — AST, CFG, DFG in a unified graph.

Extracts nodes (files, functions, classes, endpoints, secrets, …) and edges
(calls, reads, writes, imports, dataflow) from source code for security analysis.
"""

from __future__ import annotations

import ast as py_ast
import hashlib
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PurePath
from typing import Any

logger = logging.getLogger(__name__)


class NodeType(str, Enum):
    FILE = "file"
    FUNCTION = "function"
    CLASS = "class"
    METHOD = "method"
    ENDPOINT = "endpoint"  # HTTP route handler
    VARIABLE = "variable"
    IMPORT = "import"
    SECRET = "secret"
    SENSITIVE_SINK = "sensitive_sink"  # DB query, file write, exec, …
    ENTRY_POINT = "entry_point"  # user input, upload, auth
    TRUST_BOUNDARY = "trust_boundary"


class EdgeType(str, Enum):
    CALLS = "calls"
    READS = "reads"
    WRITES = "writes"
    IMPORTS = "imports"
    INHERITS = "inherits"
    DATAFLOW = "dataflow"
    CONTROLFLOW = "controlflow"
    CONTAINS = "contains"


@dataclass
class GraphNode:
    id: str = ""
    node_type: NodeType = NodeType.FILE
    name: str = ""
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    language: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def compute_id(self) -> str:
        raw = f"{self.node_type.value}:{self.file_path}:{self.name}:{self.line_start}"
        return hashlib.blake2b(raw.encode(), digest_size=16).hexdigest()


@dataclass
class GraphEdge:
    id: str = ""
    source_id: str = ""
    target_id: str = ""
    edge_type: EdgeType = EdgeType.CALLS
    metadata: dict[str, Any] = field(default_factory=dict)

    def compute_id(self) -> str:
        raw = f"{self.source_id}→{self.target_id}:{self.edge_type.value}"
        return hashlib.blake2b(raw.encode(), digest_size=16).hexdigest()


@dataclass
class CodePropertyGraph:
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    language: str = ""

    def add_node(self, node: GraphNode) -> None:
        if not node.id:
            node.id = node.compute_id()
        self.nodes.append(node)

    def add_edge(self, edge: GraphEdge) -> None:
        if not edge.id:
            edge.id = edge.compute_id()
        self.edges.append(edge)


# === Sensitive sinks — patterns to detect in code ===

_SENSITIVE_SINKS: dict[str, list[str]] = {
    "python": [
        "os.system", "subprocess.call", "subprocess.Popen",
        "eval", "exec", "__import__",
        "open", "json.loads", "pickle.loads",
        "requests.get", "requests.post", "httpx.get", "httpx.post",
        "sqlalchemy.execute", "cursor.execute",
        "shutil.rmtree", "os.remove",
        "smtplib.SMTP",
    ],
    "javascript": [
        "eval(", "Function(", "require(",
        "fetch(", "axios.",
        "fs.writeFile", "fs.readFile",
        "child_process.exec", "child_process.spawn",
    ],
    "go": [
        "os.Exec", "exec.Command",
        "http.Get", "http.Post",
        "sql.DB.Query", "sql.DB.Exec",
    ],
}

# === Entry point patterns ===

_ENTRY_POINTS: dict[str, list[str]] = {
    "python": [
        "request.args", "request.form", "request.json",
        "request.files", "request.headers", "request.cookies",
        "input(", "sys.argv", "os.environ.get",
    ],
    "javascript": [
        "req.body", "req.query", "req.params",
        "req.headers", "req.cookies",
        "process.argv", "process.env",
    ],
    "go": [
        "r.URL.Query()", "r.FormValue(",
        "r.Header.Get", "c.Request.Body",
    ],
}


def _detect_language(file_path: str) -> str:
    suffix = PurePath(file_path).suffix.lower()
    mapping = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "javascript",
        ".jsx": "javascript",
        ".tsx": "javascript",
        ".go": "go",
        ".java": "java",
        ".rb": "ruby",
        ".php": "php",
        ".rs": "rust",
        ".cs": "csharp",
        ".c": "c",
        ".cpp": "cpp",
        ".h": "c",
        ".hpp": "cpp",
    }
    return mapping.get(suffix, "")


def build_python_cpg(file_path: str, source: str) -> CodePropertyGraph:
    """Build code property graph for Python source."""
    cpg = CodePropertyGraph(language="python")
    try:
        tree = py_ast.parse(source)
    except SyntaxError:
        return cpg

    file_node = GraphNode(
        node_type=NodeType.FILE, name=file_path,
        file_path=file_path, language="python",
    )
    cpg.add_node(file_node)

    for node in py_ast.walk(tree):
        if isinstance(node, py_ast.FunctionDef):
            fn_node = GraphNode(
                node_type=NodeType.FUNCTION if not _is_method(node) else NodeType.METHOD,
                name=node.name, file_path=file_path,
                line_start=node.lineno, line_end=node.end_lineno or node.lineno,
                language="python",
            )
            cpg.add_node(fn_node)
            cpg.add_edge(GraphEdge(
                source_id=file_node.id, target_id=fn_node.id,
                edge_type=EdgeType.CONTAINS,
            ))
            for child in py_ast.walk(node):
                if isinstance(child, py_ast.Call) and isinstance(child.func, py_ast.Name):
                    cpg.add_edge(GraphEdge(
                        source_id=fn_node.id,
                        target_id=GraphNode(node_type=NodeType.FUNCTION, name=child.func.id, file_path=file_path, language="python").compute_id(),
                        edge_type=EdgeType.CALLS,
                    ))

        elif isinstance(node, py_ast.ClassDef):
            cls_node = GraphNode(
                node_type=NodeType.CLASS, name=node.name,
                file_path=file_path, line_start=node.lineno,
                line_end=node.end_lineno or node.lineno, language="python",
            )
            cpg.add_node(cls_node)
            cpg.add_edge(GraphEdge(source_id=file_node.id, target_id=cls_node.id, edge_type=EdgeType.CONTAINS))

    # Detect sensitive sinks and entry points
    for line_no, line in enumerate(source.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith('"""') or stripped.startswith("'''"):
            continue

        for sink in _SENSITIVE_SINKS.get("python", []):
            if sink in stripped:
                sink_node = GraphNode(
                    node_type=NodeType.SENSITIVE_SINK, name=sink,
                    file_path=file_path, line_start=line_no, language="python",
                )
                cpg.add_node(sink_node)
                cpg.add_edge(GraphEdge(source_id=file_node.id, target_id=sink_node.id, edge_type=EdgeType.CONTAINS))
                break

        for ep in _ENTRY_POINTS.get("python", []):
            if ep in stripped:
                ep_node = GraphNode(
                    node_type=NodeType.ENTRY_POINT, name=ep,
                    file_path=file_path, line_start=line_no, language="python",
                )
                cpg.add_node(ep_node)
                cpg.add_edge(GraphEdge(source_id=file_node.id, target_id=ep_node.id, edge_type=EdgeType.CONTAINS))
                break

    return cpg


def _is_method(node: py_ast.FunctionDef) -> bool:
    """Returns True if function is a class method (has 'self' or 'cls' parameter)."""
    if node.args.args:
        first = node.args.args[0].arg
        return first in ("self", "cls")
    return False


def build_cpg(file_path: str, source: str) -> CodePropertyGraph:
    """Build code property graph for any supported language."""
    lang = _detect_language(file_path)
    if lang == "python":
        return build_python_cpg(file_path, source)
    return CodePropertyGraph(language=lang)
