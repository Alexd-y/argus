"""F-H01 Stage 5 — structural docker-compose security regression tests.

Replaces the old substring-grep checks, which silently passed when a fifth
service mounted the socket and could not see a root user hidden behind the
``${ARGUS_WORKER_USER:-...}`` default. These parse the compose YAML and assert
structural invariants instead.

``docker-compose.hardened.yml`` uses the ``!override`` merge tag, on which
``yaml.safe_load`` chokes; we register a constructor for it (and ``!reset``) so
the file parses without shelling out to ``docker compose config`` (this test must
run in the default, Docker-less suite).
"""

from __future__ import annotations

import ast
import importlib.util
import re
from pathlib import Path
from typing import Any

import yaml

_REPO = Path(__file__).resolve().parents[2]
_INFRA = _REPO / "infra"
_BASE = _INFRA / "docker-compose.yml"
_HARDENED = _INFRA / "docker-compose.hardened.yml"
_BROKER = _INFRA / "docker-compose.broker.yml"
_LAB = _INFRA / "docker-compose.lab-runner.yml"
_SRC = _REPO / "backend" / "src"


# --------------------------------------------------------------------------- #
# YAML loading with compose merge tags (!override, !reset)
# --------------------------------------------------------------------------- #
class _ComposeLoader(yaml.SafeLoader):
    pass


def _construct_override(loader: yaml.Loader, node: yaml.Node) -> Any:
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return None


_ComposeLoader.add_constructor("!override", _construct_override)
_ComposeLoader.add_constructor("!reset", _construct_override)


def _load(path: Path) -> dict[str, Any]:
    return yaml.load(path.read_text(encoding="utf-8"), Loader=_ComposeLoader) or {}


def _services(doc: dict[str, Any]) -> dict[str, Any]:
    return doc.get("services") or {}


def _volume_refs(svc: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for v in svc.get("volumes") or []:
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, dict):
            out.append(str(v.get("source", "")))
    return out


def _has_socket_mount(svc: dict[str, Any]) -> bool:
    return any("docker.sock" in ref for ref in _volume_refs(svc))


def _networks(svc: dict[str, Any]) -> set[str]:
    nets = svc.get("networks")
    if isinstance(nets, dict):
        return set(nets.keys())
    if isinstance(nets, list):
        return set(nets)
    return set()


def _resolve_user_uid(user: Any) -> str | None:
    """Resolve the effective default UID from a compose ``user:`` value.

    Handles literals ("0:0", "1000:1000") and env substitutions with defaults
    (``${ARGUS_WORKER_USER:-1000:${DOCKER_GID:-999}}`` -> "1000").
    """
    if user is None:
        return None
    s = str(user)
    m = re.match(r"^\$\{[^:}]+:-(.+)\}$", s)
    if m:
        s = m.group(1)  # the default, e.g. "1000:${DOCKER_GID:-999}" or "0:0"
    return s.split(":")[0]


# --------------------------------------------------------------------------- #
# 1. Every socket-mounting base service is covered by the hardened overlay.
# --------------------------------------------------------------------------- #
def test_hardened_overlay_covers_all_socket_mounts() -> None:
    base = _services(_load(_BASE))
    hardened = _services(_load(_HARDENED))

    socket_services = {name for name, svc in base.items() if _has_socket_mount(svc)}
    # Services whose socket mount the overlay drops (volumes overridden to empty
    # / no docker.sock left).
    dropped = {
        name
        for name, svc in hardened.items()
        if "volumes" in svc and not _has_socket_mount(svc)
    }
    missing = socket_services - dropped
    assert not missing, (
        "hardened overlay does not drop the socket for: "
        f"{sorted(missing)} (this is exactly the worker-cairn class of gap)"
    )


def test_broker_overlay_covers_all_socket_mounts() -> None:
    base = _services(_load(_BASE))
    broker = _services(_load(_BROKER))
    socket_services = {name for name, svc in base.items() if _has_socket_mount(svc)}
    dropped = {
        name for name, svc in broker.items() if "volumes" in svc and not _has_socket_mount(svc)
    }
    missing = socket_services - dropped
    assert not missing, f"broker overlay does not drop the socket for: {sorted(missing)}"


# --------------------------------------------------------------------------- #
# 2. No service runs as root — including via the ARGUS_WORKER_USER default.
# --------------------------------------------------------------------------- #
def test_no_service_runs_as_root() -> None:
    offenders: list[str] = []
    for path in (_BASE, _HARDENED, _BROKER, _LAB):
        for name, svc in _services(_load(path)).items():
            uid = _resolve_user_uid(svc.get("user"))
            if uid == "0":
                offenders.append(f"{path.name}:{name}")
    assert not offenders, f"services resolving to root (uid 0): {offenders}"


# --------------------------------------------------------------------------- #
# 3. Sandboxes declare cap_drop [ALL] + no-new-privileges + a pids limit.
# --------------------------------------------------------------------------- #
def _pids_limit(svc: dict[str, Any]) -> Any:
    if "pids_limit" in svc:
        return svc["pids_limit"]
    return (((svc.get("deploy") or {}).get("resources") or {}).get("limits") or {}).get("pids")


def test_sandbox_services_are_hardened() -> None:
    base = _services(_load(_BASE))
    lab = _services(_load(_LAB))
    targets = {
        "sandbox": base.get("sandbox"),
        "kali-runner": base.get("kali-runner"),
        "lab-runner": lab.get("lab-runner"),
    }
    for name, svc in targets.items():
        assert svc is not None, f"{name} service missing"
        assert svc.get("cap_drop") == ["ALL"], f"{name}: cap_drop must be [ALL]"
        assert "no-new-privileges:true" in (svc.get("security_opt") or []), (
            f"{name}: security_opt must include no-new-privileges:true"
        )
        assert _pids_limit(svc) is not None, f"{name}: a pids limit must be set"


# --------------------------------------------------------------------------- #
# 4. The sandbox shares no network with the datastores.
# --------------------------------------------------------------------------- #
def test_sandbox_not_on_datastore_network() -> None:
    base = _services(_load(_BASE))
    sandbox_nets = _networks(base["sandbox"])
    for db in ("postgres", "redis", "minio"):
        db_nets = _networks(base[db])
        shared = sandbox_nets & db_nets
        assert not shared, f"sandbox shares network(s) {shared} with {db}"


# --------------------------------------------------------------------------- #
# 5. exploitation_executor.py no longer hardcodes the sandbox container name.
# --------------------------------------------------------------------------- #
def test_exploitation_executor_has_no_hardcoded_sandbox_literal() -> None:
    path = _SRC / "orchestration" / "exploitation_executor.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    literals = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and node.value == "argus-sandbox"
    ]
    assert not literals, (
        "exploitation_executor.py still has hardcoded 'argus-sandbox' string "
        "literal(s); use settings.sandbox_container_name"
    )


# --------------------------------------------------------------------------- #
# 6. The Stage 3 AST gateway guard still holds.
# --------------------------------------------------------------------------- #
def test_docker_gateway_ast_guard_still_holds() -> None:
    guard_path = Path(__file__).parent / "test_audit_docker_gateway_ast.py"
    spec = importlib.util.spec_from_file_location("_gw_ast_guard", guard_path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # Re-run the guard's assertions in-process.
    mod.test_only_gateway_touches_docker()
    mod.test_exempt_list_has_no_stale_entries()
