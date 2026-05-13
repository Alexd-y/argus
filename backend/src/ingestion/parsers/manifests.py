"""Parsers for infrastructure-as-code and dependency manifests.

Extracts structured data from Dockerfiles, Terraform, Kubernetes, SBOM, etc.
for threat modeling and vulnerability analysis.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from typing import Any


@dataclass
class DockerfileInfo:
    """Structured info extracted from Dockerfile."""

    base_images: list[str] = field(default_factory=list)
    exposed_ports: list[int] = field(default_factory=list)
    env_vars: dict[str, str] = field(default_factory=dict)
    run_commands: list[str] = field(default_factory=list)
    copy_paths: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    entrypoint: list[str] = field(default_factory=list)
    cmd: list[str] = field(default_factory=list)
    healthcheck: str = ""


@dataclass
class TerraformInfo:
    """Structured info extracted from Terraform configs."""

    providers: list[str] = field(default_factory=list)
    resources: list[dict[str, str]] = field(default_factory=list)
    data_sources: list[str] = field(default_factory=list)
    variables: dict[str, str] = field(default_factory=dict)
    outputs: list[str] = field(default_factory=list)
    security_groups: list[dict[str, Any]] = field(default_factory=list)
    iam_policies: list[str] = field(default_factory=list)


@dataclass
class DependencyInfo:
    """Structured info extracted from dependency manifests."""

    language: str = ""
    packages: list[dict[str, str]] = field(default_factory=list)
    dev_dependencies: list[dict[str, str]] = field(default_factory=list)
    total_count: int = 0


def parse_dockerfile(content: str) -> DockerfileInfo:
    info = DockerfileInfo()
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        upper = stripped.upper()
        if upper.startswith("FROM "):
            parts = stripped.split()
            if len(parts) >= 2:
                img = parts[1]
                if " AS " in img.upper():
                    img = img.split(" AS ")[0].strip()
                if " as " in img:
                    img = img.split(" as ")[0].strip()
                info.base_images.append(img)
        elif upper.startswith("EXPOSE "):
            for part in stripped.split()[1:]:
                part = part.rstrip("/tcp").rstrip("/udp")
                try:
                    info.exposed_ports.append(int(part))
                except ValueError:
                    pass
        elif upper.startswith("ENV "):
            parts = stripped.split(None, 2)
            if len(parts) >= 3:
                info.env_vars[parts[1]] = parts[2].strip('"')
        elif upper.startswith("RUN "):
            info.run_commands.append(stripped[4:].strip())
        elif upper.startswith("COPY ") or upper.startswith("ADD "):
            info.copy_paths.append(stripped)
        elif upper.startswith("USER "):
            info.users.append(stripped.split()[1] if len(stripped.split()) >= 2 else "")
        elif upper.startswith("ENTRYPOINT "):
            info.entrypoint = [stripped[11:].strip()]
        elif upper.startswith("CMD "):
            info.cmd = [stripped[4:].strip()]
        elif upper.startswith("HEALTHCHECK "):
            info.healthcheck = stripped[12:].strip()
    return info


def parse_terraform(content: str) -> TerraformInfo:
    info = TerraformInfo()
    provider_re = re.compile(r'provider\s+"([^"]+)"')
    info.providers = provider_re.findall(content)
    resource_re = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"')
    info.resources = [
        {"type": m[0], "name": m[1]} for m in resource_re.findall(content)
    ]
    data_re = re.compile(r'data\s+"([^"]+)"\s+"([^"]+)"')
    info.data_sources = [f"{m[0]}.{m[1]}" for m in data_re.findall(content)]
    sec_grp_blocks = re.findall(r'resource\s+"aws_security_group"\s+"([^"]+)"\s*\{([^}]+)\}', content, re.DOTALL)
    for name, block in sec_grp_blocks:
        sg = {"name": name, "ingress": []}
        ingress_re = re.compile(r'ingress\s*\{([^}]+)\}', re.DOTALL)
        for ing in ingress_re.findall(block):
            port = re.search(r'from_port\s*=\s*(\d+)', ing)
            proto = re.search(r'protocol\s*=\s*"([^"]+)"', ing)
            cidr = re.search(r'cidr_blocks\s*=\s*\[([^\]]+)\]', ing)
            sg["ingress"].append({
                "port": int(port.group(1)) if port else 0,
                "protocol": proto.group(1) if proto else "",
                "cidr": cidr.group(1) if cidr else "",
            })
        info.security_groups.append(sg)
    iam_policy_re = re.compile(r'resource\s+"aws_iam_policy"\s+"([^"]+)"')
    info.iam_policies = iam_policy_re.findall(content)
    return info


def parse_node_dependencies(content: str) -> DependencyInfo:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return DependencyInfo(language="node")
    info = DependencyInfo(language="node")
    deps = data.get("dependencies", {})
    dev = data.get("devDependencies", {})
    for name, version in deps.items():
        info.packages.append({"name": name, "version": str(version)})
    for name, version in dev.items():
        info.dev_dependencies.append({"name": name, "version": str(version)})
    info.total_count = len(info.packages) + len(info.dev_dependencies)
    return info


def parse_python_dependencies(content: str) -> DependencyInfo:
    info = DependencyInfo(language="python")
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if "==" in line:
            name, _, version = line.partition("==")
        elif ">=" in line:
            name, _, version = line.partition(">=")
        elif "<=" in line:
            name, _, version = line.partition("<=")
        elif "~=" in line:
            name, _, version = line.partition("~=")
        else:
            name, version = line, ""
        info.packages.append({
            "name": name.split("[")[0].strip(),
            "version": version.split(";")[0].strip(),
        })
    info.total_count = len(info.packages)
    return info


def parse_cargo_dependencies(content: str) -> DependencyInfo:
    try:
        data = tomllib.loads(content)
    except Exception:
        return DependencyInfo(language="rust")
    info = DependencyInfo(language="rust")
    deps = data.get("dependencies", {})
    for name, spec in deps.items():
        version = ""
        if isinstance(spec, str):
            version = spec
        elif isinstance(spec, dict):
            version = str(spec.get("version", ""))
        info.packages.append({"name": name, "version": version})
    info.total_count = len(info.packages)
    return info


def parse_go_dependencies(content: str) -> DependencyInfo:
    info = DependencyInfo(language="go")
    require_re = re.compile(r'\t([^\s]+)\s+v([^\s]+)')
    found_require = False
    for line in content.splitlines():
        if line.strip() == "require (":
            found_require = True
            continue
        if found_require and line.strip() == ")":
            found_require = False
            continue
        if found_require:
            m = require_re.match(line)
            if m:
                info.packages.append({"name": m.group(1), "version": m.group(2)})
    info.total_count = len(info.packages)
    return info


PARSER_REGISTRY: dict[str, callable] = {
    "dockerfile": parse_dockerfile,
    "terraform": parse_terraform,
    "package.json": parse_node_dependencies,
    "requirements.txt": parse_python_dependencies,
    "Cargo.toml": parse_cargo_dependencies,
    "go.mod": parse_go_dependencies,
}


def parse_artifact(path: str, content: str) -> Any:
    """Route to appropriate parser based on file path/name."""
    filename = path.split("/")[-1]
    if filename in PARSER_REGISTRY:
        return PARSER_REGISTRY[filename](content)
    if "Dockerfile" in filename:
        return parse_dockerfile(content)
    if filename.endswith(".tf"):
        return parse_terraform(content)
    lower = filename.lower()
    if lower in PARSER_REGISTRY:
        return PARSER_REGISTRY[lower](content)
    return None
