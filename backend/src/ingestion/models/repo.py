"""Repository and artifact models for ingestion layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class ArtifactType(str, Enum):
    SOURCE_CODE = "source_code"
    CONFIG = "config"
    IAC = "iac"  # Infrastructure as Code
    DEPENDENCY_MANIFEST = "dependency_manifest"
    DOCKERFILE = "dockerfile"
    SBOM = "sbom"
    SECRETS_SCAN = "secrets_scan"
    BINARY = "binary"
    TELEMETRY = "telemetry"
    OTHER = "other"


@dataclass
class Repository:
    id: str = ""
    tenant_id: str = ""
    provider: str = ""  # github | gitlab | bitbucket
    owner: str = ""
    name: str = ""
    full_name: str = ""
    default_branch: str = "main"
    clone_url: str = ""
    web_url: str = ""
    language: str = ""
    description: str = ""
    private: bool = False
    archived: bool = False
    webhook_secret: str = ""
    size_kb: int = 0
    last_synced_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RepoArtifact:
    id: str = ""
    tenant_id: str = ""
    repo_id: str = ""
    path: str = ""
    artifact_type: ArtifactType = ArtifactType.SOURCE_CODE
    content_hash: str = ""
    commit_sha: str = ""
    source: str = ""  # webhook | sync | manual
    size_bytes: int = 0
    parsed_info: dict[str, Any] | None = None
    synced_at: datetime | None = None
    created_at: datetime | None = None


@dataclass
class ScanTarget:
    id: str = ""
    tenant_id: str = ""
    repo_id: str = ""
    target_type: str = ""  # full_repo | pr_diff | file_paths | binary
    target_ref: str = ""  # commit sha, branch, or PR number
    paths: list[str] = field(default_factory=list)
    scan_options: dict[str, Any] = field(default_factory=dict)
    status: str = "pending"
    created_at: datetime | None = None
