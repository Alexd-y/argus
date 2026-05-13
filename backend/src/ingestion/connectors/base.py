"""Abstract base class for repository connectors (GitHub, GitLab, Bitbucket).

All connectors implement the same interface for uniform ingestion.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class RepoInfo:
    """Normalized repository metadata across all providers."""

    provider: str  # github | gitlab | bitbucket
    owner: str
    name: str
    full_name: str  # owner/name
    default_branch: str = "main"
    clone_url: str = ""
    web_url: str = ""
    language: str = ""
    description: str = ""
    private: bool = False
    archived: bool = False
    size_kb: int = 0
    pushed_at: datetime | None = None


@dataclass
class CommitInfo:
    """Normalized commit metadata."""

    sha: str
    message: str
    author_name: str
    author_email: str
    committed_at: datetime
    additions: int = 0
    deletions: int = 0
    files_changed: list[str] = field(default_factory=list)


@dataclass
class PullRequestInfo:
    """Normalized PR metadata."""

    number: int
    title: str
    body: str
    author: str
    base_branch: str
    head_branch: str
    base_sha: str
    head_sha: str
    state: str  # open | closed | merged
    created_at: datetime | None = None
    updated_at: datetime | None = None
    diff_url: str = ""


class BaseRepoConnector(ABC):
    """Abstract connector — all repository connectors inherit from this."""

    def __init__(self, base_url: str, token: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = token

    @abstractmethod
    async def get_repo(self, owner: str, name: str) -> RepoInfo:
        """Fetch repository metadata."""

    @abstractmethod
    async def list_repos(
        self, owner: str, *, page: int = 1, per_page: int = 30
    ) -> list[RepoInfo]:
        """Paginated list of repositories for owner."""

    @abstractmethod
    async def get_default_branch(self, owner: str, name: str) -> str:
        """Get the default branch name for a repository."""

    @abstractmethod
    async def list_commits(
        self,
        owner: str,
        name: str,
        *,
        branch: str = "",
        since: datetime | None = None,
        page: int = 1,
        per_page: int = 100,
    ) -> list[CommitInfo]:
        """Paginated list of commits."""

    @abstractmethod
    async def get_file_tree(
        self, owner: str, name: str, *, branch: str = "", path: str = ""
    ) -> list[dict[str, str]]:
        """Get repository file tree. Returns [{"path": ..., "type": "blob"|"tree"}]."""

    @abstractmethod
    async def get_file_content(
        self, owner: str, name: str, file_path: str, *, ref: str = ""
    ) -> str | bytes:
        """Get file content at a given ref (branch/commit)."""

    @abstractmethod
    async def list_pull_requests(
        self,
        owner: str,
        name: str,
        *,
        state: str = "open",
        page: int = 1,
        per_page: int = 30,
    ) -> list[PullRequestInfo]:
        """Paginated list of PRs."""
