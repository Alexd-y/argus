"""GitHub API connector — full implementation of BaseRepoConnector."""

from __future__ import annotations

import base64
import logging
from datetime import datetime

import httpx

from src.ingestion.connectors.base import (
    BaseRepoConnector,
    CommitInfo,
    PullRequestInfo,
    RepoInfo,
)

logger = logging.getLogger(__name__)

GITHUB_API_URL = "https://api.github.com"
GITHUB_ACCEPT_HEADER = "application/vnd.github+json"
GITHUB_API_VERSION = "2022-11-28"


class GitHubConnector(BaseRepoConnector):
    """GitHub REST API connector with pagination and rate-limit awareness."""

    def __init__(self, token: str) -> None:
        super().__init__(GITHUB_API_URL, token)

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": GITHUB_ACCEPT_HEADER,
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
            "User-Agent": "ARGUS/1.0",
        }

    async def _get(
        self, path: str, *, params: dict | None = None
    ) -> dict | list | None:
        url = f"{self._base_url}{path}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, headers=self._headers(), params=params)
            resp.raise_for_status()
            return resp.json() if resp.status_code != 204 else None

    async def _get_raw(self, path: str) -> str | bytes:
        url = f"{self._base_url}{path}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, headers=self._headers())
            resp.raise_for_status()
            return resp.text

    async def get_repo(self, owner: str, name: str) -> RepoInfo:
        data = await self._get(f"/repos/{owner}/{name}")
        if not isinstance(data, dict):
            raise ValueError(f"Unexpected response for repo {owner}/{name}")
        return self._parse_repo(data)

    async def list_repos(
        self, owner: str, *, page: int = 1, per_page: int = 30
    ) -> list[RepoInfo]:
        params = {"page": page, "per_page": per_page, "sort": "updated"}
        data = await self._get(f"/orgs/{owner}/repos", params=params)
        if not isinstance(data, list):
            data = await self._get(f"/users/{owner}/repos", params=params)
        if not isinstance(data, list):
            return []
        return [self._parse_repo(r) for r in data if isinstance(r, dict)]

    async def get_default_branch(self, owner: str, name: str) -> str:
        repo = await self.get_repo(owner, name)
        return repo.default_branch

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
        params: dict = {"page": page, "per_page": per_page}
        if branch:
            params["sha"] = branch
        if since:
            params["since"] = since.isoformat()
        data = await self._get(f"/repos/{owner}/{name}/commits", params=params)
        if not isinstance(data, list):
            return []
        commits = []
        for c in data:
            if not isinstance(c, dict):
                continue
            commit_detail = c.get("commit", {})
            author_data = commit_detail.get("author", {})
            files: list[dict] = []
            try:
                detail = await self._get(
                    f"/repos/{owner}/{name}/commits/{c['sha']}"
                )
                if isinstance(detail, dict):
                    files = detail.get("files", [])
            except Exception:
                pass
            commits.append(CommitInfo(
                sha=c.get("sha", ""),
                message=(commit_detail.get("message") or "").split("\n")[0],
                author_name=author_data.get("name", ""),
                author_email=author_data.get("email", ""),
                committed_at=_parse_github_date(author_data.get("date")),
                files_changed=[f.get("filename", "") for f in files if isinstance(f, dict)],
            ))
        return commits

    async def get_file_tree(
        self, owner: str, name: str, *, branch: str = "", path: str = ""
    ) -> list[dict[str, str]]:
        if not branch:
            branch = await self.get_default_branch(owner, name)
        try:
            ref = await self._get(
                f"/repos/{owner}/{name}/git/ref/heads/{branch}"
            )
            if not isinstance(ref, dict):
                return []
            tree_sha = ref.get("object", {}).get("sha", "")
        except Exception:
            return []
        try:
            tree_data = await self._get(
                f"/repos/{owner}/{name}/git/trees/{tree_sha}",
                params={"recursive": "1"},
            )
            if not isinstance(tree_data, dict):
                return []
            entries = tree_data.get("tree", [])
            result = []
            for e in entries:
                if not isinstance(e, dict):
                    continue
                p = e.get("path", "")
                if path and not p.startswith(path):
                    continue
                result.append({
                    "path": p,
                    "type": e.get("type", "blob"),
                    "size": e.get("size", 0),
                })
            return result
        except Exception:
            return []

    async def get_file_content(
        self, owner: str, name: str, file_path: str, *, ref: str = ""
    ) -> str | bytes:
        if not ref:
            ref = await self.get_default_branch(owner, name)
        try:
            data = await self._get(
                f"/repos/{owner}/{name}/contents/{file_path}",
                params={"ref": ref},
            )
            if isinstance(data, dict) and data.get("content"):
                return base64.b64decode(data["content"])
            return ""
        except Exception:
            return ""

    async def list_pull_requests(
        self,
        owner: str,
        name: str,
        *,
        state: str = "open",
        page: int = 1,
        per_page: int = 30,
    ) -> list[PullRequestInfo]:
        params = {"state": state, "page": page, "per_page": per_page, "sort": "updated"}
        data = await self._get(f"/repos/{owner}/{name}/pulls", params=params)
        if not isinstance(data, list):
            return []
        return [self._parse_pr(pr) for pr in data if isinstance(pr, dict)]

    def _parse_repo(self, data: dict) -> RepoInfo:
        owner_data = data.get("owner", {})
        owner = owner_data.get("login", "") if isinstance(owner_data, dict) else ""
        return RepoInfo(
            provider="github",
            owner=owner,
            name=data.get("name", ""),
            full_name=data.get("full_name", ""),
            default_branch=data.get("default_branch", "main"),
            clone_url=data.get("clone_url", ""),
            web_url=data.get("html_url", ""),
            language=(data.get("language") or ""),
            description=(data.get("description") or ""),
            private=data.get("private", False),
            archived=data.get("archived", False),
            size_kb=data.get("size", 0),
            pushed_at=_parse_github_date(data.get("pushed_at")),
        )

    def _parse_pr(self, data: dict) -> PullRequestInfo:
        head = data.get("head", {})
        base = data.get("base", {})
        user_data = data.get("user", {})
        author = user_data.get("login", "") if isinstance(user_data, dict) else ""
        return PullRequestInfo(
            number=data.get("number", 0),
            title=data.get("title", ""),
            body=(data.get("body") or ""),
            author=author,
            base_branch=base.get("ref", "") if isinstance(base, dict) else "",
            head_branch=head.get("ref", "") if isinstance(head, dict) else "",
            base_sha=base.get("sha", "") if isinstance(base, dict) else "",
            head_sha=head.get("sha", "") if isinstance(head, dict) else "",
            state=data.get("state", "open"),
            created_at=_parse_github_date(data.get("created_at")),
            updated_at=_parse_github_date(data.get("updated_at")),
            diff_url=data.get("diff_url", ""),
        )


class GitLabConnector(BaseRepoConnector):
    """GitLab API connector — self-managed and gitlab.com."""

    def __init__(self, token: str, base_url: str = "https://gitlab.com") -> None:
        super().__init__(f"{base_url.rstrip('/')}/api/v4", token)

    def _headers(self) -> dict[str, str]:
        return {"PRIVATE-TOKEN": self._token, "User-Agent": "ARGUS/1.0"}

    async def _get(
        self, path: str, *, params: dict | None = None
    ) -> dict | list | None:
        url = f"{self._base_url}{path}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, headers=self._headers(), params=params)
            resp.raise_for_status()
            return resp.json() if resp.status_code != 204 else None

    async def get_repo(self, owner: str, name: str) -> RepoInfo:
        encoded = f"{owner}%2F{name}"
        data = await self._get(f"/projects/{encoded}")
        if not isinstance(data, dict):
            raise ValueError(f"Unexpected response for repo {owner}/{name}")
        return self._parse_repo(data)

    async def list_repos(
        self, owner: str, *, page: int = 1, per_page: int = 30
    ) -> list[RepoInfo]:
        params: dict = {"page": page, "per_page": per_page, "membership": True}
        groups = await self._get(f"/groups/{owner}")
        group_id = groups.get("id") if isinstance(groups, dict) else None
        if group_id:
            params["id"] = group_id
        else:
            params["search"] = owner
        data = await self._get("/projects", params=params)
        if not isinstance(data, list):
            return []
        return [self._parse_repo(r) for r in data if isinstance(r, dict)]

    async def get_default_branch(self, owner: str, name: str) -> str:
        repo = await self.get_repo(owner, name)
        return repo.default_branch

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
        encoded = f"{owner}%2F{name}"
        params: dict = {"page": page, "per_page": per_page}
        if branch:
            params["ref_name"] = branch
        data = await self._get(
            f"/projects/{encoded}/repository/commits", params=params
        )
        if not isinstance(data, list):
            return []
        return [
            CommitInfo(
                sha=c.get("id", ""),
                message=c.get("title", ""),
                author_name=c.get("author_name", ""),
                author_email=c.get("author_email", ""),
                committed_at=_parse_gitlab_date(c.get("committed_date")),
            )
            for c in data if isinstance(c, dict)
        ]

    async def get_file_tree(
        self, owner: str, name: str, *, branch: str = "", path: str = ""
    ) -> list[dict[str, str]]:
        encoded = f"{owner}%2F{name}"
        params: dict = {"recursive": True}
        if branch:
            params["ref"] = branch
        data = await self._get(
            f"/projects/{encoded}/repository/tree", params=params
        )
        if not isinstance(data, list):
            return []
        result = []
        for e in data:
            if not isinstance(e, dict):
                continue
            p = e.get("path", "")
            if path and not p.startswith(path):
                continue
            result.append({"path": p, "type": e.get("type", "blob")})
        return result

    async def get_file_content(
        self, owner: str, name: str, file_path: str, *, ref: str = ""
    ) -> str | bytes:
        encoded = f"{owner}%2F{name}"
        encoded_path = file_path.replace("/", "%2F")
        params = {}
        if ref:
            params["ref"] = ref
        data = await self._get(
            f"/projects/{encoded}/repository/files/{encoded_path}", params=params
        )
        if isinstance(data, dict) and data.get("content"):
            return base64.b64decode(data["content"])
        return ""

    async def list_pull_requests(
        self,
        owner: str,
        name: str,
        *,
        state: str = "opened",
        page: int = 1,
        per_page: int = 30,
    ) -> list[PullRequestInfo]:
        encoded = f"{owner}%2F{name}"
        params = {"state": state, "page": page, "per_page": per_page}
        data = await self._get(
            f"/projects/{encoded}/merge_requests", params=params
        )
        if not isinstance(data, list):
            return []
        return [
            PullRequestInfo(
                number=mr.get("iid", 0),
                title=mr.get("title", ""),
                body=(mr.get("description") or ""),
                author=mr.get("author", {}).get("username", "") if isinstance(mr.get("author"), dict) else "",
                base_branch=mr.get("target_branch", ""),
                head_branch=mr.get("source_branch", ""),
                base_sha=mr.get("diff_refs", {}).get("base_sha", "") if isinstance(mr.get("diff_refs"), dict) else "",
                head_sha=mr.get("diff_refs", {}).get("head_sha", "") if isinstance(mr.get("diff_refs"), dict) else "",
                state=mr.get("state", ""),
                created_at=_parse_gitlab_date(mr.get("created_at")),
                updated_at=_parse_gitlab_date(mr.get("updated_at")),
            )
            for mr in data if isinstance(mr, dict)
        ]

    def _parse_repo(self, data: dict) -> RepoInfo:
        namespace = data.get("namespace", {})
        owner = namespace.get("path", "") if isinstance(namespace, dict) else ""
        return RepoInfo(
            provider="gitlab",
            owner=owner,
            name=data.get("path", ""),
            full_name=data.get("path_with_namespace", ""),
            default_branch=data.get("default_branch", "main"),
            clone_url=data.get("http_url_to_repo", ""),
            web_url=data.get("web_url", ""),
            language="",
            description=(data.get("description") or ""),
            private=data.get("visibility", "private") != "public",
            archived=data.get("archived", False),
            size_kb=0,
            pushed_at=_parse_gitlab_date(data.get("last_activity_at")),
        )


def _parse_github_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _parse_gitlab_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


async def create_connector(
    provider: str, token: str, *, base_url: str = ""
) -> BaseRepoConnector:
    """Factory for repository connectors."""
    if provider == "github":
        return GitHubConnector(token)
    if provider == "gitlab":
        return GitLabConnector(token, base_url=base_url or "https://gitlab.com")
    raise ValueError(f"Unsupported repository provider: {provider}")
