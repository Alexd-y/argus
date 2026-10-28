"""Paste-dump + public-repo leak collectors.

* :class:`PsbdmpPasteCollector` — paste-dump index (domain/email selectors).
* :class:`GithubLeakCollector` — public-repo secret/mention search via the
  existing :class:`src.data_sources.github_client.GitHubClient`.

Both gated; both skip silently when their key is unset.
"""

from __future__ import annotations

from typing import Any

from src.data_sources.github_client import GitHubClient
from src.data_sources.psbdmp_client import PsbdmpClient
from src.intel.dark_web.collectors.base import BaseCollector
from src.intel.dark_web.contracts import (
    DarkWebRawRecord,
    DarkWebSelector,
    ExposureType,
    SelectorKind,
    SourceNetwork,
)


def _as_list(data: Any) -> list[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("data", "results", "items", "dumps"):
            v = data.get(key)
            if isinstance(v, list):
                return v
    return []


class PsbdmpPasteCollector(BaseCollector):
    name = "paste_psbdmp"
    network = SourceNetwork.PASTE
    accepts = (SelectorKind.DOMAIN, SelectorKind.EMAIL, SelectorKind.KEYWORD)

    def __init__(self, client: PsbdmpClient | None = None) -> None:
        self._client = client or PsbdmpClient()

    def is_enabled(self) -> bool:
        return self._client.is_available()

    async def collect(self, selector: DarkWebSelector) -> list[DarkWebRawRecord]:
        resp = await self._client.query(domain=selector.value)
        out: list[DarkWebRawRecord] = []
        for item in _as_list(resp.get("data")):
            pid = str(item.get("id", "")) if isinstance(item, dict) else str(item)
            out.append(
                DarkWebRawRecord(
                    selector_id=selector.id,
                    source_network=SourceNetwork.PASTE,
                    source_ref=f"psbdmp:{pid}",
                    exposure_hint=ExposureType.DOCUMENT,
                    content=f"Paste dump referencing '{selector.value}' (id {pid}).",
                    collector="paste_psbdmp@1",
                    extra={"paste_id": pid},
                )
            )
        return out


class GithubLeakCollector(BaseCollector):
    name = "repo_github"
    network = SourceNetwork.REPO
    accepts = (SelectorKind.DOMAIN, SelectorKind.KEYWORD)

    def __init__(self, client: GitHubClient | None = None) -> None:
        self._client = client or GitHubClient()

    def is_enabled(self) -> bool:
        return self._client.is_available()

    async def collect(self, selector: DarkWebSelector) -> list[DarkWebRawRecord]:
        # GitHubClient dispatches on kwargs; a code-search for the target keyword.
        resp = await self._client.query(
            query_type="code_search", query=selector.value, q=selector.value
        )
        out: list[DarkWebRawRecord] = []
        for item in _as_list(resp.get("data"))[:25]:
            repo = ""
            path = ""
            if isinstance(item, dict):
                repo = str(
                    item.get("repository", {}).get("full_name")
                    if isinstance(item.get("repository"), dict)
                    else item.get("repository") or ""
                )
                path = str(item.get("path", ""))
            ref = f"github:{repo}:{path}".strip(":")
            out.append(
                DarkWebRawRecord(
                    selector_id=selector.id,
                    source_network=SourceNetwork.REPO,
                    source_ref=ref or "github",
                    exposure_hint=ExposureType.SECRET_KEY,
                    content=f"Public-repo hit for '{selector.value}' in {repo}/{path}.",
                    collector="repo_github@1",
                    extra={"repo": repo, "path": path},
                )
            )
        return out
