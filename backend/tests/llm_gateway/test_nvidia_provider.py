"""WP C — NVIDIA providers in the alias registry + sensitive-task guard.

Pure/offline. Hosted NVIDIA is a cloud provider for NON-sensitive tasks; a
provider-level guard (defence in depth over the facade's WRB-001) must refuse to
select a ``sensitive_allowed=False`` provider for a sensitive task.
"""

from __future__ import annotations

import asyncio

import pytest
from src.llm_gateway.provider_clients import ALIAS_REGISTRY, ProviderRouter
from src.llm_gateway.router import AllProvidersFailedError


def test_hosted_nvidia_alias_is_cloud_and_not_sensitive() -> None:
    prov = ALIAS_REGISTRY["argus-nvidia-hosted"]["providers"][0]
    assert prov["key"] == "nvidia-hosted"
    assert prov["base_url"] == "https://integrate.api.nvidia.com/v1"
    assert prov["cloud_allowed"] is True
    assert prov["sensitive_allowed"] is False


def test_self_hosted_nim_alias_is_local() -> None:
    prov = ALIAS_REGISTRY["argus-nvidia-nim-local"]["providers"][0]
    assert prov["key"] == "nvidia-nim-local"
    assert prov["cloud_allowed"] is False


def test_hosted_nvidia_api_key_env(monkeypatch) -> None:
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-secret-xyz-123456")
    router = ProviderRouter()
    assert router._get_api_key("nvidia-hosted") == "nvapi-secret-xyz-123456"


def test_sensitive_task_cannot_select_hosted_nvidia() -> None:
    router = ProviderRouter()
    with pytest.raises(AllProvidersFailedError):
        asyncio.run(router.select_provider("argus-nvidia-hosted", {"sensitive": True}))


def test_non_sensitive_task_selects_hosted_nvidia() -> None:
    router = ProviderRouter()
    prov = asyncio.run(router.select_provider("argus-nvidia-hosted", {"sensitive": False}))
    assert prov["key"] == "nvidia-hosted"
