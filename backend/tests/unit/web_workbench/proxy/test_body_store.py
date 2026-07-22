"""Unit tests for the spilled-body object backend (WB-P2a-2)."""

from __future__ import annotations

from src.web_workbench.proxy.body_store import (
    InMemoryBodyObjectStore,
    build_body_key,
)


def test_build_body_key_is_content_addressed_and_scoped() -> None:
    key = build_body_key("tenant-1", "proj-1", "a" * 64)
    assert key == f"tenant-1/proj-1/attachments/{'a' * 64}.body"


def test_in_memory_put_get_round_trip() -> None:
    store = InMemoryBodyObjectStore()
    data = b"body-bytes"
    key = store.put(tenant_id="t", project_id="p", sha256="d" * 64, data=data, content_type=None)
    assert store.get(key) == data


def test_in_memory_get_missing_returns_none() -> None:
    assert InMemoryBodyObjectStore().get("nope") is None


def test_in_memory_dedup_same_content_same_key() -> None:
    store = InMemoryBodyObjectStore()
    k1 = store.put(tenant_id="t", project_id="p", sha256="e" * 64, data=b"x", content_type=None)
    k2 = store.put(tenant_id="t", project_id="p", sha256="e" * 64, data=b"x", content_type=None)
    assert k1 == k2
