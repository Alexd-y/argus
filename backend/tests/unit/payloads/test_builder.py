"""Unit tests for :mod:`src.payloads.builder` (ARG-005, Backlog/dev1_md §6, §7).

The builder is the canonical path between a signed
:class:`~src.payloads.registry.PayloadFamily` and a deterministic
:class:`~src.payloads.builder.PayloadBundle`. The tests assert:

* Determinism — same correlation key + family yields the same manifest hash.
* Approval gate — high-risk families must carry an approval_id.
* Placeholder substitution — every ``{name}`` must resolve.
* Encoding pipeline selection — first declared if not requested, looked up by name otherwise.
* Output format — RenderedPayload fields are stable & frozen.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.payloads.builder import (
    PayloadApprovalRequiredError,
    PayloadBuildError,
    PayloadBuildRequest,
    PayloadBuilder,
    PayloadBundle,
    RenderedPayload,
)
from src.payloads.registry import PayloadRegistry


@pytest.fixture()
def loaded_registry(
    signed_payloads_dir: tuple[Path, Path, Path, str],
) -> PayloadRegistry:
    payloads_dir, keys_dir, signatures_path, _ = signed_payloads_dir
    registry = PayloadRegistry(
        payloads_dir=payloads_dir, keys_dir=keys_dir, signatures_path=signatures_path
    )
    registry.load()
    return registry


@pytest.fixture()
def builder(loaded_registry: PayloadRegistry) -> PayloadBuilder:
    return PayloadBuilder(loaded_registry)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_build_returns_payload_bundle_with_expected_fields(
    builder: PayloadBuilder,
) -> None:
    request = PayloadBuildRequest(
        family_id="demo_sqli",
        correlation_key="scan-1|hyp-1",
        parameters={"param": "id", "canary": "abc123"},
    )
    bundle = builder.build(request)

    assert isinstance(bundle, PayloadBundle)
    assert bundle.family_id == "demo_sqli"
    assert bundle.encoding_pipeline == "identity"  # first declared
    assert bundle.requires_approval is False
    assert bundle.approval_id is None
    assert bundle.oast_required is False
    assert len(bundle.payloads) == 3  # all three seeds rendered
    assert len(bundle.manifest_hash) == 64
    for rendered in bundle.payloads:
        assert isinstance(rendered, RenderedPayload)
        assert rendered.payload != ""


def test_build_is_deterministic_given_same_correlation_key(
    builder: PayloadBuilder,
) -> None:
    base = {
        "family_id": "demo_sqli",
        "correlation_key": "scan-1|hyp-1",
        "parameters": {"param": "id", "canary": "abc"},
    }
    a = builder.build(PayloadBuildRequest(**base))  # type: ignore[arg-type]
    b = builder.build(PayloadBuildRequest(**base))  # type: ignore[arg-type]
    assert a.manifest_hash == b.manifest_hash
    assert [p.payload for p in a.payloads] == [p.payload for p in b.payloads]


def test_build_changes_with_different_correlation_key(
    builder: PayloadBuilder,
) -> None:
    a = builder.build(
        PayloadBuildRequest(
            family_id="demo_sqli",
            correlation_key="scan-1",
            parameters={"param": "id", "canary": "x"},
        )
    )
    b = builder.build(
        PayloadBuildRequest(
            family_id="demo_sqli",
            correlation_key="scan-99",
            parameters={"param": "id", "canary": "x"},
        )
    )
    assert a.manifest_hash != b.manifest_hash


# ---------------------------------------------------------------------------
# Approval gate
# ---------------------------------------------------------------------------


def test_high_risk_family_without_approval_raises(builder: PayloadBuilder) -> None:
    with pytest.raises(PayloadApprovalRequiredError) as exc_info:
        builder.build(
            PayloadBuildRequest(
                family_id="demo_rce",
                correlation_key="scan-1",
                parameters={"param": "id", "canary": "x"},
            )
        )
    assert exc_info.value.family_id == "demo_rce"


def test_high_risk_family_with_approval_succeeds(builder: PayloadBuilder) -> None:
    bundle = builder.build(
        PayloadBuildRequest(
            family_id="demo_rce",
            correlation_key="scan-1",
            parameters={"param": "id", "canary": "x"},
            approval_id="op-12345",
        )
    )
    assert bundle.requires_approval is True
    assert bundle.approval_id == "op-12345"


def test_non_high_risk_family_with_approval_id_rejected(
    builder: PayloadBuilder,
) -> None:
    with pytest.raises(PayloadBuildError, match="does not require approval"):
        builder.build(
            PayloadBuildRequest(
                family_id="demo_sqli",
                correlation_key="scan-1",
                parameters={"param": "id", "canary": "x"},
                approval_id="op-12345",
            )
        )


# ---------------------------------------------------------------------------
# Encoding pipeline selection
# ---------------------------------------------------------------------------


def test_default_encoding_pipeline_is_first_declared(builder: PayloadBuilder) -> None:
    bundle = builder.build(
        PayloadBuildRequest(
            family_id="demo_sqli",
            correlation_key="k",
            parameters={"param": "id", "canary": "x"},
        )
    )
    assert bundle.encoding_pipeline == "identity"


def test_named_encoding_pipeline_is_resolved(builder: PayloadBuilder) -> None:
    bundle = builder.build(
        PayloadBuildRequest(
            family_id="demo_sqli",
            correlation_key="k",
            parameters={"param": "id", "canary": "x"},
            encoding_pipeline="url_only",
        )
    )
    assert bundle.encoding_pipeline == "url_only"
    # The payload should have been URL-encoded — at least one '%' marker present
    # in any payload that contained metacharacters.
    assert any("%" in p.payload for p in bundle.payloads)


def test_unknown_encoding_pipeline_raises(builder: PayloadBuilder) -> None:
    with pytest.raises(PayloadBuildError, match="unknown encoding pipeline"):
        builder.build(
            PayloadBuildRequest(
                family_id="demo_sqli",
                correlation_key="k",
                parameters={"param": "id", "canary": "x"},
                encoding_pipeline="nope",
            )
        )


# ---------------------------------------------------------------------------
# Placeholder substitution
# ---------------------------------------------------------------------------


def test_missing_parameter_raises(builder: PayloadBuilder) -> None:
    with pytest.raises(PayloadBuildError, match="missing parameter"):
        builder.build(
            PayloadBuildRequest(
                family_id="demo_sqli",
                correlation_key="k",
                parameters={"param": "id"},  # missing 'canary'
            )
        )


def test_unknown_family_id_raises(builder: PayloadBuilder) -> None:
    with pytest.raises(PayloadBuildError, match="unknown payload family_id"):
        builder.build(
            PayloadBuildRequest(family_id="ghost", correlation_key="k", parameters={})
        )


# ---------------------------------------------------------------------------
# Output format / frozen models
# ---------------------------------------------------------------------------


def test_rendered_payload_is_frozen(builder: PayloadBuilder) -> None:
    bundle = builder.build(
        PayloadBuildRequest(
            family_id="demo_sqli",
            correlation_key="k",
            parameters={"param": "id", "canary": "x"},
        )
    )
    rendered = bundle.payloads[0]
    with pytest.raises(Exception):
        rendered.payload = "tampered"  # type: ignore[misc]


def test_to_serialisable_returns_json_safe_dict(builder: PayloadBuilder) -> None:
    bundle = builder.build(
        PayloadBuildRequest(
            family_id="demo_sqli",
            correlation_key="k",
            parameters={"param": "id", "canary": "x"},
        )
    )
    serial = bundle.to_serialisable()
    assert serial["family_id"] == "demo_sqli"
    assert serial["encoding_pipeline"] == "identity"
    assert serial["manifest_hash"] == bundle.manifest_hash
    assert len(serial["payloads"]) == 3  # type: ignore[arg-type]
    assert all(isinstance(p, dict) for p in serial["payloads"])  # type: ignore[union-attr]


def test_max_payloads_caps_output(builder: PayloadBuilder) -> None:
    bundle = builder.build(
        PayloadBuildRequest(
            family_id="demo_sqli",
            correlation_key="k",
            parameters={"param": "id", "canary": "x"},
            max_payloads=2,
        )
    )
    assert len(bundle.payloads) == 2


def test_payload_indices_are_zero_based_and_dense(builder: PayloadBuilder) -> None:
    bundle = builder.build(
        PayloadBuildRequest(
            family_id="demo_sqli",
            correlation_key="k",
            parameters={"param": "id", "canary": "x"},
        )
    )
    assert [p.index for p in bundle.payloads] == list(range(len(bundle.payloads)))
