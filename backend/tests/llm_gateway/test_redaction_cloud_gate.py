"""WP C — content redaction gate before any cloud egress.

Pure/offline. The gate must strip NOT ONLY API keys but PII and the engagement
target before a prompt/response leaves for a cloud provider (hosted NVIDIA,
DeepSeek, …). Otherwise evidence/PII leaks to the cloud — the critical WRB-001
boundary.
"""

from __future__ import annotations

from src.llm_gateway.redaction import (
    redact_api_keys,
    redact_for_cloud_egress,
)


def test_nvidia_api_key_is_masked() -> None:
    masked = redact_api_keys("auth nvapi-abcDEF123456_78-90 trailing")
    assert "nvapi-abcDEF123456_78-90" not in masked
    assert "<REDACTED:nvidia_key>" in masked


def test_gate_masks_email_pii() -> None:
    result = redact_for_cloud_egress("contact admin@victim.example.com for access")
    assert "admin@victim.example.com" not in result.text
    assert result.redactions_applied >= 1
    assert "email" in result.categories


def test_gate_masks_engagement_target() -> None:
    result = redact_for_cloud_egress(
        "found SQLi on https://victim.example.com/login?id=1",
        targets=["victim.example.com"],
    )
    assert "victim.example.com" not in result.text
    assert "target" in result.categories


def test_gate_masks_public_ip_target() -> None:
    result = redact_for_cloud_egress("host 203.0.113.37 responded", targets=["203.0.113.37"])
    assert "203.0.113.37" not in result.text


def test_gate_composes_key_redaction() -> None:
    result = redact_for_cloud_egress("key nvapi-zzz999_abcdef is live")
    assert "nvapi-zzz999_abcdef" not in result.text
    assert "<REDACTED:nvidia_key>" in result.text


def test_clean_text_is_unchanged_and_zero_applied() -> None:
    text = "A benign sentence about remediation steps."
    result = redact_for_cloud_egress(text)
    assert result.text == text
    assert result.redactions_applied == 0
    assert result.categories == set()
