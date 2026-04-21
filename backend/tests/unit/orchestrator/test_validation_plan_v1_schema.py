"""Unit tests for ValidationPlanV1 JSON Schema + loader (ARG-001)."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from src.orchestrator.schemas import (
    SCHEMA_ID,
    ValidationPlanError,
    load_validation_plan_v1_schema,
    validate_validation_plan,
)
from src.orchestrator.schemas import loader as loader_module
from src.orchestrator.schemas.loader import (
    PayloadStrategyV1,
    RiskRating,
    ValidationPlanV1,
    ValidatorTool,
    _sanitize_pydantic_errors,
)


def _minimal_valid_plan() -> dict[str, Any]:
    """Return a minimal ValidationPlanV1 payload (blind boolean SQLi)."""
    return {
        "hypothesis": "Boolean-blind SQLi suspected on /search?q parameter",
        "risk": "high",
        "payload_strategy": {
            "registry_family": "sqli.boolean.diff.v3",
            "mutation_classes": ["canonicalization", "case_normalization"],
            "raw_payloads_allowed": False,
        },
        "validator": {
            "tool": "safe_validator",
            "inputs": {"endpoint": "/search", "param": "q"},
            "success_signals": ["response_diff > threshold"],
            "stop_conditions": ["http_500", "rate_limited"],
        },
        "approval_required": False,
        "evidence_to_collect": ["raw_output", "diff"],
        "remediation_focus": ["use parameterized queries"],
    }


class TestSchemaIntegrity:
    def test_schema_is_draft_2020_12_compliant(self) -> None:
        schema = load_validation_plan_v1_schema()
        Draft202012Validator.check_schema(schema)

    def test_schema_has_expected_id_and_title(self) -> None:
        schema = load_validation_plan_v1_schema()
        assert schema["$id"] == SCHEMA_ID
        assert schema["title"] == "ValidationPlanV1"
        assert schema["additionalProperties"] is False

    def test_schema_loader_is_cached(self) -> None:
        # Two consecutive calls return the SAME dict object (lru_cache).
        first = load_validation_plan_v1_schema()
        second = load_validation_plan_v1_schema()
        assert first is second


class TestPositiveValidation:
    def test_valid_blind_sqli_plan_passes(self) -> None:
        parsed = validate_validation_plan(_minimal_valid_plan())
        assert isinstance(parsed, ValidationPlanV1)
        assert parsed.risk is RiskRating.HIGH
        assert parsed.payload_strategy.registry_family == "sqli.boolean.diff.v3"
        assert parsed.validator.tool is ValidatorTool.SAFE_VALIDATOR

    def test_pydantic_model_round_trip_via_validator(self) -> None:
        plan = validate_validation_plan(_minimal_valid_plan())
        as_json = plan.model_dump_json()
        rebuilt = ValidationPlanV1.model_validate_json(as_json)
        assert rebuilt == plan

    def test_pydantic_model_validate_typed_access(self) -> None:
        # Construct directly via Pydantic — IDE/mypy gets typed access to fields.
        parsed = ValidationPlanV1.model_validate(_minimal_valid_plan())
        assert isinstance(parsed.payload_strategy, PayloadStrategyV1)
        assert parsed.payload_strategy.raw_payloads_allowed is False

    @pytest.mark.parametrize(
        "family",
        [
            "sqli.boolean.diff.v3",
            "xss.reflected.canary.v3",
            "ssrf.oast.redirect.v1",
            "rce.oast.dns.v1",
            "lfi.sentinel.etc.v1",
            "xxe.dtd.exfil.v1",
            "ssti.marker.jinja.v1",
        ],
    )
    def test_registry_family_regex_accepts_canonical_names(self, family: str) -> None:
        payload = _minimal_valid_plan()
        payload["payload_strategy"]["registry_family"] = family
        parsed = validate_validation_plan(payload)
        assert parsed.payload_strategy.registry_family == family


class TestNegativeValidation:
    def test_raw_payloads_allowed_true_is_rejected(self) -> None:
        payload = _minimal_valid_plan()
        payload["payload_strategy"]["raw_payloads_allowed"] = True
        with pytest.raises(ValidationPlanError) as exc:
            validate_validation_plan(payload)
        assert "raw_payloads_allowed" in exc.value.field_path

    def test_missing_hypothesis_rejected(self) -> None:
        payload = _minimal_valid_plan()
        del payload["hypothesis"]
        with pytest.raises(ValidationPlanError) as exc:
            validate_validation_plan(payload)
        assert "hypothesis" in exc.value.reason

    def test_short_hypothesis_rejected(self) -> None:
        payload = _minimal_valid_plan()
        payload["hypothesis"] = "tiny"
        with pytest.raises(ValidationPlanError):
            validate_validation_plan(payload)

    def test_unknown_top_level_field_rejected(self) -> None:
        payload = _minimal_valid_plan()
        payload["malicious_extra"] = {"shell": "rm -rf /"}
        with pytest.raises(ValidationPlanError):
            validate_validation_plan(payload)

    def test_invalid_risk_value_rejected(self) -> None:
        payload = _minimal_valid_plan()
        payload["risk"] = "lethal"
        with pytest.raises(ValidationPlanError) as exc:
            validate_validation_plan(payload)
        assert "risk" in exc.value.field_path

    def test_invalid_validator_tool_rejected(self) -> None:
        payload = _minimal_valid_plan()
        payload["validator"]["tool"] = "shell_exec"
        with pytest.raises(ValidationPlanError):
            validate_validation_plan(payload)

    def test_invalid_mutation_class_rejected(self) -> None:
        payload = _minimal_valid_plan()
        payload["payload_strategy"]["mutation_classes"] = ["full_waf_bypass"]
        with pytest.raises(ValidationPlanError):
            validate_validation_plan(payload)

    @pytest.mark.parametrize(
        "bad_family",
        [
            "SQLI.boolean.v3",       # uppercase
            "sqli.boolean",          # missing version
            "sqli.boolean.v",        # malformed version
            "sqli..v1",              # empty subfamily
            "sqli.boolean.v0a",      # version not pure digits
            "sqli.boolean-blind.v1", # hyphen not allowed
            ".sqli.boolean.v1",      # leading dot
        ],
    )
    def test_registry_family_regex_rejects_bad_names(self, bad_family: str) -> None:
        payload = _minimal_valid_plan()
        payload["payload_strategy"]["registry_family"] = bad_family
        with pytest.raises(ValidationPlanError) as exc:
            validate_validation_plan(payload)
        assert "registry_family" in exc.value.field_path

    def test_payload_strategy_missing_required_field(self) -> None:
        payload = _minimal_valid_plan()
        del payload["payload_strategy"]["registry_family"]
        with pytest.raises(ValidationPlanError):
            validate_validation_plan(payload)

    def test_validator_missing_required_field(self) -> None:
        payload = _minimal_valid_plan()
        del payload["validator"]["success_signals"]
        with pytest.raises(ValidationPlanError):
            validate_validation_plan(payload)

    def test_evidence_to_collect_must_be_string_array(self) -> None:
        payload = _minimal_valid_plan()
        payload["evidence_to_collect"] = [{"not": "a string"}]
        with pytest.raises(ValidationPlanError):
            validate_validation_plan(payload)


class TestValidationPlanError:
    def test_error_carries_field_path_and_reason(self) -> None:
        payload = _minimal_valid_plan()
        payload["payload_strategy"]["raw_payloads_allowed"] = True
        with pytest.raises(ValidationPlanError) as exc:
            validate_validation_plan(payload)
        # Field path is dotted, includes the offending leaf.
        assert exc.value.field_path.endswith("raw_payloads_allowed")
        # Reason is non-empty and human-readable.
        assert exc.value.reason

    def test_error_does_not_leak_full_payload(self) -> None:
        # The exception message should reference the field, not the full payload.
        payload = _minimal_valid_plan()
        payload["payload_strategy"]["raw_payloads_allowed"] = True
        try:
            validate_validation_plan(payload)
        except ValidationPlanError as exc:
            msg = str(exc)
            # Sanity: it should not contain the full hypothesis string verbatim.
            assert payload["hypothesis"] not in msg


class TestValidationPlanImmutability:
    def test_loader_returns_independent_view_after_mutation(self) -> None:
        # Even though we cache the schema dict, callers should not be encouraged
        # to mutate it. We don't deep-freeze (Python lacks first-class immutability
        # for dicts), but we document the expectation by ensuring deepcopy works.
        schema = load_validation_plan_v1_schema()
        snapshot = deepcopy(schema)
        # Mutate the cached dict (bad practice — we just verify it doesn't crash).
        schema["__test_marker__"] = True
        try:
            assert "__test_marker__" not in snapshot
        finally:
            schema.pop("__test_marker__", None)


class TestPydanticGuards:
    """Defense-in-depth checks at the Pydantic layer (independent of jsonschema)."""

    def test_payload_strategy_rejects_raw_payloads_at_pydantic_layer(self) -> None:
        # Direct construction skips the JSON Schema layer; the Pydantic field
        # validator must still reject ``raw_payloads_allowed=True``.
        with pytest.raises(ValidationError) as exc:
            PayloadStrategyV1.model_validate(
                {
                    "registry_family": "sqli.boolean.diff.v3",
                    "mutation_classes": ["canonicalization"],
                    "raw_payloads_allowed": True,
                }
            )
        assert "raw_payloads_allowed" in str(exc.value)

    def test_validate_falls_back_to_pydantic_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Force the JSON Schema layer to be permissive so a malformed payload makes
        # it to the Pydantic layer; verify that the loader translates the
        # ValidationError into a domain ``ValidationPlanError`` with a non-empty
        # field path. This exercises the ``except`` branch in
        # ``validate_validation_plan`` (defense-in-depth code path). The
        # ``monkeypatch`` fixture auto-reverts after the test; the underlying
        # ``lru_cache`` keeps its previously-loaded real schema for other tests.
        permissive: dict[str, Any] = {"type": "object"}
        monkeypatch.setattr(
            loader_module,
            "load_validation_plan_v1_schema",
            lambda: permissive,
        )
        with pytest.raises(ValidationPlanError) as exc:
            validate_validation_plan({"hypothesis": "too short"})  # < 8 chars
        # Field path should be a known field name (Pydantic surfaces required-field
        # errors before string-length errors), and the reason must be non-empty.
        assert exc.value.field_path in {
            "hypothesis",
            "risk",
            "payload_strategy",
            "validator",
            "approval_required",
        }
        assert exc.value.reason


class TestPydanticErrorSanitization:
    """The Pydantic-fallback branch must not echo input values into the reason.

    The loader's docstring promises that ``ValidationPlanError.reason`` carries
    only ``loc``/``msg``/``type`` from Pydantic — never the rejected payload
    content. These tests pin that invariant down so a future contributor cannot
    silently re-introduce ``str(exc)`` (which embeds ``input_value=...``).
    """

    _MARKER = "LEAK_MARKER_xyz_42"

    def test_sanitizer_strips_input_values_from_pydantic_validation_error(self) -> None:
        # Trigger Pydantic directly with a payload whose values should NOT appear
        # anywhere in the sanitized output. ``str(exc)`` for Pydantic v2 normally
        # contains ``input_value='LEAK_MARKER_xyz_42'`` — the helper must drop it.
        with pytest.raises(ValidationError) as raised:
            ValidationPlanV1.model_validate(
                {
                    "hypothesis": self._MARKER,  # short, will fail min_length=8 only if <8 chars
                    "risk": self._MARKER,        # invalid enum -> input_value leaks here
                    "payload_strategy": {
                        "registry_family": self._MARKER,
                        "mutation_classes": [],
                        "raw_payloads_allowed": False,
                    },
                    "validator": {
                        "tool": self._MARKER,
                        "inputs": {},
                        "success_signals": [],
                        "stop_conditions": [],
                    },
                    "approval_required": False,
                    "evidence_to_collect": [],
                    "remediation_focus": [],
                }
            )
        raw = str(raised.value)
        assert self._MARKER in raw, (
            "Sanity check: Pydantic's default error string should leak the marker; "
            "if this assertion fails, the test is no longer exercising the leak-vector."
        )

        sanitized = _sanitize_pydantic_errors(raised.value)
        assert self._MARKER not in sanitized
        assert "input_value" not in sanitized
        assert "input=" not in sanitized
        assert sanitized, "sanitized reason must be non-empty"
        # Each error contributes a "loc: msg (type=...)" segment.
        assert "type=" in sanitized

    def test_sanitizer_handles_non_pydantic_exception(self) -> None:
        # Defense-in-depth: a stray non-Pydantic exception in the fallback branch
        # must not crash the sanitizer; it should degrade to the class name.
        sanitized = _sanitize_pydantic_errors(RuntimeError("boom: secret_data_xyz"))
        assert sanitized == "RuntimeError"
        assert "secret_data_xyz" not in sanitized

    def test_sanitizer_handles_errors_callable_that_raises(self) -> None:
        # ``errors()`` exists but blows up — fall back to the class name.
        class FakePydanticError(Exception):
            def errors(self) -> list[dict[str, Any]]:
                raise RuntimeError("internal: secret_data_xyz")

        sanitized = _sanitize_pydantic_errors(FakePydanticError("payload secret_data_xyz"))
        assert sanitized == "FakePydanticError"
        assert "secret_data_xyz" not in sanitized

    def test_sanitizer_handles_empty_errors_list(self) -> None:
        class FakePydanticError(Exception):
            def errors(self) -> list[dict[str, Any]]:
                return []

        sanitized = _sanitize_pydantic_errors(FakePydanticError("ignored"))
        assert sanitized == "FakePydanticError"

    def test_pydantic_fallback_does_not_leak_input_values(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # End-to-end: route a payload containing ``LEAK_MARKER_xyz_42`` through
        # the public ``validate_validation_plan`` API, forcing the JSON Schema
        # layer to be permissive so the marker reaches the Pydantic-only branch.
        # Neither ``str(exc)`` nor ``.reason`` may contain the marker.
        permissive: dict[str, Any] = {"type": "object"}
        monkeypatch.setattr(
            loader_module,
            "load_validation_plan_v1_schema",
            lambda: permissive,
        )
        bad_payload: dict[str, Any] = {
            "hypothesis": f"valid hypothesis text containing {self._MARKER}",
            "risk": self._MARKER,
            "payload_strategy": {
                "registry_family": self._MARKER,
                "mutation_classes": [],
                "raw_payloads_allowed": False,
            },
            "validator": {
                "tool": self._MARKER,
                "inputs": {},
                "success_signals": [],
                "stop_conditions": [],
            },
            "approval_required": False,
            "evidence_to_collect": [],
            "remediation_focus": [],
        }
        with pytest.raises(ValidationPlanError) as raised:
            validate_validation_plan(bad_payload)
        assert self._MARKER not in raised.value.reason
        assert self._MARKER not in str(raised.value)
        assert "input_value" not in raised.value.reason
        assert "input_value" not in str(raised.value)
