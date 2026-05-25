"""Authentication and scoping configuration for target applications.

Provides Pydantic models for declarative authentication configuration,
including login flow descriptions, success conditions, and rules of
engagement. Inspired by Shannon's YAML config system but adapted for
ARGUS's multi-tenant architecture and existing scope/policy infrastructure.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    model_validator,
)


class LoginType(StrEnum):
    """Supported authentication mechanisms."""

    FORM = "form"
    SSO = "sso"
    API = "api"
    BASIC = "basic"


class SuccessConditionType(StrEnum):
    """Types of post-login success checks."""

    URL_CONTAINS = "url_contains"
    STATUS_CODE = "status_code"
    BODY_CONTAINS = "body_contains"
    HEADER_CONTAINS = "header_contains"
    COOKIE_EXISTS = "cookie_exists"


class SuccessCondition(BaseModel):
    """How to verify that authentication succeeded."""

    model_config = ConfigDict(extra="forbid")

    type: SuccessConditionType = Field(
        description="Type of success check to perform.",
    )
    value: StrictStr = Field(
        min_length=1,
        max_length=2048,
        description="Expected value for the success check.",
    )


class EmailLoginConfig(BaseModel):
    """Credentials for magic-link / email-OTP flows."""

    model_config = ConfigDict(extra="forbid")

    address: StrictStr = Field(min_length=1, max_length=512)
    password: StrictStr = Field(min_length=0, max_length=256, default="")
    totp_secret: StrictStr | None = Field(
        default=None,
        max_length=128,
        description="TOTP secret for email inbox 2FA.",
    )


class AuthCredentials(BaseModel):
    """Target application credentials with placeholder support.

    Placeholders ``$username``, ``$password``, ``$totp``,
    ``$email_address``, ``$email_password``, ``$email_totp`` are
    resolved at runtime by :meth:`AuthConfig.resolve_placeholders`.
    """

    model_config = ConfigDict(extra="forbid")

    username: StrictStr = Field(min_length=1, max_length=256)
    password: StrictStr = Field(min_length=0, max_length=256)
    totp_secret: StrictStr | None = Field(
        default=None,
        max_length=128,
        description="TOTP secret for 2FA (RFC 6238).",
    )
    email_login: EmailLoginConfig | None = Field(
        default=None,
        description="Mailbox credentials for magic-link / email-OTP flows.",
    )


class LoginFlowStep(BaseModel):
    """A single declarative step in a login flow.

    Supports placeholder tokens that are resolved at runtime:

    * ``$username`` — resolved from ``credentials.username``
    * ``$password`` — resolved from ``credentials.password``
    * ``$totp`` — resolved by generating a TOTP code from ``credentials.totp_secret``
    * ``$email_address`` — resolved from ``credentials.email_login.address``
    * ``$email_password`` — resolved from ``credentials.email_login.password``
    * ``$email_totp`` — resolved by generating a TOTP code from ``credentials.email_login.totp_secret``
    """

    model_config = ConfigDict(extra="forbid")

    instruction: StrictStr = Field(
        min_length=1,
        max_length=2048,
        description="Natural-language instruction for the login step.",
    )


class AuthConfig(BaseModel):
    """Full authentication configuration for a target application.

    Example YAML::

        authentication:
          login_type: form
          login_url: "https://app.example.com/login"
          credentials:
            username: "test@example.com"
            password: "s3cret"
            totp_secret: "JBSWY3DPEHPK3PXP"
          login_flow:
            - instruction: "Type $username into the email field"
            - instruction: "Type $password into the password field"
            - instruction: "Click the Sign In button"
            - instruction: "If prompted for 2FA, type $totp into the code field"
          success_condition:
            type: url_contains
            value: "/dashboard"
    """

    model_config = ConfigDict(extra="forbid")

    login_type: LoginType = Field(
        description="Authentication mechanism to use.",
    )
    login_url: StrictStr = Field(
        min_length=1,
        max_length=2048,
        description="URL of the login page or API endpoint.",
    )
    credentials: AuthCredentials = Field(
        description="Credentials for the target application.",
    )
    login_flow: list[LoginFlowStep] = Field(
        default_factory=list,
        max_length=32,
        description="Ordered list of steps to perform during login.",
    )
    success_condition: SuccessCondition | None = Field(
        default=None,
        description="How to verify that authentication succeeded.",
    )


class ScopeRuleConfig(BaseModel):
    """A single focus or avoid rule for the scan scope."""

    model_config = ConfigDict(extra="forbid")

    description: StrictStr = Field(
        min_length=1,
        max_length=512,
        description="Human-readable description of this rule.",
    )
    type: StrictStr = Field(
        description="Rule type: url_path, subdomain, domain, method, header, parameter, code_path.",
    )
    value: StrictStr = Field(
        min_length=1,
        max_length=2048,
        description="Pattern or value to match.",
    )


class RulesOfEngagement(BaseModel):
    """Free-form and structured rules governing scan behavior."""

    model_config = ConfigDict(extra="forbid")

    description: StrictStr = Field(
        default="",
        max_length=5000,
        description="Free-form description of the target environment and context.",
    )
    focus: list[ScopeRuleConfig] = Field(
        default_factory=list,
        max_length=64,
        description="Areas the scan should emphasize.",
    )
    avoid: list[ScopeRuleConfig] = Field(
        default_factory=list,
        max_length=64,
        description="Areas the scan should skip or de-emphasize.",
    )
    max_rps: StrictInt = Field(
        default=10,
        ge=1,
        le=1000,
        description="Maximum requests per second per endpoint.",
    )
    max_concurrent: StrictInt = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum concurrent pipelines/agents.",
    )
    rules_text: StrictStr = Field(
        default="",
        max_length=10000,
        description="Free-form rules of engagement text.",
    )


class TargetConfig(BaseModel):
    """Top-level configuration combining auth, scope, and scan settings.

    This is the primary config object loaded from YAML/JSON files.
    It composes :class:`AuthConfig`, :class:`RulesOfEngagement`,
    and scan-level settings (``vuln_classes``, ``exploit``).

    Example YAML::

        description: "Next.js app on PostgreSQL"
        authentication:
          login_type: form
          login_url: "https://app.example.com/login"
          credentials:
            username: "user"
            password: "pass"
          success_condition:
            type: url_contains
            value: "/dashboard"
        rules:
          focus:
            - description: "Emphasize API endpoints"
              type: url_path
              value: "/api"
          avoid:
            - description: "Skip logout"
              type: url_path
              value: "/logout"
        vuln_classes: [injection, xss, ssrf]
        exploit: true
    """

    model_config = ConfigDict(extra="forbid")

    description: StrictStr = Field(
        default="",
        max_length=500,
        description="Human-readable description of the target environment.",
    )
    authentication: AuthConfig | None = Field(
        default=None,
        description="Authentication configuration for the target application.",
    )
    rules: RulesOfEngagement = Field(
        default_factory=RulesOfEngagement,
        description="Rules of engagement governing scan behavior.",
    )
    vuln_classes: list[StrictStr] = Field(
        default_factory=list,
        max_length=8,
        description="Which vulnerability classes to test (empty = all).",
    )
    exploit: StrictBool = Field(
        default=True,
        description="Whether to run the exploitation phase.",
    )

    def resolve_placeholders(self) -> "TargetConfig":
        """Return a copy with ``$username``, ``$password``, ``$totp``
        placeholders resolved from credentials.

        TOTP codes are generated at resolution time using :mod:`pyotp`
        (if available).  If ``pyotp`` is not installed, any ``$totp``
        placeholders are left as-is.
        """
        if self.authentication is None:
            return self

        creds = self.authentication.credentials
        totp_code = self._generate_totp(creds.totp_secret)

        placeholder_map: dict[str, str] = {
            "$username": creds.username,
            "$password": creds.password,
            "$totp": totp_code or "$totp",
        }
        if creds.email_login is not None:
            email_totp = self._generate_totp(creds.email_login.totp_secret)
            placeholder_map["$email_address"] = creds.email_login.address
            placeholder_map["$email_password"] = creds.email_login.password
            placeholder_map["$email_totp"] = email_totp or "$email_totp"

        resolved_steps = [
            LoginFlowStep(
                instruction=self._replace_placeholders(step.instruction, placeholder_map)
            )
            for step in self.authentication.login_flow
        ]

        data = self.model_dump()
        if data.get("authentication") and data["authentication"].get("login_flow"):
            for i, step in enumerate(resolved_steps):
                data["authentication"]["login_flow"][i]["instruction"] = step.instruction

        return TargetConfig.model_validate(data)

    @staticmethod
    def _replace_placeholders(text: str, mapping: dict[str, str]) -> str:
        for placeholder, value in mapping.items():
            text = text.replace(placeholder, value)
        return text

    @staticmethod
    def _generate_totp(secret: str | None) -> str | None:
        if secret is None:
            return None
        try:
            import pyotp

            return pyotp.TOTP(secret).now()
        except ImportError:
            return None

    @classmethod
    def from_yaml(cls, content: str) -> "TargetConfig":
        """Load a :class:`TargetConfig` from a YAML string."""
        data = yaml.safe_load(content)
        if data is None:
            data = {}
        return cls.model_validate(data)

    @classmethod
    def from_yaml_file(cls, path: str) -> "TargetConfig":
        """Load a :class:`TargetConfig` from a YAML file path."""
        with open(path, encoding="utf-8") as f:
            return cls.from_yaml(f.read())

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "TargetConfig":
        """Load a :class:`TargetConfig` from a JSON-compatible dict."""
        return cls.model_validate(data)


__all__ = [
    "AuthConfig",
    "AuthCredentials",
    "EmailLoginConfig",
    "LoginFlowStep",
    "LoginType",
    "RulesOfEngagement",
    "ScopeRuleConfig",
    "SuccessCondition",
    "SuccessConditionType",
    "TargetConfig",
]