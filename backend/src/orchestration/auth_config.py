"""Authentication and scoping configuration for target applications.

Provides Pydantic models for declarative authentication configuration,
including login flow descriptions, success conditions, and rules of
engagement. Inspired by Shannon's YAML config system but adapted for
ARGUS's multi-tenant architecture and existing scope/policy infrastructure.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    StringConstraints,
)

# A ``SecretRef`` is an opaque, non-secret *identifier* (handle) for a secret.
# It is safe to keep in configs/plans/logs/prompts because it never carries the
# secret value itself — resolution to the real value happens only on the
# execution layer via ``SessionStore.resolve_secret`` (SI-3 split-plane).
SecretRef = Annotated[
    str,
    StringConstraints(min_length=1, max_length=256, pattern=r"^[A-Za-z0-9_.:\-/]+$"),
]


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
    selector: StrictStr | None = Field(
        default=None,
        max_length=512,
        description="CSS/XPath selector for the element to interact with.",
    )
    value: StrictStr | None = Field(
        default=None,
        max_length=2048,
        description="Value to input (supports $username/$password/$totp placeholders).",
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


def _generate_totp(secret: str | None) -> str | None:
    """Generate a current TOTP code, or ``None`` when unavailable.

    ``pyotp`` is an optional dependency, so it is imported lazily here (the only
    sanctioned inline-import exception): a top-level import would break config
    loading on installs without 2FA support.
    """
    if secret is None:
        return None
    try:
        import pyotp  # noqa: PLC0415 — optional dependency, imported lazily on purpose
    except ImportError:
        return None
    return pyotp.TOTP(secret).now()


def _replace_placeholders(text: str, mapping: dict[str, str]) -> str:
    for placeholder, value in mapping.items():
        text = text.replace(placeholder, value)
    return text


def _placeholder_map(creds: AuthCredentials) -> dict[str, str]:
    """Build the ``$placeholder -> value`` map for a credentials block."""
    totp_code = _generate_totp(creds.totp_secret)
    mapping: dict[str, str] = {
        "$username": creds.username,
        "$password": creds.password,
        "$totp": totp_code or "$totp",
    }
    if creds.email_login is not None:
        email_totp = _generate_totp(creds.email_login.totp_secret)
        mapping["$email_address"] = creds.email_login.address
        mapping["$email_password"] = creds.email_login.password
        mapping["$email_totp"] = email_totp or "$email_totp"
    return mapping


def _resolve_auth_config(auth: AuthConfig, creds: AuthCredentials) -> AuthConfig:
    """Return a copy of ``auth`` with login-flow placeholders resolved."""
    mapping = _placeholder_map(creds)
    resolved_steps = [
        LoginFlowStep(
            instruction=_replace_placeholders(step.instruction, mapping),
            selector=_replace_placeholders(step.selector, mapping) if step.selector else None,
            value=_replace_placeholders(step.value, mapping) if step.value else None,
        )
        for step in auth.login_flow
    ]
    return auth.model_copy(update={"login_flow": resolved_steps})


class PrincipalRole(StrEnum):
    """Roles a principal (identity) can hold during a multi-principal scan.

    Aliases used across the docs/config:

    * ``owner`` — the primary authenticated user (a.k.a. ``user_a``). The legacy
      single ``authentication`` block maps to this role.
    * ``attacker`` — a second, lower-trust authenticated user (a.k.a. ``user_b``)
      used for authorization / IDOR / cross-tenant testing.
    * ``anonymous`` — an unauthenticated principal (no credentials).
    """

    ANONYMOUS = "anonymous"
    OWNER = "owner"
    ATTACKER = "attacker"
    TENANT_A_USER = "tenant_a_user"
    TENANT_B_USER = "tenant_b_user"
    MODERATOR = "moderator"
    ADMIN = "admin"


class PrincipalConfig(BaseModel):
    """A single authenticated (or anonymous) identity used during a scan.

    Multi-principal scans (G-2) declare several principals so that
    authorization, IDOR, and cross-tenant issues can be probed with distinct,
    **isolated** sessions. Secrets may be provided two ways:

    * **inline** — via :attr:`credentials` / :attr:`login` (back-compat path,
      identical to the legacy single-``authentication`` model), or
    * **split-plane** — via ``*_ref`` handles (:attr:`secret_ref`,
      :attr:`bearer_token_ref`, :attr:`api_key_ref`) which carry only opaque
      identifiers. The real values are resolved on the execution layer by
      ``SessionStore.resolve_secret`` and never appear in configs, prompts,
      logs, or evidence (SI-3).
    """

    model_config = ConfigDict(extra="forbid")

    principal_id: StrictStr = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_]{0,63}$",
        description="Stable identifier for this principal (e.g. owner, attacker, anon).",
    )
    role: PrincipalRole = Field(
        description="Role this principal holds during the scan.",
    )
    tenant_id: StrictStr | None = Field(
        default=None,
        max_length=128,
        description="Tenant this principal belongs to (multi-tenant isolation testing).",
    )
    credentials: AuthCredentials | None = Field(
        default=None,
        description="Inline credentials (back-compat path). Omit when using *_ref handles.",
    )
    login: AuthConfig | None = Field(
        default=None,
        description="Per-principal login flow (login_url/login_flow/success_condition).",
    )
    secret_ref: SecretRef | None = Field(
        default=None,
        description="Opaque handle resolved to a password/secret on the execution layer.",
    )
    bearer_token_ref: SecretRef | None = Field(
        default=None,
        description="Opaque handle resolved to a Bearer token on the execution layer.",
    )
    api_key_ref: SecretRef | None = Field(
        default=None,
        description="Opaque handle resolved to an API key on the execution layer.",
    )

    def resolve_placeholders(self) -> "PrincipalConfig":
        """Return a copy with login-flow placeholders resolved from credentials.

        Mirrors :meth:`TargetConfig.resolve_placeholders` but scoped to this
        principal. If there is no :attr:`login` block, the principal is returned
        unchanged. Credentials are taken from :attr:`login` first, then from
        :attr:`credentials`.
        """
        if self.login is None:
            return self

        creds = self.login.credentials or self.credentials
        if creds is None:
            return self

        resolved_login = _resolve_auth_config(self.login, creds)
        return self.model_copy(update={"login": resolved_login})


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
        description="Legacy single-principal auth config (maps to the 'owner' principal).",
    )
    principals: list[PrincipalConfig] | None = Field(
        default=None,
        max_length=16,
        description="Multi-principal identities (owner/attacker/...). Overrides 'authentication'.",
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
        resolved_auth = _resolve_auth_config(self.authentication, self.authentication.credentials)
        return self.model_copy(update={"authentication": resolved_auth})

    def resolved_principals(self) -> list[PrincipalConfig]:
        """Return the effective list of principals for this scan.

        Resolution order (SI-7 back-compat):

        1. If :attr:`principals` is set, it is returned as-is (multi-principal).
        2. Otherwise, if the legacy single :attr:`authentication` block is set,
           it is adapted into a single ``owner`` principal so downstream code has
           one uniform representation.
        3. Otherwise an empty list (anonymous / no auth).
        """
        if self.principals:
            return list(self.principals)
        if self.authentication is not None:
            return [
                PrincipalConfig(
                    principal_id="owner",
                    role=PrincipalRole.OWNER,
                    credentials=self.authentication.credentials,
                    login=self.authentication,
                )
            ]
        return []

    @staticmethod
    def _replace_placeholders(text: str, mapping: dict[str, str]) -> str:
        return _replace_placeholders(text, mapping)

    @staticmethod
    def _generate_totp(secret: str | None) -> str | None:
        return _generate_totp(secret)

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

    @classmethod
    def from_scan_options(cls, options: dict[str, Any]) -> "TargetConfig | None":
        """Build a TargetConfig from scan options dict (engagement API).

        Looks for ``auth_config`` or ``target_config`` keys in options.
        Returns None if neither key is present.
        """
        if not isinstance(options, dict):
            return None
        cfg_data = options.get("auth_config") or options.get("target_config")
        if cfg_data is None:
            return None
        if isinstance(cfg_data, str):
            return cls.from_yaml(cfg_data)
        if isinstance(cfg_data, dict):
            return cls.from_json(cfg_data)
        return None


__all__ = [
    "AuthConfig",
    "AuthCredentials",
    "EmailLoginConfig",
    "LoginFlowStep",
    "LoginType",
    "PrincipalConfig",
    "PrincipalRole",
    "RulesOfEngagement",
    "ScopeRuleConfig",
    "SecretRef",
    "SuccessCondition",
    "SuccessConditionType",
    "TargetConfig",
]
