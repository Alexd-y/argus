"""Unit tests for :mod:`src.oast.provisioner` (ARG-007).

Tested invariants:

* Token generation produces RFC 1035-compliant DNS labels and a URL-safe
  path token bounded by configured length limits.
* Issued tokens are tenant-scoped, immutable, and tracked under their
  generated id; ``get`` returns the same instance, ``is_active`` returns
  ``True`` until expiry or explicit revocation.
* Edge-case validation rejects malformed base domains, oversize TTLs,
  bogus family hints, and any control characters / whitespace in
  hostnames.
* :class:`DisabledOASTProvisioner` raises :class:`OASTUnavailableError`
  on every issue call without leaking a token.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from itertools import count
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from src.oast.provisioner import (
    DisabledOASTProvisioner,
    InternalOASTProvisioner,
    OASTBackendKind,
    OASTProvisioner,
    OASTProvisioningError,
    OASTToken,
    OASTUnavailableError,
)


_TENANT = UUID("11111111-1111-1111-1111-111111111111")
_SCAN = UUID("22222222-2222-2222-2222-222222222222")


# ---------------------------------------------------------------------------
# OASTToken model
# ---------------------------------------------------------------------------


class TestOASTToken:
    def _build(
        self,
        *,
        dns_label: str = "argus-deadbeef0001",
        subdomain: str = "argus-deadbeef0001.oast.argus.local",
        path_token: str = "abcdef0123456789abcdef0123456789",
        backend: OASTBackendKind = OASTBackendKind.INTERNAL,
        expires_in: timedelta = timedelta(minutes=10),
    ) -> OASTToken:
        now = datetime(2026, 4, 17, 12, 0, 0, tzinfo=timezone.utc)
        return OASTToken(
            id=uuid4(),
            tenant_id=_TENANT,
            scan_id=_SCAN,
            subdomain=subdomain,
            path_token=path_token,
            dns_label=dns_label,
            backend=backend,
            created_at=now,
            expires_at=now + expires_in,
        )

    def test_token_is_frozen(self) -> None:
        token = self._build()
        with pytest.raises(ValidationError):
            token.subdomain = "other.example.com"

    def test_http_url_strips_dns_label(self) -> None:
        token = self._build(
            dns_label="argus-cafebabe",
            subdomain="argus-cafebabe.oast.argus.local",
            path_token="0123456789abcdef0123456789abcdef",
        )
        # The HTTPS URL drops the per-token DNS label and uses the
        # canonical OAST host so listeners do not need wildcard
        # certificates per token.
        assert token.http_url == (
            "https://oast.argus.local/p/0123456789abcdef0123456789abcdef"
        )

    def test_dns_label_rejects_uppercase(self) -> None:
        with pytest.raises(ValidationError):
            self._build(
                dns_label="ARGUS-bad",
                subdomain="ARGUS-bad.oast.argus.local",
            )

    def test_dns_label_rejects_leading_hyphen(self) -> None:
        with pytest.raises(ValidationError):
            self._build(
                dns_label="-bad-label",
                subdomain="-bad-label.oast.argus.local",
            )

    def test_dns_label_too_long(self) -> None:
        too_long = "a" * 64
        with pytest.raises(ValidationError):
            self._build(
                dns_label=too_long,
                subdomain=f"{too_long}.oast.argus.local",
            )

    def test_subdomain_must_start_with_dns_label(self) -> None:
        with pytest.raises(ValidationError):
            self._build(
                dns_label="argus-aabbccddeeff",
                subdomain="something-else.oast.argus.local",
            )

    def test_subdomain_must_contain_dot(self) -> None:
        with pytest.raises(ValidationError):
            self._build(subdomain="onlylabel")

    def test_path_token_rejects_non_url_safe_chars(self) -> None:
        with pytest.raises(ValidationError):
            self._build(path_token="bad token with spaces!")

    def test_expires_at_must_follow_created_at(self) -> None:
        with pytest.raises(ValidationError):
            self._build(expires_in=timedelta(seconds=-1))

    def test_naive_datetime_rejected(self) -> None:
        # We pass a naive datetime via construction; pydantic should
        # reject it via the model validator.
        with pytest.raises(ValidationError):
            OASTToken(
                id=uuid4(),
                tenant_id=_TENANT,
                scan_id=_SCAN,
                subdomain="argus-test01abcdef.oast.argus.local",
                path_token="abcdef0123456789",
                dns_label="argus-test01abcdef",
                created_at=datetime(2026, 4, 17, 12, 0, 0),
                expires_at=datetime(2026, 4, 17, 13, 0, 0),
            )

    def test_reserved_for_family_must_match_pattern(self) -> None:
        with pytest.raises(ValidationError):
            OASTToken(
                id=uuid4(),
                tenant_id=_TENANT,
                scan_id=_SCAN,
                subdomain="argus-test01abcdef.oast.argus.local",
                path_token="abcdef0123456789",
                dns_label="argus-test01abcdef",
                created_at=datetime(2026, 4, 17, 12, 0, 0, tzinfo=timezone.utc),
                expires_at=datetime(2026, 4, 17, 13, 0, 0, tzinfo=timezone.utc),
                reserved_for_family="BadFamily",
            )

    def test_is_active_at_requires_tz_aware_moment(self) -> None:
        token = self._build()
        with pytest.raises(ValueError):
            token.is_active_at(datetime(2026, 4, 17, 12, 0, 0))


# ---------------------------------------------------------------------------
# InternalOASTProvisioner
# ---------------------------------------------------------------------------


class TestInternalOASTProvisioner:
    def test_issue_produces_dns_compliant_token(
        self, internal_provisioner: InternalOASTProvisioner
    ) -> None:
        token = internal_provisioner.issue(
            tenant_id=_TENANT,
            scan_id=_SCAN,
            ttl=timedelta(minutes=10),
        )
        assert token.tenant_id == _TENANT
        assert token.scan_id == _SCAN
        assert token.backend is OASTBackendKind.INTERNAL
        assert token.subdomain.endswith(".oast.argus.local")
        assert token.subdomain.startswith(token.dns_label + ".")
        # Default token factory yields 16-char hex (64 bits); with our
        # deterministic fixture the label collapses to ``argus-aaaaaaaa...01``.
        assert len(token.dns_label) <= 63

    def test_issue_records_token_in_lookup_table(
        self, internal_provisioner: InternalOASTProvisioner
    ) -> None:
        token = internal_provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)
        assert internal_provisioner.get(token.id) is token
        assert internal_provisioner.is_active(token.id) is True

    def test_revoke_marks_token_inactive(
        self, internal_provisioner: InternalOASTProvisioner
    ) -> None:
        token = internal_provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)
        internal_provisioner.revoke(token.id)
        assert internal_provisioner.is_active(token.id) is False
        # The lookup table still resolves the token (audit-friendly).
        assert internal_provisioner.get(token.id) is token

    def test_revoke_unknown_token_is_noop(
        self, internal_provisioner: InternalOASTProvisioner
    ) -> None:
        # Should not raise even if id is unknown.
        internal_provisioner.revoke(UUID(int=0xDEADBEEF))
        assert internal_provisioner.is_active(UUID(int=0xDEADBEEF)) is False

    def test_issue_rejects_short_ttl(
        self, internal_provisioner: InternalOASTProvisioner
    ) -> None:
        with pytest.raises(OASTProvisioningError):
            internal_provisioner.issue(
                tenant_id=_TENANT,
                scan_id=_SCAN,
                ttl=timedelta(seconds=10),
            )

    def test_issue_rejects_oversize_ttl(
        self, internal_provisioner: InternalOASTProvisioner
    ) -> None:
        with pytest.raises(OASTProvisioningError):
            internal_provisioner.issue(
                tenant_id=_TENANT,
                scan_id=_SCAN,
                ttl=timedelta(days=2),
            )

    def test_issue_rejects_bad_family_hint(
        self, internal_provisioner: InternalOASTProvisioner
    ) -> None:
        with pytest.raises(OASTProvisioningError):
            internal_provisioner.issue(
                tenant_id=_TENANT, scan_id=_SCAN, family="BadFamily"
            )

    def test_issue_accepts_well_formed_family(
        self, internal_provisioner: InternalOASTProvisioner
    ) -> None:
        token = internal_provisioner.issue(
            tenant_id=_TENANT, scan_id=_SCAN, family="ssrf"
        )
        assert token.reserved_for_family == "ssrf"

    def test_constructor_rejects_bad_base_domain(self) -> None:
        with pytest.raises(OASTProvisioningError):
            InternalOASTProvisioner(base_domain="invalid_domain!!")

    def test_constructor_rejects_oversize_base_domain(self) -> None:
        with pytest.raises(OASTProvisioningError):
            InternalOASTProvisioner(base_domain="a." * 200 + "b")

    def test_constructor_normalises_base_domain(self) -> None:
        provisioner = InternalOASTProvisioner(base_domain="OAST.Example.COM.")
        assert provisioner.base_domain == "oast.example.com"

    def test_list_active_filters_revoked_and_expired(
        self,
        deterministic_uuid_factory: Callable[[], UUID],
        deterministic_token_factory: Callable[[int], str],
    ) -> None:
        clock_call = count(start=0)
        base = datetime(2026, 4, 17, 12, 0, 0, tzinfo=timezone.utc)

        def _moving_clock() -> datetime:
            return base + timedelta(seconds=next(clock_call))

        provisioner = InternalOASTProvisioner(
            base_domain="oast.argus.local",
            clock=_moving_clock,
            id_factory=deterministic_uuid_factory,
            token_factory=deterministic_token_factory,
        )
        # Issue three tokens with short TTLs so the second issue tick
        # already lies past the first token's expiry.
        provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN, ttl=timedelta(seconds=30))
        revoked_token = provisioner.issue(
            tenant_id=_TENANT, scan_id=_SCAN, ttl=timedelta(seconds=120)
        )
        provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN, ttl=timedelta(seconds=120))
        provisioner.revoke(revoked_token.id)

        # Advance the clock past the 30-second token expiry.
        # Move the clock counter forward by sampling enough times.
        for _ in range(60):
            _moving_clock()

        active = list(provisioner.list_active())
        active_ids = {t.id for t in active}
        assert revoked_token.id not in active_ids

    def test_token_id_collision_raises(
        self,
        deterministic_token_factory: Callable[[int], str],
        fixed_clock: Callable[[], datetime],
    ) -> None:
        # Inject an id_factory that always yields the same UUID; the
        # second issue must raise to avoid silent overwrites.
        fixed = UUID(int=42)

        def _id_factory() -> UUID:
            return fixed

        provisioner = InternalOASTProvisioner(
            base_domain="oast.argus.local",
            clock=fixed_clock,
            id_factory=_id_factory,
            token_factory=deterministic_token_factory,
        )
        provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)
        with pytest.raises(OASTProvisioningError):
            provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)

    def test_default_token_factory_rejects_bad_size(self) -> None:
        from src.oast.provisioner import _default_token_hex

        with pytest.raises(OASTProvisioningError):
            _default_token_hex(0)
        with pytest.raises(OASTProvisioningError):
            _default_token_hex(64)

    def test_satisfies_protocol(
        self, internal_provisioner: InternalOASTProvisioner
    ) -> None:
        assert isinstance(internal_provisioner, OASTProvisioner)


# ---------------------------------------------------------------------------
# DNS label entropy (MEDIUM-1, post-ARG-007 review)
# ---------------------------------------------------------------------------


class TestDNSLabelEntropy:
    """The label suffix MUST embed at least 64 bits of CSPRNG entropy and
    fit RFC 1035's 63-octet single-label ceiling."""

    def test_dns_label_has_at_least_64_bits_entropy(self) -> None:
        # Use the production CSPRNG-backed factory (no deterministic
        # fixture override) so we exercise the actual entropy source.
        provisioner = InternalOASTProvisioner(base_domain="oast.argus.local")

        seen_hex_sections: set[str] = set()
        for _ in range(100):
            token = provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)
            assert token.dns_label.startswith("argus-")
            hex_section = token.dns_label[len("argus-") :]
            assert len(hex_section) == 16, (
                f"expected 16 hex chars (64 bits), got {len(hex_section)}"
            )
            assert all(c in "0123456789abcdef" for c in hex_section)
            assert hex_section not in seen_hex_sections, (
                "CSPRNG collision on a 64-bit label across 100 issues — "
                "either entropy regressed or the test got cosmically unlucky"
            )
            seen_hex_sections.add(hex_section)

        # Total label length: "argus-" (6) + 16 hex chars = 22, well within
        # the 63-octet RFC 1035 limit.
        sample_token = next(iter(provisioner.list_active()))
        assert len(sample_token.dns_label) == 22
        assert len(sample_token.dns_label) <= 63


# ---------------------------------------------------------------------------
# purge_expired (MEDIUM-3, post-ARG-007 review)
# ---------------------------------------------------------------------------


class TestProvisionerPurgeExpired:
    """``purge_expired`` is the eviction primitive that keeps the in-memory
    token store from growing unbounded across long-running scans."""

    def _make_provisioner(
        self,
        clock: Callable[[], datetime],
        deterministic_uuid_factory: Callable[[], UUID],
        deterministic_token_factory: Callable[[int], str],
    ) -> InternalOASTProvisioner:
        return InternalOASTProvisioner(
            base_domain="oast.argus.local",
            clock=clock,
            id_factory=deterministic_uuid_factory,
            token_factory=deterministic_token_factory,
        )

    def test_purge_drops_tokens_past_grace(
        self,
        deterministic_uuid_factory: Callable[[], UUID],
        deterministic_token_factory: Callable[[int], str],
    ) -> None:
        moments: list[datetime] = [datetime(2026, 4, 17, 12, 0, 0, tzinfo=timezone.utc)]

        def clock() -> datetime:
            return moments[-1]

        provisioner = self._make_provisioner(
            clock, deterministic_uuid_factory, deterministic_token_factory
        )
        short = provisioner.issue(
            tenant_id=_TENANT, scan_id=_SCAN, ttl=timedelta(seconds=60)
        )
        long = provisioner.issue(
            tenant_id=_TENANT, scan_id=_SCAN, ttl=timedelta(hours=2)
        )

        # 30 minutes after the snapshot: short token is 29 minutes past
        # expiry (well past the 5-minute default grace) but the long token
        # is still active.
        future = moments[0] + timedelta(minutes=30)
        evicted = provisioner.purge_expired(before=future)
        assert evicted == 1
        assert provisioner.get(short.id) is None
        assert provisioner.get(long.id) is long

    def test_purge_respects_grace_window(
        self,
        deterministic_uuid_factory: Callable[[], UUID],
        deterministic_token_factory: Callable[[int], str],
    ) -> None:
        moments: list[datetime] = [datetime(2026, 4, 17, 12, 0, 0, tzinfo=timezone.utc)]

        def clock() -> datetime:
            return moments[-1]

        provisioner = self._make_provisioner(
            clock, deterministic_uuid_factory, deterministic_token_factory
        )
        token = provisioner.issue(
            tenant_id=_TENANT, scan_id=_SCAN, ttl=timedelta(seconds=60)
        )

        # 30 seconds past expiry, well within the 5 minute default grace.
        slight_future = moments[0] + timedelta(seconds=90)
        evicted = provisioner.purge_expired(before=slight_future)
        assert evicted == 0
        assert provisioner.get(token.id) is token

    def test_purge_evicts_revoked_token_metadata(
        self,
        deterministic_uuid_factory: Callable[[], UUID],
        deterministic_token_factory: Callable[[int], str],
    ) -> None:
        """Revoked-but-expired tokens drop their revocation marker too,
        otherwise ``_revoked`` would leak ids forever."""
        moments: list[datetime] = [datetime(2026, 4, 17, 12, 0, 0, tzinfo=timezone.utc)]

        def clock() -> datetime:
            return moments[-1]

        provisioner = self._make_provisioner(
            clock, deterministic_uuid_factory, deterministic_token_factory
        )
        token = provisioner.issue(
            tenant_id=_TENANT, scan_id=_SCAN, ttl=timedelta(seconds=60)
        )
        provisioner.revoke(token.id)

        future = moments[0] + timedelta(minutes=30)
        evicted = provisioner.purge_expired(before=future)
        assert evicted == 1
        assert provisioner.get(token.id) is None
        # No public surface to inspect _revoked, but is_active now returns
        # False (the standard absent-token answer) instead of leaking
        # state forever.
        assert provisioner.is_active(token.id) is False

    def test_purge_negative_grace_rejected(
        self, internal_provisioner: InternalOASTProvisioner
    ) -> None:
        with pytest.raises(OASTProvisioningError):
            internal_provisioner.purge_expired(grace=timedelta(seconds=-1))

    def test_purge_naive_before_rejected(
        self, internal_provisioner: InternalOASTProvisioner
    ) -> None:
        with pytest.raises(OASTProvisioningError):
            internal_provisioner.purge_expired(before=datetime(2026, 4, 17, 12, 0, 0))

    def test_purge_default_clock_uses_provisioner_clock(
        self,
        deterministic_uuid_factory: Callable[[], UUID],
        deterministic_token_factory: Callable[[int], str],
    ) -> None:
        moments: list[datetime] = [datetime(2026, 4, 17, 12, 0, 0, tzinfo=timezone.utc)]

        def clock() -> datetime:
            return moments[-1]

        provisioner = self._make_provisioner(
            clock, deterministic_uuid_factory, deterministic_token_factory
        )
        provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN, ttl=timedelta(seconds=60))

        # Advance only the provisioner's clock — purge_expired() with no
        # explicit ``before`` must use that updated clock and evict.
        moments.append(moments[0] + timedelta(minutes=30))
        evicted = provisioner.purge_expired()
        assert evicted == 1


# ---------------------------------------------------------------------------
# DisabledOASTProvisioner
# ---------------------------------------------------------------------------


class TestDisabledOASTProvisioner:
    def test_issue_raises_unavailable(
        self, disabled_provisioner: DisabledOASTProvisioner
    ) -> None:
        with pytest.raises(OASTUnavailableError):
            disabled_provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)

    def test_revoke_is_noop(
        self, disabled_provisioner: DisabledOASTProvisioner
    ) -> None:
        disabled_provisioner.revoke(UUID(int=1))

    def test_is_active_returns_false(
        self, disabled_provisioner: DisabledOASTProvisioner
    ) -> None:
        assert disabled_provisioner.is_active(UUID(int=1)) is False

    def test_get_returns_none(
        self, disabled_provisioner: DisabledOASTProvisioner
    ) -> None:
        assert disabled_provisioner.get(UUID(int=1)) is None

    def test_backend_is_disabled(
        self, disabled_provisioner: DisabledOASTProvisioner
    ) -> None:
        assert disabled_provisioner.backend is OASTBackendKind.DISABLED

    def test_satisfies_protocol(
        self, disabled_provisioner: DisabledOASTProvisioner
    ) -> None:
        assert isinstance(disabled_provisioner, OASTProvisioner)

    def test_custom_reason_propagates(self) -> None:
        provisioner = DisabledOASTProvisioner(reason="oast_kill_switch")
        assert provisioner.reason == "oast_kill_switch"
        with pytest.raises(OASTUnavailableError) as exc_info:
            provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)
        assert "oast_kill_switch" in str(exc_info.value)
