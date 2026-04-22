"""ARG-024 / ARG-025 — ReportService: single entry-point for tier × format
generation.

The service exposes one public coroutine:

    bundle = await ReportService().generate(
        tenant_id="...",
        scan_id="...",
        tier=ReportTier.MIDGARD,
        fmt=ReportFormat.SARIF,
    )

The flow:

    1. Resolve ``Report`` / ``Finding`` rows from PostgreSQL (tenant-scoped).
    2. Build a unified ``ReportData`` using ``build_report_data_from_db``.
    3. Apply ``tier_classifier.classify_for_tier(data, tier)`` (pure;
       Asgard tier triggers in-place replay-command sanitisation per
       ARG-025).
    4. **Asgard branch** (ARG-025): build an
       :class:`AsgardSectionAssembly` and splice it into the Jinja /
       JSON context so HTML / PDF / JSON / CSV emit the
       full-findings + remediation + sanitized reproducer + timeline +
       presigned evidence URL stack.
    5. Dispatch to the correct format generator:
        - HTML / PDF / JSON / CSV → existing ``src.reports.generators``
          (the Jinja context now carries an ``asgard_report`` slot for
          tier == ASGARD).
        - SARIF                   → ``src.reports.sarif_generator``.
        - JUNIT                   → ``src.reports.junit_generator``.
    6. Wrap the bytes in a :class:`ReportBundle` (computes SHA-256 + size).

The service is **stateless** and **async-safe**: callers may instantiate
one per request, or share a singleton across the FastAPI app.

Security
    * Every DB query is constrained by ``tenant_id`` (never relies on RLS
      session vars alone — defense-in-depth against driver bugs).
    * No raw payload bytes are logged; only counts, ids, and durations.
    * PDF generation can throw on missing native libs (WeasyPrint); we
      surface a typed :class:`ReportGenerationError` so the API router can
      return 503 without leaking the underlying ImportError.
    * Asgard tier always passes through
      :func:`tier_classifier.classify_for_tier`, which in turn invokes
      :func:`replay_command_sanitizer.sanitize_replay_command` — there is
      no path through the service that bypasses sanitisation.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any, Final
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from src.core.observability import get_tracer, safe_set_span_attribute, tenant_hash
from src.db.models import Finding as FindingModel
from src.db.models import Report
from src.reports.asgard_tier_renderer import (
    AsgardSectionAssembly,
    asgard_assembly_to_jinja_context,
    assemble_asgard_sections,
)
from src.reports.generators import (
    ReportData,
    build_report_data_from_db,
    generate_csv,
    generate_html,
    generate_json,
    generate_pdf,
)
from src.reports.junit_generator import generate_junit
from src.reports.replay_command_sanitizer import SanitizeContext
from src.reports.report_bundle import ReportBundle, ReportFormat, ReportTier
from src.reports.sarif_generator import generate_sarif
from src.reports.tenant_pdf_format import resolve_tenant_pdf_archival_format
from src.reports.tier_classifier import classify_for_tier
from src.reports.valhalla_tier_renderer import (
    BusinessContext,
    ValhallaSectionAssembly,
    assemble_valhalla_sections,
    valhalla_assembly_to_jinja_context,
)

logger = logging.getLogger(__name__)


# Optional caller-overridable. The service never calls ``settings.version``
# directly so we can stub the tool version in unit tests.
DEFAULT_TOOL_VERSION: Final[str] = "1.0.0"

# Tenant id is always required upstream (FastAPI dep injection); the empty
# string would make the SQL filter a no-op so we reject it eagerly.
_EMPTY_TENANT = ""


class ReportGenerationError(Exception):
    """Raised when report rendering fails (PDF native libs missing, etc.)."""


class ReportNotFoundError(Exception):
    """Raised when a ``scan_id`` / ``report_id`` is not visible to the tenant."""


class ReportService:
    """Tenant-scoped, async report generator.

    The class holds no per-request state; it can be instantiated once per
    process and reused across requests. ``session_factory`` is injectable
    purely for tests (an in-memory SQLite engine in ``tests/integration``).
    """

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession] | None = None,
        tool_version: str | None = None,
    ) -> None:
        # Defer ``async_session_factory`` resolution until the first DB call so
        # importing ``ReportService`` does NOT trigger ``create_async_engine``
        # at module-load time. That kept downstream test suites (which use an
        # in-memory SQLite engine via their own fixture) free to swap the
        # database URL without touching ``ReportService`` symbols.
        self._session_factory_override = session_factory
        self._tool_version = (
            tool_version or DEFAULT_TOOL_VERSION
        ).strip() or DEFAULT_TOOL_VERSION

    @property
    def _session_factory(self) -> async_sessionmaker[AsyncSession]:
        if self._session_factory_override is not None:
            return self._session_factory_override
        from src.db.session import async_session_factory  # late import — see __init__

        return async_session_factory

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def generate(
        self,
        *,
        tenant_id: str,
        scan_id: str | None = None,
        report_id: str | None = None,
        tier: ReportTier = ReportTier.MIDGARD,
        fmt: ReportFormat = ReportFormat.JSON,
    ) -> ReportBundle:
        """Generate a tenant-scoped report bundle for ``(scan_id|report_id, tier, fmt)``."""
        tracer = get_tracer("argus.reports")
        with tracer.start_as_current_span("report.generate") as span:
            safe_set_span_attribute(span, "tenant.hash", tenant_hash(tenant_id))
            safe_set_span_attribute(span, "argus.tier", str(tier))
            safe_set_span_attribute(span, "argus.format", str(fmt))
            if scan_id is not None:
                safe_set_span_attribute(span, "argus.scan_id", scan_id)
            if report_id is not None:
                safe_set_span_attribute(span, "argus.report_id", report_id)

            self._validate_inputs(
                tenant_id=tenant_id, scan_id=scan_id, report_id=report_id
            )
            normalized_tier = self._coerce_tier(tier)
            normalized_fmt = self._coerce_format(fmt)

            from src.db.session import (
                set_session_tenant,
            )  # late import — keep DB out of cold path

            async with self._session_factory() as session:
                await set_session_tenant(session, tenant_id)
                data = await self._load_report_data(
                    session,
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    report_id=report_id,
                )
                pdf_archival_format = await resolve_tenant_pdf_archival_format(
                    session, tenant_id
                )

            return self.render_bundle(
                data,
                tier=normalized_tier,
                fmt=normalized_fmt,
                pdf_archival_format=pdf_archival_format,
            )

    def render_bundle(
        self,
        data: ReportData,
        *,
        tier: ReportTier,
        fmt: ReportFormat,
        presigner: Callable[[str], str | None] | None = None,
        sanitize_context: SanitizeContext | None = None,
        business_context: BusinessContext | None = None,
        pdf_archival_format: str | None = None,
    ) -> ReportBundle:
        """Render an in-memory ``ReportData`` to a :class:`ReportBundle`.

        Exposed publicly so unit tests / orchestrator code can pass a hand-
        built ``ReportData`` without going through SQLAlchemy.

        For tier == ``ReportTier.ASGARD`` the service additionally
        builds an :class:`AsgardSectionAssembly` and splices it into
        the Jinja / JSON pipeline as ``asgard_report`` — operators get
        full findings, sanitized reproducer and presigned evidence URLs
        in every format. ``presigner`` (object_key → URL) is optional;
        when ``None``, the assembly emits ``presigned_url=None`` and the
        report still renders correctly with the bare object key.

        For tier == ``ReportTier.VALHALLA`` (ARG-031) the service builds
        a :class:`ValhallaSectionAssembly` and splices it into the
        Jinja / JSON pipeline as ``valhalla_executive_report`` —
        executives get the business-impact lens (per-asset risk
        quantification, OWASP Top-10 rollup, top-N findings ranked by
        composite ``severity × exploitability × business_value``,
        remediation roadmap P0..P3). ``business_context`` is optional;
        when ``None`` every asset weighs ``1.0``.

        ``pdf_archival_format`` (B6-T02 / T48) is forwarded verbatim to
        :func:`generators.generate_pdf` so the PDF-only branch can decide
        whether to engage the PDF/A-2u LaTeX preamble. ``None`` keeps the
        env-only legacy behaviour for direct test callers.
        """
        normalized_tier = self._coerce_tier(tier)
        normalized_fmt = self._coerce_format(fmt)
        projected = classify_for_tier(
            data,
            normalized_tier,
            sanitize_context=sanitize_context,
        )
        asgard_assembly: AsgardSectionAssembly | None = None
        valhalla_assembly: ValhallaSectionAssembly | None = None
        if normalized_tier is ReportTier.ASGARD:
            asgard_assembly = assemble_asgard_sections(
                projected,
                sanitize_context=sanitize_context,
                presigner=presigner,
            )
        elif normalized_tier is ReportTier.VALHALLA:
            valhalla_assembly = assemble_valhalla_sections(
                projected,
                business_context=business_context,
                sanitize_context=sanitize_context,
                presigner=presigner,
            )
        content = self._render_format(
            projected,
            fmt=normalized_fmt,
            tier=normalized_tier,
            asgard_assembly=asgard_assembly,
            valhalla_assembly=valhalla_assembly,
            pdf_archival_format=pdf_archival_format,
        )
        return ReportBundle.from_content(
            tier=normalized_tier,
            fmt=normalized_fmt,
            content=content,
        )

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_inputs(
        *,
        tenant_id: str,
        scan_id: str | None,
        report_id: str | None,
    ) -> None:
        if not tenant_id or tenant_id == _EMPTY_TENANT:
            raise ValueError("ReportService.generate requires a non-empty tenant_id")
        if not scan_id and not report_id:
            raise ValueError(
                "ReportService.generate requires at least one of scan_id or report_id"
            )

    @staticmethod
    def _coerce_tier(tier: ReportTier | str) -> ReportTier:
        if isinstance(tier, ReportTier):
            return tier
        try:
            return ReportTier(str(tier).strip().lower())
        except ValueError as exc:
            raise ValueError(
                f"Unknown ReportTier {tier!r}; expected one of {[t.value for t in ReportTier]}"
            ) from exc

    @staticmethod
    def _coerce_format(fmt: ReportFormat | str) -> ReportFormat:
        if isinstance(fmt, ReportFormat):
            return fmt
        try:
            return ReportFormat(str(fmt).strip().lower())
        except ValueError as exc:
            raise ValueError(
                f"Unknown ReportFormat {fmt!r}; expected one of "
                f"{[f.value for f in ReportFormat]}"
            ) from exc

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    async def _load_report_data(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        scan_id: str | None,
        report_id: str | None,
    ) -> ReportData:
        report = await self._load_report(
            session,
            tenant_id=tenant_id,
            scan_id=scan_id,
            report_id=report_id,
        )
        if report is None:
            target = self._derive_target_or_empty(scan_id=scan_id, report_id=report_id)
            return self._empty_report_data(
                tenant_id=tenant_id,
                scan_id=scan_id,
                report_id=report_id,
                target=target,
            )

        findings_result = await session.execute(
            select(FindingModel).where(
                FindingModel.report_id == report.id,
                FindingModel.tenant_id == tenant_id,
            )
        )
        findings = list(findings_result.scalars().all())
        return build_report_data_from_db(report, findings)

    async def _load_report(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        scan_id: str | None,
        report_id: str | None,
    ) -> Report | None:
        if report_id:
            result = await session.execute(
                select(Report).where(
                    Report.id == report_id,
                    Report.tenant_id == tenant_id,
                )
            )
            return result.scalar_one_or_none()
        if scan_id:
            result = await session.execute(
                select(Report)
                .where(
                    Report.scan_id == scan_id,
                    Report.tenant_id == tenant_id,
                )
                .order_by(Report.created_at.desc())
            )
            return result.scalars().first()
        return None

    @staticmethod
    def _derive_target_or_empty(
        *,
        scan_id: str | None,
        report_id: str | None,
    ) -> str:
        """Best-effort target derivation when no Report row exists.

        We never invent a hostname; the caller may pass a scan_id derived
        from a URL elsewhere. For an empty result we just return ``""``,
        which the generators handle gracefully.
        """
        for candidate in (scan_id, report_id):
            if candidate and "://" in candidate:
                parsed = urlparse(candidate)
                if parsed.hostname:
                    return parsed.hostname
        return ""

    @staticmethod
    def _empty_report_data(
        *,
        tenant_id: str,
        scan_id: str | None,
        report_id: str | None,
        target: str,
    ) -> ReportData:
        from src.api.schemas import ReportSummary

        rid = report_id or scan_id or "unknown"
        empty_summary = ReportSummary(
            critical=0,
            high=0,
            medium=0,
            low=0,
            info=0,
            technologies=[],
            sslIssues=0,
            headerIssues=0,
            leaksFound=False,
        )
        return ReportData(
            report_id=rid,
            target=target,
            summary=empty_summary,
            findings=[],
            technologies=[],
            created_at=None,
            scan_id=scan_id,
            tenant_id=tenant_id,
        )

    # ------------------------------------------------------------------
    # Format dispatch
    # ------------------------------------------------------------------

    def _render_format(
        self,
        data: ReportData,
        *,
        fmt: ReportFormat,
        tier: ReportTier,
        asgard_assembly: AsgardSectionAssembly | None = None,
        valhalla_assembly: ValhallaSectionAssembly | None = None,
        pdf_archival_format: str | None = None,
    ) -> bytes:
        try:
            jinja_context = self._build_jinja_context(
                data,
                tier=tier,
                asgard_assembly=asgard_assembly,
                valhalla_assembly=valhalla_assembly,
            )
            if fmt is ReportFormat.JSON:
                return generate_json(data, jinja_context=jinja_context)
            if fmt is ReportFormat.CSV:
                return generate_csv(data, jinja_context=jinja_context)
            if fmt is ReportFormat.HTML:
                return generate_html(data, tier=tier.value, jinja_context=jinja_context)
            if fmt is ReportFormat.PDF:
                return generate_pdf(
                    data,
                    tier=tier.value,
                    jinja_context=jinja_context,
                    pdf_archival_format=pdf_archival_format,
                )
            if fmt is ReportFormat.SARIF:
                return generate_sarif(data, tool_version=self._tool_version)
            if fmt is ReportFormat.JUNIT:
                return generate_junit(data)
        except RuntimeError as exc:
            # WeasyPrint missing → bubble up a typed error (router maps to 503).
            logger.warning(
                "report_service.render_failed",
                extra={
                    "event": "report_service_render_failed",
                    "tier": tier.value,
                    "format": fmt.value,
                    "error_type": type(exc).__name__,
                },
            )
            raise ReportGenerationError(
                f"Report generation failed for {tier.value}/{fmt.value}"
            ) from exc

        # Pydantic StrEnum is exhaustive at type-check time; the unreachable
        # branch is here only to satisfy mypy --strict.
        raise ValueError(f"Unsupported ReportFormat {fmt!r}")

    def _build_jinja_context(
        self,
        data: ReportData,
        *,
        tier: ReportTier,
        asgard_assembly: AsgardSectionAssembly | None,
        valhalla_assembly: ValhallaSectionAssembly | None = None,
    ) -> dict[str, Any] | None:
        """Build the Jinja / JSON context for HTML / PDF / JSON / CSV.

        For tier == ``ReportTier.ASGARD`` we layer the Asgard assembly
        (``asgard_report`` slot) on top of the existing minimal context so
        the shared base template (``base.html.j2``) keeps rendering
        ``recon_summary``, ``findings_table`` and ``ai_slots`` partials
        without changes.

        For tier == ``ReportTier.VALHALLA`` (ARG-031) we layer the
        Valhalla assembly (``valhalla_executive_report`` slot) on top of
        the same minimal context. The legacy ``valhalla_report`` payload
        (built later in :func:`generators.generate_json` from
        ``valhalla_context``) coexists with the new slot — both are
        emitted to JSON so consumers can opt into the executive lens
        independently.

        For Midgard with no assemblies attached we return ``None`` and
        let the legacy chain pick the default context — preserving
        byte-identical Midgard snapshots.
        """
        if tier is ReportTier.ASGARD and asgard_assembly is not None:
            from src.reports.jinja_minimal_context import (
                minimal_jinja_context_from_report_data,
            )

            base = minimal_jinja_context_from_report_data(data, tier.value)
            return asgard_assembly_to_jinja_context(asgard_assembly, base_context=base)
        if tier is ReportTier.VALHALLA and valhalla_assembly is not None:
            from src.reports.jinja_minimal_context import (
                minimal_jinja_context_from_report_data,
            )

            base = minimal_jinja_context_from_report_data(data, tier.value)
            return valhalla_assembly_to_jinja_context(
                valhalla_assembly, base_context=base
            )
        return None


__all__ = [
    "DEFAULT_TOOL_VERSION",
    "ReportGenerationError",
    "ReportNotFoundError",
    "ReportService",
]
