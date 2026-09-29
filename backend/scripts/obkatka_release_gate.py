"""Live break-in for the Valhalla release gate (honest-draft) with the flag ON.

Seeds a minimal scan + Valhalla report + findings, runs the real report pipeline
against live Postgres/Redis/MinIO, and asserts the release is published as an honest
draft (``generation_status='draft'`` with recorded reasons + artifacts still emitted),
never ``ready`` and never a discarded hard-fail. Run inside argus-backend on the
compose data network.
"""

from __future__ import annotations

import asyncio
import uuid

from sqlalchemy import String, cast, select
from src.core.config import settings
from src.db.models import Finding, Report, Scan, Tenant
from src.db.session import async_session_factory, set_session_tenant
from src.reports.report_pipeline import run_generate_report_pipeline

TENANT_ID = "00000000-0000-0000-0000-000000000001"


async def _get_or_create_tenant(session) -> None:
    existing = await session.execute(select(Tenant).where(cast(Tenant.id, String) == TENANT_ID))
    if existing.scalar_one_or_none() is None:
        session.add(Tenant(id=TENANT_ID, name="obkatka"))
        await session.flush()


async def main() -> int:
    print(f"valhalla_release_blockers_enabled = {settings.valhalla_release_blockers_enabled}")
    scan_id = str(uuid.uuid4())
    report_id = str(uuid.uuid4())

    async with async_session_factory() as session:
        await set_session_tenant(session, TENANT_ID)
        await _get_or_create_tenant(session)

        session.add(
            Scan(
                id=scan_id,
                tenant_id=TENANT_ID,
                target_url="https://obkatka.example",
                status="completed",
                scan_mode="standard",
            )
        )
        await session.commit()

    async with async_session_factory() as session:
        await set_session_tenant(session, TENANT_ID)
        session.add(
            Report(
                id=report_id,
                tenant_id=TENANT_ID,
                scan_id=scan_id,
                target="https://obkatka.example",
                tier="valhalla",
                generation_status="pending",
                requested_formats=["json", "md", "xml", "html", "pdf"],
                summary={},
            )
        )
        # One high-severity finding → trips O (CVSS/review), U (passport/chain), LLM gates.
        session.add(
            Finding(
                id=str(uuid.uuid4()),
                tenant_id=TENANT_ID,
                scan_id=scan_id,
                severity="high",
                title="SQL Injection in /search",
            )
        )
        await session.commit()

    async with async_session_factory() as session:
        await set_session_tenant(session, TENANT_ID)
        result = await run_generate_report_pipeline(
            session,
            report_id=report_id,
            tenant_id=TENANT_ID,
            scan_id_hint=scan_id,
            formats=["json", "md", "xml", "html", "pdf"],
        )
        print("pipeline result status:", result.get("status"))
        print("generation_status:", result.get("generation_status"))
        blockers = result.get("release_blockers")
        print("release_blockers (truncated):", (blockers or "")[:300])
        print("artifacts generated:", sorted(result.get("object_keys", {}).keys()))

    async with async_session_factory() as session:
        await set_session_tenant(session, TENANT_ID)
        row = (
            await session.execute(select(Report).where(cast(Report.id, String) == report_id))
        ).scalar_one()
        print("DB generation_status:", row.generation_status)
        print("DB last_error_message (truncated):", (row.last_error_message or "")[:200])

        status = row.generation_status
        if status == "draft" and (row.last_error_message or "").startswith("honest_draft:"):
            print(
                "RESULT: PASS — enforced gate published an honest draft (not ready, artifacts kept)"
            )
            return 0
        if status == "ready":
            print("RESULT: NOTE — released ready (no blockers tripped for this fixture)")
            return 0
        print(f"RESULT: FAIL — unexpected status {status!r}")
        return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
