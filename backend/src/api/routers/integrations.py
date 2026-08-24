"""Integrations API — forward findings to external systems.

POST /api/v1/integrations/splunk    — send to Splunk
POST /api/v1/integrations/elastic   — send to Elasticsearch
POST /api/v1/integrations/jira      — create Jira ticket
POST /api/v1/integrations/servicenow— create ServiceNow incident
POST /api/v1/integrations/webhook   — generic webhook
"""

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/integrations", tags=["integrations"])


class ForwardRequest(BaseModel):
    finding: dict[str, Any]
    config: dict[str, str] = {}  # override default connection config


@router.post("/splunk")
async def forward_to_splunk(req: ForwardRequest) -> dict[str, Any]:
    from src.integrations.siem.siem_clients import send_to_splunk

    result = await send_to_splunk(
        [req.finding],
        splunk_url=req.config.get("splunk_url", ""),
        splunk_token=req.config.get("splunk_token", ""),
    )
    return {"success": result.success, "provider": "splunk", "error": result.error}


@router.post("/elastic")
async def forward_to_elastic(req: ForwardRequest) -> dict[str, Any]:
    from src.integrations.siem.siem_clients import send_to_elastic

    result = await send_to_elastic(
        [req.finding],
        elastic_url=req.config.get("elastic_url", ""),
        elastic_api_key=req.config.get("elastic_api_key", ""),
    )
    return {"success": result.success, "provider": "elastic", "error": result.error}


@router.post("/jira")
async def create_jira(req: ForwardRequest) -> dict[str, Any]:
    from src.integrations.siem.siem_clients import create_jira_ticket

    result = await create_jira_ticket(
        req.finding,
        jira_url=req.config.get("jira_url", ""),
        jira_user=req.config.get("jira_user", ""),
        jira_token=req.config.get("jira_token", ""),
    )
    return {"success": result.success, "provider": "jira", "external_id": result.external_id, "error": result.error}


@router.post("/servicenow")
async def create_snow(req: ForwardRequest) -> dict[str, Any]:
    from src.integrations.siem.siem_clients import create_servicenow_incident

    result = await create_servicenow_incident(
        req.finding,
        snow_url=req.config.get("snow_url", ""),
        snow_user=req.config.get("snow_user", ""),
        snow_password=req.config.get("snow_password", ""),
    )
    return {"success": result.success, "provider": "servicenow", "external_id": result.external_id, "error": result.error}


@router.post("/webhook")
async def send_webhook(url: str, payload: dict[str, Any], secret: str = "") -> dict[str, Any]:
    from src.integrations.siem.siem_clients import send_webhook as do_webhook

    result = await do_webhook(url, payload, secret=secret)
    return {"success": result.success, "provider": "webhook", "error": result.error}
