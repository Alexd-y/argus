"""Web Workbench REST API routers (mounted under ``/api/v1``)."""

from fastapi import APIRouter

from src.api.routers.web_workbench.organizer import router as organizer_router
from src.api.routers.web_workbench.projects import router as projects_router
from src.api.routers.web_workbench.proxy import router as proxy_router
from src.api.routers.web_workbench.repeater import router as repeater_router
from src.api.routers.web_workbench.tools import router as tools_router

web_workbench_router = APIRouter()
web_workbench_router.include_router(projects_router)
web_workbench_router.include_router(proxy_router)
web_workbench_router.include_router(tools_router)
web_workbench_router.include_router(organizer_router)
web_workbench_router.include_router(repeater_router)

__all__ = ["web_workbench_router"]
