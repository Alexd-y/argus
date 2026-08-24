"""ARGUS LLM Gateway — standalone FastAPI service for multi-model orchestration.

OpenAI-compatible API. Routes requests through WhiteRabbitNeo (primary)
with cloud fallback for report supplements. Enforces JSON policy, budget,
compliance flags, and telemetry collection.
"""

from fastapi import FastAPI

from src.llm_gateway.health import router as health_router
from src.llm_gateway.router import router as chat_router

app = FastAPI(title="ARGUS LLM Gateway", version="1.0.0")

app.include_router(chat_router)
app.include_router(health_router)
