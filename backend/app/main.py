"""FastAPI application factory.

Startup order matters: configuration is validated first (fail fast on unsafe
production settings), then logging, then the database.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import __version__
from app.api.middleware import RequestContextMiddleware
from app.api.router import api_router
from app.core.config import Settings, get_settings
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging
from app.db.session import dispose_engine, init_db

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Initialise shared resources for the lifetime of the process."""
    settings: Settings = app.state.settings
    if settings.retention_policy_file:
        from app.services.retention import read_policy

        read_policy(settings.retention_policy_file)
        if not settings.retention_backup_dir:
            raise RuntimeError("Retention requires a configured backup directory.")
    settings.ensure_directories()
    init_db(settings)
    from app.security.production_checks import check_production

    check_production(settings)

    if settings.seed_demo_users and not settings.is_production:
        # Imported lazily so production images never load demo data paths.
        from app.db.seed import run_seed

        summary = run_seed(settings)
        logger.info("demo_data_ready users=%s tickets=%s", summary["users"], summary["tickets"])
    else:
        logger.info("demo_seeding_disabled")

    # Knowledge base + vector index. Building here means the first user query
    # never pays the embedding cost and a malformed document fails loudly at
    # startup rather than at answer time.
    from app.services.knowledge_service import KnowledgeService

    knowledge = KnowledgeService(settings)
    try:
        stats = knowledge.startup()
        logger.info(
            "knowledge_ready documents=%d chunks=%d provider=%s store=%s",
            stats.document_count,
            stats.chunk_count,
            stats.embedding_provider,
            stats.vector_store,
        )
    except Exception:
        # The API must still serve /health and authentication so an operator can
        # see *why* the knowledge base is unavailable.
        logger.exception("knowledge_base_failed_to_load")
    app.state.knowledge = knowledge

    # Chat pipeline: retrieval + grounded generation. Constructed here so a
    # misconfigured LLM provider fails at startup rather than at first question.
    from app.security.limit_factory import login_guard, window_limiter
    from app.services.chat_service import ChatService

    app.state.chat = ChatService(knowledge, settings)
    app.state.chat_limiter = window_limiter(
        settings, scope="chat_limiter", limit=settings.chat_rate_limit_per_minute
    )
    app.state.login_guard = login_guard(settings)

    logger.info(
        "startup_complete app=%s version=%s env=%s llm=%s vector_store=%s",
        settings.app_name,
        __version__,
        settings.app_env,
        settings.llm_provider,
        settings.vector_store,
    )
    if settings.auth_secret_ephemeral:
        logger.warning(
            "auth_secret_not_configured: a random per-process signing key was generated. "
            "Existing sessions are invalidated on restart. Set AUTH_SECRET_KEY in .env "
            "to keep sessions stable during development."
        )
    from app.services.maintenance import maintenance_loop
    from app.services.notifications import notification_loop
    from app.services.workflow_worker import recovery_loop

    worker = (
        asyncio.create_task(recovery_loop(app.state.chat.workflow_tasks, settings))
        if settings.workflow_retry_interval_seconds
        else None
    )
    maintenance = (
        asyncio.create_task(maintenance_loop(settings))
        if settings.maintenance_interval_seconds
        else None
    )
    notification_worker = (
        asyncio.create_task(notification_loop(settings))
        if settings.notification_webhook_url and settings.notification_poll_interval_seconds
        else None
    )
    try:
        yield
    finally:
        if worker is not None:
            worker.cancel()
            with suppress(asyncio.CancelledError):
                await worker
        if maintenance is not None:
            maintenance.cancel()
            with suppress(asyncio.CancelledError):
                await maintenance
        if notification_worker is not None:
            notification_worker.cancel()
            with suppress(asyncio.CancelledError):
                await notification_worker
        dispose_engine()
        logger.info("shutdown_complete")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build a fully configured application instance."""
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_format)

    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        description=(
            "RAG-based enterprise security assistant. All data is simulated; "
            "no real enterprise data is used."
        ),
        lifespan=lifespan,
        docs_url="/docs" if not settings.is_production else None,
        redoc_url=None,
        openapi_url="/openapi.json" if not settings.is_production else None,
    )
    app.state.settings = settings

    # CORS: explicit origins only, credentials allowed for the SPA.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.api_cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID"],
    )
    app.add_middleware(RequestContextMiddleware)

    register_exception_handlers(app)
    app.include_router(api_router)

    @app.get("/", include_in_schema=False)
    def root() -> JSONResponse:
        return JSONResponse(
            {
                "name": settings.app_name,
                "version": __version__,
                "docs": "/docs" if not settings.is_production else None,
                "health": "/api/v1/health",
            }
        )

    return app


app = create_app()
