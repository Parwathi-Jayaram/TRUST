from __future__ import annotations

from contextlib import asynccontextmanager
import hmac
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import Settings, get_settings
from .database.neo4j_connection import Neo4jConnection, Neo4jConnectionError
from .routes.dashboard import router as dashboard_router
from .routes.blast_radius import router as blast_radius_router
from .routes.containment import router as containment_router
from .routes.graph import router as graph_router
from .routes.health import router as health_router
from .routes.incidents import router as incidents_router
from .routes.investigations import router as investigations_router
from .routes.threats import router as threats_router
from .services.incident_service import IncidentConflict, IncidentNotFound
from .services.investigation_service import (
    InvestigationConflict,
    InvestigationNotFound,
    InvestigationReferenceNotFound,
)
from .services.containment_service import (
    ContainmentTargetNotFound,
    InvalidContainmentAction,
)
from .services.member4_detection import (
    DetectionEngineUnavailable,
    DetectionInferenceError,
    Member4DetectionEngine,
)


def create_app(
    settings: Settings | None = None,
    neo4j_connection: Neo4jConnection | None = None,
    detection_engine: Member4DetectionEngine | None = None,
) -> FastAPI:
    app_settings = settings or get_settings()
    if app_settings.app_env == "production" and not app_settings.api_bearer_token:
        raise RuntimeError("API_BEARER_TOKEN must be configured in production.")
    database = neo4j_connection or Neo4jConnection(app_settings)
    member4_engine = detection_engine or Member4DetectionEngine()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.neo4j = database
        app.state.detection_engine = member4_engine
        yield
        await database.close()

    app = FastAPI(
        title="TRUSTRAIL AI API",
        description="Backend API for graph-based security operations workflows.",
        version="0.1.0",
        docs_url=None if app_settings.app_env == "production" else "/docs",
        redoc_url=None if app_settings.app_env == "production" else "/redoc",
        openapi_url=None if app_settings.app_env == "production" else "/openapi.json",
        lifespan=lifespan,
    )
    app.state.settings = app_settings
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(app_settings.cors_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["Content-Type", "Authorization"],
    )

    @app.middleware("http")
    async def require_api_bearer_token(request: Request, call_next):
        if (
            not app_settings.api_bearer_token
            or request.url.path in {"/api/health", "/healthz"}
            or request.method == "OPTIONS"
        ):
            return await call_next(request)

        provided = request.headers.get("Authorization", "")
        expected = f"Bearer {app_settings.api_bearer_token}"
        if not hmac.compare_digest(
            provided.encode("utf-8"),
            expected.encode("utf-8"),
        ):
            return JSONResponse(
                status_code=401,
                content={"success": False, "message": "Authentication required.", "data": None},
                headers={"WWW-Authenticate": "Bearer"},
            )
        return await call_next(request)

    @app.get("/healthz", include_in_schema=False)
    async def liveness() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(health_router)
    app.include_router(dashboard_router)
    app.include_router(graph_router)
    app.include_router(blast_radius_router)
    app.include_router(containment_router)
    app.include_router(incidents_router)
    app.include_router(investigations_router)
    app.include_router(threats_router)

    @app.exception_handler(Neo4jConnectionError)
    async def handle_database_error(
        request: Request,
        exc: Neo4jConnectionError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=503,
            content={"success": False, "message": str(exc), "data": None},
        )

    @app.exception_handler(DetectionEngineUnavailable)
    async def handle_detection_unavailable(
        request: Request,
        exc: DetectionEngineUnavailable,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=503,
            content={"success": False, "message": str(exc), "data": None},
        )

    @app.exception_handler(DetectionInferenceError)
    async def handle_detection_failure(
        request: Request,
        exc: DetectionInferenceError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=502,
            content={"success": False, "message": str(exc), "data": None},
        )

    @app.exception_handler(IncidentNotFound)
    async def handle_incident_not_found(
        request: Request,
        exc: IncidentNotFound,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=404,
            content={"success": False, "message": "Incident not found.", "data": None},
        )

    @app.exception_handler(IncidentConflict)
    async def handle_incident_conflict(
        request: Request,
        exc: IncidentConflict,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=409,
            content={"success": False, "message": str(exc), "data": None},
        )

    @app.exception_handler(ContainmentTargetNotFound)
    async def handle_containment_target_not_found(
        request: Request,
        exc: ContainmentTargetNotFound,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=404,
            content={"success": False, "message": "Containment target not found.", "data": None},
        )

    @app.exception_handler(InvalidContainmentAction)
    async def handle_invalid_containment_action(
        request: Request,
        exc: InvalidContainmentAction,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={"success": False, "message": str(exc), "data": None},
        )

    @app.exception_handler(InvestigationNotFound)
    async def handle_investigation_not_found(
        request: Request,
        exc: InvestigationNotFound,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=404,
            content={"success": False, "message": "Investigation not found.", "data": None},
        )

    @app.exception_handler(InvestigationReferenceNotFound)
    async def handle_investigation_reference_not_found(
        request: Request,
        exc: InvestigationReferenceNotFound,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=404,
            content={"success": False, "message": str(exc), "data": None},
        )

    @app.exception_handler(InvestigationConflict)
    async def handle_investigation_conflict(
        request: Request,
        exc: InvestigationConflict,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=409,
            content={"success": False, "message": str(exc), "data": None},
        )

    return app


app = create_app()
