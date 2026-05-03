from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.database import init_db
from app.routers import analysis, dashboard, nef, nrf, scanner, tester, udm
from core.database import init_db as init_scanner_db

logging.basicConfig(
    level=getattr(logging, settings.log_level, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("5gc-security-lab")


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    init_scanner_db()
    logger.info("Application initialized with DB at %s", settings.db_path)
    yield


app = FastAPI(
    title="5G Core Microservice API Security & Injection Attack Tester (OpenAPI-driven)",
    description=(
        "OpenAPI-driven testing platform for injection vulnerabilities and authorization flaws in 5G core microservice APIs."
    ),
    version=settings.app_version,
    lifespan=lifespan,
    docs_url="/docs" if settings.docs_enabled else None,
    redoc_url="/redoc" if settings.docs_enabled else None,
    openapi_url="/openapi.json" if settings.docs_enabled else None,
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.middleware("http")
async def telemetry_middleware(request: Request, call_next):
    request_id = request.headers.get("x-request-id", str(uuid.uuid4()))
    start = time.perf_counter()
    response = await call_next(request)
    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    logger.info(
        "%s %s -> %s in %.2fms [request_id=%s]",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
        request_id,
    )
    return response

app.include_router(dashboard.router)
app.include_router(analysis.router)
app.include_router(scanner.router)
app.include_router(nrf.router)
app.include_router(udm.router)
app.include_router(nef.router)
app.include_router(tester.router)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "project": app.title}


@app.get("/health/ready")
def readiness() -> JSONResponse:
    if settings.db_path.exists():
        return JSONResponse(
            {
                "status": "ready",
                "database": str(settings.db_path),
                "environment": settings.app_env,
                "version": settings.app_version,
            }
        )
    return JSONResponse(
        {"status": "not_ready", "database": str(settings.db_path)},
        status_code=503,
    )
