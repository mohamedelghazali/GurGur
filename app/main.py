from __future__ import annotations

import hmac
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from .config import Settings
from .db import Store, utc_now
from .engine import BoundedTrafficEngine, safe_target_summary
from .safety import validate_private_target, validate_target_url
from .schemas import RunCreate, StopResponse, TargetCreate


BASE_DIR = Path(__file__).resolve().parent


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved_settings = settings or Settings.from_env()
    store = Store(resolved_settings.database_path)
    engine = BoundedTrafficEngine(resolved_settings, store)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        await engine.shutdown()
        store.close()

    application = FastAPI(
        title="GurGur API",
        version="0.1.0",
        description="Bounded traffic measurement and defensive telemetry for private lab targets.",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    application.state.store = store
    application.state.engine = engine
    application.state.settings = resolved_settings

    @application.middleware("http")
    async def api_key_guard(request: Request, call_next):
        if request.url.path.startswith("/api/") or request.url.path == "/metrics":
            authorization = request.headers.get("authorization", "")
            scheme, _, supplied = authorization.partition(" ")
            if scheme.lower() != "bearer" or not supplied or not hmac.compare_digest(supplied.encode("utf-8"), resolved_settings.api_key.encode("utf-8")):
                return PlainTextResponse("Unauthorized", status_code=401, headers={"WWW-Authenticate": "Bearer"})
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
            "img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        )
        if request.url.path.startswith("/api/") or request.url.path == "/metrics":
            response.headers["Cache-Control"] = "no-store"
        return response

    @application.get("/health", tags=["system"])
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "gurgur", "version": "0.1.0"}

    @application.get("/", include_in_schema=False)
    async def dashboard():
        return FileResponse(BASE_DIR / "static" / "index.html")

    @application.get("/api/v1/targets")
    async def list_targets(request: Request) -> list[dict[str, Any]]:
        return [safe_target_summary(item) for item in request.app.state.store.list_targets()]

    @application.post("/api/v1/targets", status_code=201)
    async def create_target(payload: TargetCreate, request: Request) -> dict[str, Any]:
        if request.app.state.store.count_targets() >= 100:
            raise HTTPException(status_code=409, detail="This lab profile is limited to 100 registered targets.")
        ip = validate_private_target(payload.ip)
        record = {
            "id": str(uuid.uuid4()),
            "name": payload.name,
            "ip": ip,
            "port": payload.port,
            "scheme": payload.scheme,
            "created_at": utc_now(),
        }
        request.app.state.store.add_target(record)
        request.app.state.store.add_audit("target.registered", record["id"], {"ip": ip, "port": payload.port, "scheme": payload.scheme})
        return safe_target_summary(record)

    @application.post("/api/v1/runs", status_code=202)
    async def create_run(payload: RunCreate, request: Request) -> dict[str, Any]:
        current_engine: BoundedTrafficEngine = request.app.state.engine
        current_store: Store = request.app.state.store
        settings: Settings = request.app.state.settings

        if payload.requests_per_second > settings.max_rps:
            raise HTTPException(status_code=422, detail=f"Rate exceeds the hard limit of {settings.max_rps} requests/second.")
        if payload.duration_seconds > settings.max_duration_seconds:
            raise HTTPException(status_code=422, detail=f"Duration exceeds the hard limit of {settings.max_duration_seconds} seconds.")
        if payload.concurrency > settings.max_concurrency:
            raise HTTPException(status_code=422, detail=f"Concurrency exceeds the hard limit of {settings.max_concurrency}.")
        if payload.requests_per_second * payload.duration_seconds > settings.max_requests_per_run:
            raise HTTPException(status_code=422, detail=f"Run exceeds the hard budget of {settings.max_requests_per_run} requests.")

        target = current_store.get_target(payload.target_id)
        if not target:
            raise HTTPException(status_code=404, detail="Registered target not found.")
        validate_target_url(f"{target['scheme']}://{target['ip']}:{target['port']}/")
        if current_engine.active_run_id is not None:
            raise HTTPException(status_code=409, detail="A measurement run is already active.")

        record = {
            "id": str(uuid.uuid4()),
            "target_id": target["id"],
            "status": "queued",
            "requests_per_second": payload.requests_per_second,
            "duration_seconds": payload.duration_seconds,
            "concurrency": payload.concurrency,
        }
        current_store.create_run(record)
        current_store.add_audit("run.created", record["id"], {
            "target_id": target["id"],
            "requests_per_second": payload.requests_per_second,
            "duration_seconds": payload.duration_seconds,
            "concurrency": payload.concurrency,
        })
        try:
            await current_engine.start(record, target)
        except RuntimeError as exc:
            current_store.update_run(record["id"], "failed", {"reason": "engine_busy"})
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"id": record["id"], "status": "running", "target": safe_target_summary(target)}

    @application.get("/api/v1/runs")
    async def list_runs(request: Request) -> list[dict[str, Any]]:
        return request.app.state.store.list_runs()

    @application.get("/api/v1/runs/{run_id}")
    async def get_run(run_id: str, request: Request) -> dict[str, Any]:
        record = request.app.state.store.get_run(run_id)
        if not record:
            raise HTTPException(status_code=404, detail="Run not found.")
        live = request.app.state.engine.live_snapshot(run_id)
        if live and record["status"] == "running":
            record["live"] = live
        return record

    @application.post("/api/v1/runs/{run_id}/stop", response_model=StopResponse)
    async def stop_run(run_id: str, request: Request) -> StopResponse:
        record = request.app.state.store.get_run(run_id)
        if not record:
            raise HTTPException(status_code=404, detail="Run not found.")
        stopped = await request.app.state.engine.stop(run_id)
        if stopped:
            request.app.state.store.add_audit("run.stop_requested", run_id, {})
            return StopResponse(run_id=run_id, status="stopping")
        return StopResponse(run_id=run_id, status="already_finished")

    @application.get("/api/v1/audit/verify")
    async def verify_audit(request: Request) -> dict[str, Any]:
        return request.app.state.store.verify_audit_chain()

    @application.get("/metrics", response_class=PlainTextResponse)
    async def prometheus_metrics(request: Request) -> str:
        store: Store = request.app.state.store
        active_id = request.app.state.engine.active_run_id
        latest = store.get_run(active_id) if active_id else (store.list_runs(1) or [None])[0]
        lines = [
            "# HELP gurgur_up GurGur API process health.",
            "# TYPE gurgur_up gauge",
            "gurgur_up 1",
            "# HELP gurgur_run_active Whether a measurement run is active.",
            "# TYPE gurgur_run_active gauge",
            f"gurgur_run_active {1 if active_id else 0}",
        ]
        if latest:
            values = request.app.state.engine.live_snapshot(active_id) if active_id else None
            values = values or latest.get("result", {})
            for metric, key in (("gurgur_requests_started_total", "requests_started"), ("gurgur_requests_completed_total", "requests_completed"), ("gurgur_successful_responses_total", "successful_responses")):
                lines.extend([f"# TYPE {metric} counter", f"{metric} {int(values.get(key, 0))}"])
        return "\n".join(lines) + "\n"

    application.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
    return application


app = create_app()
