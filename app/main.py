from __future__ import annotations

import hmac
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from .audit import create_signed_checkpoint, verify_signed_checkpoint
from .config import Settings
from .db import Store, utc_now
from .engine import BoundedTrafficEngine, safe_target_summary
from .safety import validate_private_target, validate_target_url
from .schemas import AuditCheckpoint, RunCreate, StopResponse, TargetCreate


BASE_DIR = Path(__file__).resolve().parent


def _security_headers(response) -> None:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved_settings = settings or Settings.from_env()
    store = Store(resolved_settings.database_path)
    engine = BoundedTrafficEngine(resolved_settings, store)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        engine.recover_abandoned_runs_if_idle()
        yield
        await engine.shutdown()
        store.close()

    application = FastAPI(
        title="GurGur API",
        version="0.2.0",
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
            if (
                scheme.lower() != "bearer"
                or not supplied
                or not hmac.compare_digest(
                    supplied.encode("utf-8"),
                    resolved_settings.api_key.encode("utf-8"),
                )
            ):
                response = PlainTextResponse(
                    "Unauthorized",
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"},
                )
                response.headers["Cache-Control"] = "no-store"
                _security_headers(response)
                return response
        response = await call_next(request)
        _security_headers(response)
        if request.url.path.startswith("/api/") or request.url.path == "/metrics":
            response.headers["Cache-Control"] = "no-store"
        return response

    @application.get("/health", tags=["system"])
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "gurgur", "version": "0.2.0"}

    @application.get("/", include_in_schema=False)
    async def dashboard():
        return FileResponse(BASE_DIR / "static" / "index.html")

    @application.get("/api/v1/targets")
    async def list_targets(request: Request) -> list[dict[str, Any]]:
        return [
            safe_target_summary(item)
            for item in request.app.state.store.list_targets()
        ]

    @application.post("/api/v1/targets", status_code=201)
    async def create_target(payload: TargetCreate, request: Request) -> dict[str, Any]:
        current_store: Store = request.app.state.store
        if current_store.count_targets() >= 100:
            raise HTTPException(
                status_code=409,
                detail="This lab profile is limited to 100 registered targets.",
            )
        ip = validate_private_target(payload.ip)
        record = {
            "id": str(uuid.uuid4()),
            "name": payload.name,
            "ip": ip,
            "port": payload.port,
            "scheme": payload.scheme,
            "created_at": utc_now(),
        }
        current_store.add_target(record)
        current_store.add_audit(
            "target.registered",
            record["id"],
            {"ip": ip, "port": payload.port, "scheme": payload.scheme},
        )
        return safe_target_summary(record)

    @application.post("/api/v1/runs", status_code=202)
    async def create_run(payload: RunCreate, request: Request) -> dict[str, Any]:
        current_engine: BoundedTrafficEngine = request.app.state.engine
        current_store: Store = request.app.state.store
        limits: Settings = request.app.state.settings

        if payload.requests_per_second > limits.max_rps:
            raise HTTPException(
                status_code=422,
                detail=f"Rate exceeds the hard limit of {limits.max_rps} requests/second.",
            )
        if payload.duration_seconds > limits.max_duration_seconds:
            raise HTTPException(
                status_code=422,
                detail=f"Duration exceeds the hard limit of {limits.max_duration_seconds} seconds.",
            )
        if payload.concurrency > limits.max_concurrency:
            raise HTTPException(
                status_code=422,
                detail=f"Concurrency exceeds the hard limit of {limits.max_concurrency}.",
            )
        if payload.requests_per_second * payload.duration_seconds > limits.max_requests_per_run:
            raise HTTPException(
                status_code=422,
                detail=f"Run exceeds the hard budget of {limits.max_requests_per_run} requests.",
            )

        target = current_store.get_target(payload.target_id)
        if not target:
            raise HTTPException(status_code=404, detail="Registered target not found.")
        validate_target_url(
            f"{target['scheme']}://{target['ip']}:{target['port']}/"
        )

        record = {
            "id": str(uuid.uuid4()),
            "target_id": target["id"],
            "status": "queued",
            "requests_per_second": payload.requests_per_second,
            "duration_seconds": payload.duration_seconds,
            "concurrency": payload.concurrency,
        }
        try:
            await current_engine.start(record, target)
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {
            "id": record["id"],
            "status": "running",
            "target": safe_target_summary(target),
        }

    @application.get("/api/v1/runs")
    async def list_runs(request: Request) -> list[dict[str, Any]]:
        return request.app.state.store.list_runs()

    @application.get("/api/v1/runs/{run_id}")
    async def get_run(run_id: str, request: Request) -> dict[str, Any]:
        record = request.app.state.store.get_run(run_id)
        if not record:
            raise HTTPException(status_code=404, detail="Run not found.")
        if record["status"] == "running":
            record["live"] = record["result"]
        return record

    @application.post("/api/v1/runs/{run_id}/stop", response_model=StopResponse)
    async def stop_run(run_id: str, request: Request) -> StopResponse:
        record = request.app.state.store.get_run(run_id)
        if not record:
            raise HTTPException(status_code=404, detail="Run not found.")
        stopped = await request.app.state.engine.stop(run_id)
        return StopResponse(
            run_id=run_id,
            status="stopping" if stopped else "already_finished",
        )

    @application.get("/api/v1/audit/verify")
    async def verify_audit(request: Request) -> dict[str, Any]:
        return request.app.state.store.verify_audit_chain()

    @application.post("/api/v1/audit/checkpoints", status_code=201)
    async def create_audit_checkpoint(request: Request) -> dict[str, Any]:
        settings: Settings = request.app.state.settings
        current_store: Store = request.app.state.store
        if not settings.audit_signing_key:
            raise HTTPException(
                status_code=503,
                detail="Detached audit checkpoints are not configured. Set LAB_AUDIT_SIGNING_KEY.",
            )
        chain = current_store.verify_audit_chain()
        if not chain["valid"]:
            raise HTTPException(status_code=409, detail="Audit chain verification failed.")
        head = current_store.audit_head()
        checkpoint = create_signed_checkpoint(
            head["event_count"],
            head["head_hash"],
            settings.audit_signing_key,
            settings.audit_signing_key_id,
        )
        current_store.add_audit(
            "audit.checkpoint.created",
            None,
            {
                "key_id": checkpoint["key_id"],
                "event_count": checkpoint["event_count"],
                "head_hash": checkpoint["head_hash"],
            },
        )
        return checkpoint

    @application.post("/api/v1/audit/checkpoints/verify")
    async def verify_audit_checkpoint(
        payload: AuditCheckpoint, request: Request
    ) -> dict[str, Any]:
        settings: Settings = request.app.state.settings
        current_store: Store = request.app.state.store
        if not settings.audit_signing_key:
            raise HTTPException(
                status_code=503,
                detail="Audit checkpoint verification is not configured. Set LAB_AUDIT_SIGNING_KEY.",
            )
        checkpoint = payload.model_dump()
        signature_valid = verify_signed_checkpoint(
            checkpoint,
            settings.audit_signing_key,
            settings.audit_signing_key_id,
        )
        current_chain = current_store.verify_audit_chain()
        checkpoint_head_present = (
            current_store.audit_hash_at(checkpoint["event_count"])
            == checkpoint["head_hash"]
        )
        valid = signature_valid and checkpoint_head_present and current_chain["valid"]
        return {
            "valid": valid,
            "signature_valid": signature_valid,
            "checkpoint_head_present": checkpoint_head_present,
            "current_chain_valid": current_chain["valid"],
            "key_id": checkpoint["key_id"],
            "checkpoint_event_count": checkpoint["event_count"],
            "current_event_count": current_chain["checked_events"],
        }

    @application.get("/metrics", response_class=PlainTextResponse)
    async def prometheus_metrics(request: Request) -> str:
        current_store: Store = request.app.state.store
        active_id = current_store.get_active_run_id()
        latest = (
            current_store.get_run(active_id)
            if active_id
            else (current_store.list_runs(1) or [None])[0]
        )
        lines = [
            "# HELP gurgur_up GurGur API process health.",
            "# TYPE gurgur_up gauge",
            "gurgur_up 1",
            "# HELP gurgur_run_active Whether a measurement run is active.",
            "# TYPE gurgur_run_active gauge",
            f"gurgur_run_active {1 if active_id else 0}",
        ]
        if latest:
            values = latest.get("result", {})
            for metric, key in (
                ("gurgur_requests_started_total", "requests_started"),
                ("gurgur_requests_completed_total", "requests_completed"),
                ("gurgur_successful_responses_total", "successful_responses"),
            ):
                lines.extend(
                    [f"# TYPE {metric} counter", f"{metric} {int(values.get(key, 0))}"]
                )
        return "\n".join(lines) + "\n"

    application.mount(
        "/static", StaticFiles(directory=BASE_DIR / "static"), name="static"
    )
    return application


app = create_app()
