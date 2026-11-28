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
from .telemetry import MAX_PCAP_BYTES, MAX_TEXT_BYTES, TelemetryInputError, parse_pcap, parse_suricata, parse_zeek, source_digest


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
        title="ZYRAX API",
        version="0.3.0.dev0",
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
        return {"status": "ok", "service": "zyrax", "version": "0.3.0.dev0"}

    @application.get("/", include_in_schema=False)
    async def dashboard():
        return FileResponse(BASE_DIR / "static" / "index.html")

    async def _read_bounded_upload(request: Request, maximum: int) -> bytes:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > maximum:
                    raise HTTPException(status_code=413, detail="Upload exceeds the configured size limit.")
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="Invalid Content-Length header.") from exc
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > maximum:
                raise HTTPException(status_code=413, detail="Upload exceeds the configured size limit.")
        if not body:
            raise HTTPException(status_code=400, detail="Empty telemetry upload.")
        return bytes(body)

    @application.post("/api/v1/telemetry/zeek", status_code=201)
    async def ingest_zeek(request: Request, log_type: str = "conn") -> dict[str, Any]:
        media = request.headers.get("content-type", "").split(";")[0].strip()
        if media not in {"text/plain", "application/octet-stream"}:
            raise HTTPException(status_code=415, detail="Use text/plain or application/octet-stream.")
        data = await _read_bounded_upload(request, MAX_TEXT_BYTES)
        try:
            events = parse_zeek(data, log_type)
            if not events:
                raise TelemetryInputError("No supported Zeek records were found.")
            return request.app.state.store.ingest_telemetry("zeek", source_digest(data), events)
        except TelemetryInputError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @application.post("/api/v1/telemetry/suricata", status_code=201)
    async def ingest_suricata(request: Request) -> dict[str, Any]:
        media = request.headers.get("content-type", "").split(";")[0].strip()
        if media not in {"application/x-ndjson", "application/json", "text/plain"}:
            raise HTTPException(status_code=415, detail="Use application/x-ndjson, application/json, or text/plain.")
        data = await _read_bounded_upload(request, MAX_TEXT_BYTES)
        try:
            events = parse_suricata(data)
            if not events:
                raise TelemetryInputError("No supported Suricata EVE events were found.")
            return request.app.state.store.ingest_telemetry("suricata", source_digest(data), events)
        except TelemetryInputError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @application.post("/api/v1/telemetry/pcap", status_code=201)
    async def ingest_pcap(request: Request) -> dict[str, Any]:
        media = request.headers.get("content-type", "").split(";")[0].strip()
        if media != "application/vnd.tcpdump.pcap":
            raise HTTPException(status_code=415, detail="Use application/vnd.tcpdump.pcap.")
        data = await _read_bounded_upload(request, MAX_PCAP_BYTES)
        try:
            events = parse_pcap(data)
            if not events:
                raise TelemetryInputError("No supported Ethernet IP packets were found in the capture.")
            return request.app.state.store.ingest_telemetry("pcap", source_digest(data), events)
        except TelemetryInputError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @application.get("/api/v1/telemetry/batches")
    async def list_telemetry_batches(request: Request, limit: int = 50) -> list[dict[str, Any]]:
        if not 1 <= limit <= 100:
            raise HTTPException(status_code=422, detail="limit must be between 1 and 100.")
        return request.app.state.store.list_telemetry_batches(limit)

    @application.get("/api/v1/telemetry/events")
    async def list_telemetry_events(request: Request, limit: int = 100, source: str | None = None) -> list[dict[str, Any]]:
        if not 1 <= limit <= 500:
            raise HTTPException(status_code=422, detail="limit must be between 1 and 500.")
        if source not in {None, "zeek", "suricata", "pcap"}:
            raise HTTPException(status_code=422, detail="Unsupported telemetry source.")
        return request.app.state.store.list_telemetry_events(limit, source)

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
            "# HELP zyrax_up ZYRAX API process health.",
            "# TYPE zyrax_up gauge",
            "zyrax_up 1",
            "# HELP zyrax_run_active Whether a measurement run is active.",
            "# TYPE zyrax_run_active gauge",
            f"zyrax_run_active {1 if active_id else 0}",
        ]
        if latest:
            values = latest.get("result", {})
            for metric, key in (
                ("zyrax_requests_started_total", "requests_started"),
                ("zyrax_requests_completed_total", "requests_completed"),
                ("zyrax_successful_responses_total", "successful_responses"),
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
