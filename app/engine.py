from __future__ import annotations

import asyncio
import math
import time
from collections import Counter
from datetime import datetime, timezone
from statistics import median
from typing import Any

import httpx

from .config import Settings
from .db import Store, utc_now


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil((pct / 100) * len(ordered)) - 1))
    return round(ordered[index], 2)


class BoundedTrafficEngine:
    """Low-rate, fixed-destination HTTP measurement engine for private lab targets."""

    def __init__(self, settings: Settings, store: Store):
        self.settings = settings
        self.store = store
        self._active_run_id: str | None = None
        self._stop_events: dict[str, asyncio.Event] = {}
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._live: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    @property
    def active_run_id(self) -> str | None:
        return self._active_run_id

    async def start(self, run: dict[str, Any], target: dict[str, Any]) -> None:
        async with self._lock:
            if self._active_run_id is not None:
                raise RuntimeError("A measurement run is already active.")
            self._active_run_id = run["id"]
            stop_event = asyncio.Event()
            self._stop_events[run["id"]] = stop_event
            task = asyncio.create_task(self._execute(run, target, stop_event), name=f"gurgur-{run['id']}")
            self._tasks[run["id"]] = task

    def live_snapshot(self, run_id: str) -> dict[str, Any] | None:
        snapshot = self._live.get(run_id)
        return dict(snapshot) if snapshot else None

    async def shutdown(self) -> None:
        for event in self._stop_events.values():
            event.set()
        tasks = list(self._tasks.values())
        if tasks:
            try:
                await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=5.0)
            except TimeoutError:
                for task in tasks:
                    task.cancel()

    async def stop(self, run_id: str) -> bool:
        event = self._stop_events.get(run_id)
        if not event:
            return False
        event.set()
        return True

    async def _execute(self, run: dict[str, Any], target: dict[str, Any], stop_event: asyncio.Event) -> None:
        run_id = run["id"]
        started = time.monotonic()
        started_at = utc_now()
        counts: Counter[str] = Counter()
        status_counts: Counter[str] = Counter()
        latencies: list[float] = []
        semaphore = asyncio.Semaphore(run["concurrency"])
        request_tasks: set[asyncio.Task[None]] = set()
        url = f"{target['scheme']}://{target['ip']}:{target['port']}/"
        self.store.update_run(run_id, "running", {"requests_sent": 0}, started_at=started_at)

        def publish_live() -> None:
            elapsed = max(time.monotonic() - started, 0.001)
            self._live[run_id] = {
                "requests_started": counts["started"],
                "requests_completed": counts["completed"],
                "successful_responses": counts["successful"],
                "http_errors": counts["http_errors"],
                "timeouts": counts["timeouts"],
                "connection_errors": counts["connection_errors"],
                "protocol_errors": counts["protocol_errors"],
                "request_errors": counts["request_errors"],
                "actual_requests_per_second": round(counts["started"] / elapsed, 2),
                "latency_ms": {"median": round(median(latencies), 2) if latencies else None,
                               "p95": percentile(latencies, 95), "p99": percentile(latencies, 99)},
            }

        async def one_request(client: httpx.AsyncClient) -> None:
            try:
                started_request = time.perf_counter()
                async with client.stream("GET", url) as response:
                    body_bytes = 0
                    async for chunk in response.aiter_bytes(chunk_size=4096):
                        body_bytes += len(chunk)
                        if body_bytes >= self.settings.max_response_bytes:
                            break
                    elapsed_ms = (time.perf_counter() - started_request) * 1000
                    latencies.append(elapsed_ms)
                    counts["completed"] += 1
                    status_counts[str(response.status_code)] += 1
                    if 200 <= response.status_code < 400:
                        counts["successful"] += 1
                    else:
                        counts["http_errors"] += 1
                    publish_live()
            except httpx.TimeoutException:
                counts["timeouts"] += 1
                publish_live()
            except httpx.ConnectError:
                counts["connection_errors"] += 1
                publish_live()
            except httpx.HTTPError:
                counts["protocol_errors"] += 1
                publish_live()
            except Exception:
                counts["request_errors"] += 1
                publish_live()
            finally:
                semaphore.release()

        max_requests = min(
            run["requests_per_second"] * run["duration_seconds"],
            self.settings.max_requests_per_run,
        )
        interval = 1.0 / run["requests_per_second"]
        next_due = started
        deadline = started + run["duration_seconds"]
        try:
            limits = httpx.Limits(max_connections=run["concurrency"], max_keepalive_connections=run["concurrency"])
            timeout = httpx.Timeout(self.settings.request_timeout_seconds, connect=1.0)
            async with httpx.AsyncClient(
                timeout=timeout,
                limits=limits,
                follow_redirects=False,
                trust_env=False,
                verify=True,
                headers={"User-Agent": "GurGur/0.1 (+authorized-private-lab)"},
            ) as client:
                while counts["started"] < max_requests and not stop_event.is_set():
                    await semaphore.acquire()
                    now = time.monotonic()
                    if stop_event.is_set() or now >= deadline:
                        semaphore.release()
                        break
                    delay = next_due - now
                    if delay > 0:
                        try:
                            await asyncio.wait_for(stop_event.wait(), timeout=delay)
                        except TimeoutError:
                            pass
                    now = time.monotonic()
                    if stop_event.is_set() or now >= deadline:
                        semaphore.release()
                        break
                    counts["started"] += 1
                    publish_live()
                    task = asyncio.create_task(one_request(client))
                    request_tasks.add(task)
                    task.add_done_callback(request_tasks.discard)
                    # Skip missed slots instead of sending a catch-up burst after a slow target.
                    next_due = max(next_due, now) + interval
                if request_tasks:
                    try:
                        await asyncio.wait_for(asyncio.gather(*request_tasks, return_exceptions=True), timeout=3.0)
                    except TimeoutError:
                        counts["drain_timeouts"] += 1
        except Exception:
            counts["engine_errors"] += 1

        elapsed = max(time.monotonic() - started, 0.001)
        status = "failed" if counts["engine_errors"] else ("stopped" if stop_event.is_set() else "completed")
        result = {
            "requests_started": counts["started"],
            "requests_completed": counts["completed"],
            "successful_responses": counts["successful"],
            "http_errors": counts["http_errors"],
            "timeouts": counts["timeouts"],
            "connection_errors": counts["connection_errors"],
            "protocol_errors": counts["protocol_errors"],
            "request_errors": counts["request_errors"],
            "engine_errors": counts["engine_errors"],
            "drain_timeouts": counts["drain_timeouts"],
            "status_codes": dict(status_counts),
            "elapsed_seconds": round(elapsed, 3),
            "actual_requests_per_second": round(counts["started"] / elapsed, 2),
            "latency_ms": {
                "median": round(median(latencies), 2) if latencies else None,
                "p95": percentile(latencies, 95),
                "p99": percentile(latencies, 99),
                "max": round(max(latencies), 2) if latencies else None,
            },
            "finished_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        }
        self._live[run_id] = result
        self.store.update_run(run_id, status, result)
        self.store.add_audit("run.finished", run_id, {"status": status, "requests_started": counts["started"], "target_id": run["target_id"]})
        async with self._lock:
            self._stop_events.pop(run_id, None)
            self._tasks.pop(run_id, None)
            if self._active_run_id == run_id:
                self._active_run_id = None


def safe_target_summary(target: dict[str, Any]) -> dict[str, Any]:
    return {key: target[key] for key in ("id", "name", "ip", "port", "scheme", "created_at")}
