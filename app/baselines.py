from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from statistics import median
from typing import Any

BASELINE_VERSION = "0.1.0"
MIN_BUCKETS = 5
BUCKET_SECONDS = 300


def _timestamp(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except ValueError:
        return None


def analyze(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize event-type volume by fixed UTC five-minute buckets; never emits verdicts."""
    buckets: dict[tuple[str, str, int], int] = defaultdict(int)
    ignored = 0
    for event in events:
        source = str(event.get("source", "unknown"))
        kind = str(event.get("event_type", "unknown"))
        ts = _timestamp(event.get("timestamp"))
        if ts is None:
            ignored += 1
            continue
        buckets[(source, kind, ts // BUCKET_SECONDS)] += 1

    grouped: dict[tuple[str, str], list[tuple[int, int]]] = defaultdict(list)
    for (source, kind, bucket), count in buckets.items():
        grouped[(source, kind)].append((bucket, count))

    rows = []
    for (source, kind), points in sorted(grouped.items()):
        points.sort()
        counts = [count for _, count in points]
        latest_bucket, latest_count = points[-1]
        history = counts[:-1]
        baseline = median(history) if len(history) >= MIN_BUCKETS else None
        drift = baseline is not None and baseline > 0 and latest_count >= baseline * 3
        rows.append({
            "source": source, "event_type": kind, "bucket_count": len(points),
            "latest_bucket_start": datetime.fromtimestamp(latest_bucket * BUCKET_SECONDS, timezone.utc).isoformat(),
            "latest_count": latest_count, "median_historical_bucket_count": baseline,
            "baseline_ready": baseline is not None, "volume_drift_3x": bool(drift),
            "interpretation": "Review signal only; not a security verdict.",
        })
    return {
        "version": BASELINE_VERSION, "bucket_seconds": BUCKET_SECONDS,
        "minimum_historical_buckets": MIN_BUCKETS, "event_count": len(events),
        "ignored_invalid_timestamps": ignored, "series": rows,
    }
