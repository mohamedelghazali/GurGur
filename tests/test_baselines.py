from app.baselines import analyze


def event(source, kind, timestamp):
    return {"source": source, "event_type": kind, "timestamp": timestamp}


def test_baseline_is_deterministic_and_groups_by_source_type():
    events = [event("zeek", "connection", f"2026-01-01T00:0{i}:00Z") for i in range(6)]
    assert analyze(events) == analyze(list(reversed(events)))
    result = analyze(events)
    assert result["series"][0]["bucket_count"] == 6
    assert result["series"][0]["baseline_ready"] is True


def test_drift_requires_history_and_nonzero_median():
    history = [event("zeek", "connection", f"2026-01-01T00:0{i}:00Z") for i in range(5)]
    latest = [event("zeek", "connection", "2026-01-01T00:25:00Z") for _ in range(4)]
    result = analyze(history + latest)
    assert result["series"][0]["volume_drift_3x"] is True


def test_invalid_timestamps_are_ignored():
    result = analyze([event("zeek", "conn", "bad")])
    assert result["ignored_invalid_timestamps"] == 1
    assert result["series"] == []
