# Behavioral Baselines — v0.5 development

ZYRAX v0.5 introduces a deterministic offline behavioral summary for imported telemetry.

- Fixed epoch-aligned 5-minute buckets.
- Aggregates event volume by telemetry source and event type.
- Baseline readiness requires at least five prior buckets.
- Median historical bucket volume is the baseline; the latest bucket is flagged for review only when it is at least 3x a non-zero baseline median.
- Invalid timestamps are counted and excluded.
- No external network access, live sensor interaction, or response actions.

This first increment is deliberately narrow: volume-based drift is not anomaly proof and is susceptible to sparse data, clock gaps, and uneven collection. The API exposes a review signal only. Calibration, rate normalization, per-entity profiles, and labeled validation remain future increments.
