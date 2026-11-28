# Controlled Measurement Protocol

## Objective

Measure the behavior of an authorized private lab service under a small, repeatable HTTP request workload. The objective is to characterize service latency and errors, not to saturate the network or deny service.

## Preparation

1. Record the service owner, written authorization, permitted IP, port, date, and experiment operator outside the tool.
2. Place controller and target in a private, isolated lab network. Do not register a public address or a device outside the approved test scope.
3. Verify the target is healthy and record a quiet baseline: service CPU/memory, network throughput, response latency, and server-side HTTP status counts.
4. Register the exact IPv4 address and permitted port in the ZYRAX dashboard.

## Run sequence

Use the smallest values first. Suggested sequence: 1 RPS × 5 seconds, then 2 RPS × 5 seconds, then 5 RPS × 10 seconds. 10 RPS × 30 seconds is the application ceiling, not a recommended default. Wait for the target to recover between runs. Run no more than one experiment at a time.

Stop immediately if the service becomes unhealthy, error rates rise sharply, latency exceeds the service owner's agreed threshold, or the target operator asks to stop. The API stop action terminates new request scheduling and drains outstanding requests under a bounded timeout.

## Record and compare

For each run, retain target ID, requested rate, duration, concurrency, started/completed counts, successful responses, HTTP status distribution, timeouts, connection failures, median latency, p95/p99 latency, and actual request-start rate. Correlate these with independent target-side CPU, memory, queue, and network telemetry. The tool does not collect packet captures or host metrics itself.

Repeat the same scenario at least three times after a recovery interval before drawing conclusions. Compare the median across runs and document environmental differences. Never infer capacity from one short measurement.

## Defensive evaluation

Evaluate defensive controls on the target side (for example, server request limits, reverse-proxy connection limits, queue protection, and alerting) using the same authorized workload. Record whether the control triggered, detection delay, false positives during an idle baseline, and impact on legitimate health checks. Do not disable protections or extend the workload to force an outage.

## Attribution limits

This tool reports the target address and HTTP response behavior only. It does not infer the identity of a person or attacker from an IP address. Source attribution requires independent network, provider, and host evidence, careful time synchronization, and documented uncertainty. NAT, shared egress, VPNs, and proxies can make an IP a poor identity signal; this release does not rotate proxies or manipulate source addresses.

## Evidence handling

Store run records and the audit-chain verification output with the experiment notes. Hashes can show whether a stored artifact changed relative to a known digest, but an unsigned local hash chain is not proof of origin or non-repudiation. Do not store credentials, session tokens, or personal data in target labels or experiment notes.
