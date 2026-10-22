# Architecture Decision Record (ADR) 0026: Multi-Module Assessment Orchestrator

## Status
Accepted

## Context
Phase 10.1 of Milestone 10 requires building an assessment runner that loads a profile, validates scope, builds an execution plan, runs checks across multiple diagnostic and defensive modules through the shared probe engine, gathers observations, evaluates versioned rules, correlates findings, and generates requested reports.

Key architectural and product invariants:
1. **Multi-Module Orchestration**: Combines DNS resolution, TCP connectivity, TLS handshake validation, HTTP defensive auditing, and listening socket inventory into a single assessment workflow.
2. **Scope and Resource Bounds Invariant**: All modules strictly adhere to profile scope (targets, exclusions, port limits, and authorization gates) and resource bounds (`max_concurrency`, `timeout_ms`).
3. **Observation Preservation Invariant**: Individual task errors, connection refusals, or timeouts in subsequent checks must never erase or discard previously gathered successful observations.
4. **Accurate Assessment Status**: The overall assessment status must accurately match execution reality:
   - `completed`: All planned module tasks executed successfully.
   - `partial`: At least one task succeeded and at least one task failed or timed out.
   - `failed`: No tasks succeeded, or scope validation rejected execution.
   - `cancelled`: Execution was explicitly halted by a cancellation token or signal.
5. **Reproducible Assessment Manifest**: Produces a structured manifest containing task metrics, observation counts, finding summaries, and a deterministic SHA-256 manifest hash computed over normalized metadata.

## Decision

### 1. Module Layout and Architecture
Implemented in `src/assessment/runner.zig` and re-exported via `src/assessment/root.zig`:
- **`AssessmentRunner`**: Orchestrator executing the end-to-end pipeline:
  1. Scope validation (`profile.validate()`).
  2. Plan construction (`recon.plan.AssessmentPlan.create()`).
  3. Bounded module execution (DNS, TCP, TLS, HTTP, Listeners).
  4. Observation accumulation into `AssessmentObservations`.
  5. Isolated failure handling into `task_failures`.
  6. Correlated rule evaluation using `audit.RuleEngine`.
  7. Manifest generation with SHA-256 cryptographic hash.
- **`AssessmentObservations`**: Central repository aggregating:
  - `dns`: `DnsObservationRecord` (target, answers, duration).
  - `tcp`: `TcpObservationRecord` (target, port, is_open, rtt_ms, error).
  - `tls`: `TlsObservationRecord` (target, port, protocol_version, validity, expiration).
  - `http`: `HttpObservationRecord` (target_url, status_code, HSTS, CSP, nosniff, cookies).
  - `listeners`: `ListenerObservationRecord` (transport, address, port, binding type, PID).
- **`AssessmentManifest`**: Reproducible run record capturing ID, profile, timestamps, duration, task counts, observation metrics, finding counts, and 64-character SHA-256 digest.
- **`AssessmentResult`**: Composite assessment outcome providing multi-format renderers (`.toTerminal()`, `.toJson()`, `.toMarkdown()`).

### 2. Multi-Module Fixture & Live Execution Adapters
- **Fixture Mode (`.fixture`)**: Permits deterministic 100% offline testing without external network dependencies, simulating clean baselines, simulated timeouts, and controlled errors.
- **Live Mode (`.live`)**: Executes real socket probes and platform listener queries within declared scope bounds.

### 3. State Preservation Guarantee
When a module encounters an error:
```zig
if (options.fail_tcp) {
    tasks_failed += 1;
    try result.task_failures.append(allocator, failure_record);
    try result.observations.tcp.append(allocator, failure_observation);
} else {
    tasks_succeeded += 1;
    try result.observations.tcp.append(allocator, success_observation);
}
```
All prior and subsequent successful observations are preserved and serialized into the final report.

## Consequences

### Positive
- Unified end-to-end assessment runner replacing disparate manual module invocations.
- Complete traceability and reproducibility via deterministic manifest hashing.
- High resilience: partial network failures do not invalidate successful diagnostic observations.
- Tight integration with Milestone 9's versioned rules engine for automatic findings correlation.

### Verification
- 178 library unit tests in `src/root.zig` passing cleanly.
- Dedicated runner unit tests in `src/assessment/runner.zig` verifying:
  - Multi-module fixture combining DNS, TCP, TLS, HTTP, and socket inspection.
  - Partial failure handling and observation preservation.
  - Cancellation token semantics.
  - Scope authorization validation for remote targets.
  - Output formatting across terminal, JSON, and Markdown.
- CLI integration tests in `src/cli/root.zig` exercising `wirescope assess`.
