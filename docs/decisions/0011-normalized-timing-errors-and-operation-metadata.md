# Architecture Decision Record (ADR) 0011: Normalized Timing, Errors, and Operation Metadata

## Status
Accepted

## Context
Phase 4.2 of Milestone 4 requires normalizing operation metadata, timing semantics, structured errors, and capability limitations across all WireScope probes.
Key requirements:
1. Shared operation IDs, target specifications, profile references, and start/end metadata.
2. High-resolution monotonic elapsed time alongside separate probe-specific timing stages.
3. Structured, machine-readable error categories with clear mapping to outcome categories.
4. Deterministic JSON serialization with character-exact key ordering.
5. Explicit distinguishability between partial, cancelled, and inconclusive operations.
6. Injectable clock test seams (`Clock`, `SystemClock`, `MockClock`) for deterministic timing tests without reliance on sleep or wall-clock drift.

## Decision

### 1. Clock Abstraction & Injectable Test Seams (`src/core/clock.zig`)
- **`Clock` Interface**: Uses a virtual table (`nowMs` and `monotonicNs`) allowing callers to swap system time with mock time.
- **`SystemClock`**: Production implementation delegating to `std.time.milliTimestamp()` and `std.time.nanoTimestamp()`.
- **`MockClock`**: Injectable test double allowing simulated, deterministic time stepping (`advanceMs`, `advanceNs`). Prevents brittle test delays and enables instant simulation of multi-hour deadlines.

### 2. Normalized Timing Stages (`src/core/timing.zig`)
- **`TimingStages`**: Keeps probe-specific stages distinct from total duration:
  - `dns_lookup_ns: ?u64`: DNS resolution latency.
  - `tcp_connect_ns: ?u64`: TCP 3-way handshake duration.
  - `tls_handshake_ns: ?u64`: TLS handshake negotiation duration.
  - `http_ttfb_ns: ?u64`: Time to first byte of HTTP response headers.
  - `http_transfer_ns: ?u64`: HTTP response body stream duration.
  - `total_elapsed_ns: u64`: End-to-end monotonic elapsed time.
- **Deterministic Stage Serialization**: Emits JSON keys in strictly fixed order (`dns_lookup_ns` -> `tcp_connect_ns` -> `tls_handshake_ns` -> `http_ttfb_ns` -> `http_transfer_ns` -> `total_elapsed_ns`).
- **`OperationIdGenerator`**: Atomic monotonic generator yielding formatted operation identifiers (`op_<prefix>_<000001>`).

### 3. Structured Error Categories (`src/core/errors.zig`)
- Machine-readable `ErrorCode` enum comprehensively mapped to `OutcomeCategory` via `ErrorCode.toOutcome()`:
  - Network refusals (`.connection_refused`) -> `.refusal`
  - Timeouts (`.connection_timed_out`) -> `.timeout`
  - Unresolved hostnames (`.unknown_host`) -> `.no_answer`
  - Policy/scope limits (`.out_of_scope_target`, `.scope_limit_exceeded`) -> `.invalid_input`
  - Permission limits (`.permission_denied`) -> `.permission_denied`
  - Platform/API limits (`.unsupported_platform_api`) -> `.unsupported_capability`
  - Cancellation (`.operation_cancelled`) -> `.cancelled`
  - Transport/protocol errors (`.tls_handshake_failed`, `.http_protocol_error`, `.io_error`) -> `.operational_failure`
- Structured errors provide `toJson()` for clean serialization with error codes, human-readable messages, and optional technical details.

### 4. Normalized Operation Envelope (`src/core/results.zig`)
- **`OperationEnvelope`**: Universal result envelope for all probes:
  - `operation_id: []const u8`
  - `operation_type: OperationType` (`dns`, `tcp`, `tls`, `http`, `interface`, `listener`, `generic`)
  - `target: []const u8`
  - `profile_id: ?[]const u8`
  - `start_time_ms: i64`, `end_time_ms: i64`, `monotonic_elapsed_ns: u64`
  - `outcome: OutcomeCategory`
  - `is_partial: bool`
  - `timing_stages: TimingStages`
  - `err: StructuredError`
  - `capability_limitations: ?[]const u8`
  - `payload: OperationPayload`
- **Deterministic Key Order**: Fixed ordering in `toJson()` ensures regression-test stability and repeatable JSON digests.
- **Answer Sorting**: `DnsPayload.sortAnswers()` sorts DNS answers lexicographically before serialization.

### 5. Distinguishability Guarantee
- Partial operations (`is_partial = true`) are clearly distinguished from complete operations (`is_partial = false`).
- Cancelled operations (`outcome = .cancelled`) are distinct from timed out operations (`outcome = .timeout`), which in turn are distinct from inconclusive ones (`outcome = .inconclusive`).

## Consequences
- Every probe module in subsequent milestones (DNS, TCP, TLS, HTTP) now shares a unified, evidence-driven result contract.
- Testing timing logic no longer requires nondeterministic wall-clock delays.
- Downstream reporting, storage, and policy engines receive standardized schemas with deterministic JSON formatting.
