# Architecture Decision Record (ADR) 0004: Typed Results, Error Model, and Memory Ownership

## Status
Accepted

## Context
Phase 1.2 of Milestone 1 requires defining common result metadata, strongly-typed outcome categories, probe-specific payloads, machine-readable structured errors, and explicit resource ownership rules. The system must guarantee that failed, unsupported, or inconclusive operations cannot be misrepresented as success.

## Decision

### 1. Typed Outcome Categories
Defined `OutcomeCategory` enum (`src/core/outcome.zig`) encompassing:
- `success`: Fully verified positive outcome.
- `refusal`: Target actively rejected connection (e.g., TCP RST).
- `timeout`: Operation exceeded bounded deadline.
- `no_answer`: DNS/query produced no answer or NXDOMAIN.
- `invalid_input`: Malformed host, port, or configuration.
- `permission_denied`: Operation lacked necessary OS privileges.
- `unsupported_capability`: OS or environment lacks required API.
- `inconclusive`: Evidence insufficient to prove reachability or state.
- `cancelled`: Terminated early by user or overall deadline.
- `operational_failure`: Unexpected I/O or protocol error.

Invariants: `OutcomeCategory.isSuccess()` evaluates to true strictly for `.success`. All other outcomes evaluate to false.

### 2. Envelope Pattern for Probe-Specific Payloads
Rather than forcing unrelated fields onto every operation, `OperationEnvelope` (`src/core/results.zig`) contains common metadata:
- `operation_id`: Unique identifier
- `target`: Canonical target string
- `profile_id`: Optional active profile
- `start_time_ms`: UTC epoch timestamp
- `elapsed_ns`: High-resolution monotonic duration
- `outcome`: `OutcomeCategory`
- `err`: `StructuredError`
- `payload`: Tagged union `OperationPayload` with distinct variants:
  - `dns`: `DnsPayload` (answers, record type, resolver, ttl)
  - `tcp`: `TcpPayload` (port, is_open, connect_time_ns, bytes sent/received)
  - `tls`: `TlsPayload` (protocol version, cipher, subject, issuer, expiry, hostname match, chain validity)
  - `http`: `HttpPayload` (status code, security headers, redirect target, response size)
  - `interface`: `InterfacePayload` (adapter name, display name, IPv4/IPv6, status)
  - `listener`: `ListenerPayload` (local address, port, loopback/wildcard flags, pid)
  - `generic`: `GenericPayload` (sample count, details)

### 3. Machine-Readable Structured Error Model
Defined `StructuredError` (`src/core/errors.zig`) with:
- `code`: `ErrorCode` enum for programmatic classification.
- `message`: Sanitized error string.
- `details`: Optional diagnostic context, scrubbed of secrets.
- `toOutcome()`: Deterministic mapping from error code to `OutcomeCategory`.

### 4. Memory Ownership and Cleanup Conventions
- Allocations are explicitly caller-owned.
- Any structure holding dynamically allocated slices or strings implements a deterministic `deinit(allocator: std.mem.Allocator) void` method.
- Unit tests use `std.testing.allocator` to detect any memory leaks upon teardown.

## Consequences
- Compile-time safety across all probe outcomes and payloads.
- Zero memory leakage verified across all tested payload constructions.
- Complete independence from terminal rendering; core types are embeddable and serializable.
