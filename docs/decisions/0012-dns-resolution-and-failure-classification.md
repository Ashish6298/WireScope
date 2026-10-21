# Architecture Decision Record (ADR) 0012: DNS Resolution and Failure Classification

## Status
Accepted

## Context
Phase 5.1 of Milestone 5 requires implementing hostname resolution and structured failure classification.
Key requirements:
1. Support A (IPv4) and AAAA (IPv6) record queries.
2. Record resolved IP addresses, high-resolution monotonic elapsed time, resolution method, and resolver context.
3. Classify outcomes into success, no answer, NXDOMAIN, timeout, malformed input, and resolver/transport errors.
4. Validate hostnames before any network activity (RFC 1035 / RFC 1123).
5. Ensure multiple-answer ordering is stable and deterministic.
6. Provide an injectable resolver abstraction (`Resolver`, `SystemResolver`, `MockResolver`) so unit and CI testing never rely on public DNS servers or live internet access.
7. Document resolver and platform limitations clearly.

## Decision

### 1. Hostname Syntax Validation (`validateHostname`)
- Enforced according to RFC 1035 / RFC 1123 before initiating any resolver API calls:
  - Empty hostname rejected (`error.EmptyHostname`).
  - Maximum 253 characters limit enforced (`error.HostnameTooLong`).
  - Label lengths bounded between 1 and 63 characters (`error.EmptyLabel`, `error.LabelTooLong`).
  - Disallows leading and trailing hyphens on labels (`error.InvalidHyphenPlacement`).
  - Disallows illegal characters, whitespace, and control codes (`error.InvalidCharacter`).
  - Numeric IPv4 and IPv6 literals are recognized as valid endpoints.
- Syntax failures return immediately with outcome `.invalid_input` and error code `parse_error` with `elapsed_ns = 0`.

### 2. Failure Classification (`DnsFailureCategory`)
- Maps granular DNS outcomes to WireScope `OutcomeCategory` and `ErrorCode`:
  - `success`: Target resolved to $\ge 1$ IP address $\to$ `.success`, `ErrorCode.none`
  - `no_answer`: Target exists but has no records for requested family $\to$ `.no_answer`, `ErrorCode.unknown_host`
  - `nxdomain`: Hostname does not exist (`UnknownHostName`) $\to$ `.no_answer`, `ErrorCode.unknown_host`
  - `timeout`: Resolver timed out (`TemporaryNameServerFailure`) $\to$ `.timeout`, `ErrorCode.connection_timed_out`
  - `malformed_input`: Syntax error caught pre-resolution $\to$ `.invalid_input`, `ErrorCode.parse_error`
  - `resolver_transport_error`: System socket or OS resolver error $\to$ `.operational_failure`, `ErrorCode.network_unreachable`

### 3. Injectable Resolver Architecture (`src/probes/dns.zig`)
- **`Resolver` Virtual Table**: Declares `resolve(ctx, allocator, host, record_type)`.
- **`SystemResolver`**: Uses Zig stdlib `std.net.getAddressList` backed by OS `getaddrinfo` (`ws2_32.dll` on Windows, POSIX libc on Linux/macOS).
- **`MockResolver`**: Hermetic test fixture supporting configurable answers, mock categories (`nxdomain`, `timeout`, `no_answer`), and simulated latency for CI testing without public DNS dependencies.

### 4. Deterministic Multi-Answer Sorting
- Multiple IPv4 and IPv6 addresses are sorted lexicographically (`std.mem.sort`) before emission.
- Ensures identical answer order regardless of round-robin DNS responses or OS socket cache permutations.

### 5. Documented Platform Limitations
- OS `getaddrinfo` does not expose wire-level DNS flags, TTL values, authoritative NS records, or DNSSEC validation details.
- OS-level caching (`Dnscache` on Windows, `systemd-resolved` on Linux) can return cached responses with near-zero latency. WireScope preserves actual observed latency without fabricating TTL values.

## Consequences
- WireScope provides robust, RFC-compliant DNS diagnostic capabilities.
- Hermetic CI testing is guaranteed via `MockResolver`.
- Seamless integration with the shared probe result envelope (`OperationEnvelope`).
