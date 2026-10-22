# Architecture Decision Record (ADR) 0014: TCP Connectivity Probes

## Status
Accepted

## Context
Phase 6.1 of Milestone 6 requires implementing explicit host/IP and port connectivity checks through the shared probe engine:
1. Validate target and port syntax before opening sockets.
2. Only requested or profile-authorized targets may be contacted (scope guard).
3. Record high-resolution monotonic connect timing.
4. Classify outcomes into typed failure categories: success, refusal, timeout, cancellation, permission errors, unreachable, malformed input, and operational failures.
5. Guarantee deterministic socket and buffer cleanup on every path.
6. Enforce per-operation timeouts and concurrency bounds via `ProbeEngine`.
7. Never mislabel TCP connection time as ICMP ping latency.
8. Use local fixtures for deterministic open, closed, timeout, invalid-input, and cancellation test cases.

## Decision

### 1. Target & Port Syntax Validation (`src/probes/tcp.zig`)
- **`parseTargetAndPort`**: Normalizes `host:port`, `[ipv6]:port`, bare hosts/IPs with default ports, and bracketed IPv6 literals.
- **Pre-Network Syntax Checks**:
  - Validates ports strictly in RFC 793 range `[1, 65535]` using `validatePort`.
  - Validates hostnames against RFC 1035 / RFC 1123 via `dns.validateHostname`.
  - Any syntax violation terminates immediately with `TcpFailureCategory.malformed_input` / `OutcomeCategory.invalid_input` without opening local sockets or initiating network packets.

### 2. Scope Enforcement & Profile Integration
- Integrated with `AssessmentProfile.isScopePermitted`:
  - Validates target host and port against profile exclusions, target CIDRs/hostnames, and port inclusions.
  - Rejects out-of-scope targets before initiating connection attempts.

### 3. Non-Blocking Connect & Cross-Platform Sockets
- **Socket Lifecycle**:
  - Allocates stream socket using `std.posix.socket(family, SOCK.STREAM, IPPROTO.TCP)`.
  - Sets non-blocking mode:
    - Windows: `ioctlsocket(sock, FIONBIO, &mode)` (where mode = 1).
    - POSIX: `fcntl(sock, F_SETFL, flags | O_NONBLOCK)`.
  - Deferred closure via `closeSocket(sock)`:
    - Windows: `ws2_32.closesocket(sock)`.
    - POSIX: `std.posix.close(sock)`.
- **Polling & Handshake Completion**:
  - Evaluates `connect()` response: immediate success (0) vs in-progress (`WSAEWOULDBLOCK` / `EINPROGRESS`).
  - Polling in 25ms slices to facilitate reactive cancellation checks:
    - Windows: Uses `ws2_32.select(0, NULL, &write_fds, &except_fds, &tv)` with `fd_set`, avoiding known `WSAPoll` connect failure bugs.
    - POSIX: Uses `std.posix.poll(&pfd, wait_ms)`.
  - Inspects socket error via `getsockopt(SOL_SOCKET, SO_ERROR)`.

### 4. Outcome & Error Classification (`TcpFailureCategory`)
- `success`: Handshake completed (`is_open = true`, `OutcomeCategory.success`, `ErrorCode.none`).
- `refusal`: Remote endpoint sent RST (`is_open = false`, `OutcomeCategory.refusal`, `ErrorCode.connection_refused`).
- `timeout`: Handshake exceeded deadline (`is_open = false`, `OutcomeCategory.timeout`, `ErrorCode.connection_timed_out`).
- `cancelled`: Token cancelled during connect (`is_open = false`, `OutcomeCategory.cancelled`, `ErrorCode.none`).
- `permission_denied`: Blocked by local firewall / lacks permissions (`OutcomeCategory.permission_denied`, `ErrorCode.permission_denied`).
- `network_unreachable`: Host or network unreachable (`OutcomeCategory.operational_failure`, `ErrorCode.network_unreachable`).
- `malformed_input`: Syntax error (`OutcomeCategory.invalid_input`, `ErrorCode.parse_error`).
- `operational_failure`: Socket/system error (`OutcomeCategory.operational_failure`, `ErrorCode.internal_error`).

### 5. Timing Semantics
- Records `tcp_connect_ns` as the exact monotonic duration of the TCP 3-way handshake.
- Segregates DNS resolution (`dns_time_ns` / `timing_stages.dns_lookup_ns`) from TCP connect time.
- Terminal rendering and JSON payloads explicitly state: "TCP connect time reflects 3-way SYN/SYN-ACK handshake duration, not ICMP echo ping latency."

### 6. Injectable Test Seams & Local Fixtures
- **`TcpConnector` interface**: Supports `RealTcpConnector` and `MockTcpConnector`.
- **Local Fixtures**:
  - Open: Ephemeral TCP server listener on `127.0.0.1:0`.
  - Refused: Unbound closed ephemeral port on `127.0.0.1`.
  - Timeout: Programmable mock or short deadline.
  - Invalid Input: Non-numeric and out-of-range ports.
  - Cancellation: `CancellationToken.cancel()` verified before and during handshake.
  - Engine Concurrency: Executed through `ProbeEngine` worker pool.

## Consequences
- Deterministic, resource-safe TCP probing with zero socket leaks.
- Clear distinction between open, refused, timed-out, and filtered states.
- Clean separation between transport connection time and ping latency.
- Full compatibility with existing CLI flags, formats, and exit codes.
