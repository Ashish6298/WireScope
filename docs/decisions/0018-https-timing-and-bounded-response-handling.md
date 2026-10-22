# Architecture Decision Record (ADR) 0018: HTTPS Timing and Bounded Response Handling

## Status
Accepted

## Context
Phase 7.2 of Milestone 7 requires implementing HTTPS diagnostic probing with separate timing stages, bounded response handling, and strict redirect security controls:
1. Measure TCP connect, TLS handshake, HTTP TTFB, and HTTP transfer stages separately where feasible, preserving each stage distinctly from total elapsed duration.
2. Apply total deadlines, configurable redirect thresholds (default: 5), and response-size limits (default: 1 MB).
3. Enforce privacy invariant: do not persist or store HTTP response bodies by default; only record response metadata and security headers.
4. Enforce Scope Guard: redirects must remain strictly within the approved assessment scope (initial host or configured profile targets) unless explicit authorization allows otherwise. Out-of-scope redirects must be rejected pre-connection.
5. Provide local synthetic HTTPS fixtures for success, in-scope redirect, out-of-scope redirect, redirect loop, timeout, oversized response, and invalid certificate without requiring public endpoints.
6. Provide actionable diagnostic guidance separating observed facts from unverified hypotheses.

## Decision

### 1. Granular Timing Stages (`TimingStages`)
HTTPS timings are captured via monotonic `std.time.nanoTimestamp()` and mapped into `TimingStages`:
- **`tcp_connect_ns`**: Monotonic time required for the TCP 3-way handshake.
- **`tls_handshake_ns`**: Monotonic time required for TLS 1.3 session negotiation and certificate validation.
- **`http_ttfb_ns`**: Time to First Byte — measured from the moment the HTTP request line/headers are transmitted until the first byte of the HTTP response status line is received.
- **`http_transfer_ns`**: Response transfer duration — time spent reading headers and bounded response body.
- **`total_elapsed_ns`**: Monotonic end-to-end elapsed time.
Stages are never merged or conflated into an ambiguous latency figure.

### 2. Scope Guard for Redirections
In `isRedirectPermitted()`:
- Redirections (HTTP 301, 302, 303, 307, 308) inspect the `Location` header.
- If an `AssessmentProfile` is supplied, `profile.isScopePermitted(redirect_host, redirect_port)` verifies whether the destination is in scope.
- In ad-hoc mode, redirects must match the initial target host unless `--allow-redirect-scope-expansion` is explicitly provided.
- If a redirection attempts to jump outside the approved scope, the probe immediately terminates the redirect chain, records `redirect_target`, and sets `failure_category = .redirect_out_of_scope` (ErrorCode: `.out_of_scope_target`, OutcomeCategory: `.invalid_input`).
- Redirection loops (circular chains) and chains exceeding `--max-redirects` (default 5) are trapped and halted with `.redirect_loop` and `.redirect_limit_exceeded`.

### 3. Response Bounds and Privacy Invariant
- **`max_response_bytes`**: Default bound of 1,048,576 bytes (1 MB). Configurable via `--max-response-size <bytes>`.
- **Response Body Discard**: Incoming response body bytes are consumed and counted in `response_size_bytes` without storing the body bytes in heap memory or persisting to reports.
- **Oversized Response Rejection**: If the response exceeds `max_response_bytes`, the stream is terminated immediately with `failure_category = .response_size_exceeded` (ErrorCode: `.http_response_oversized`).

### 4. Failure Classifications (`HttpsFailureCategory`)
Granular machine-readable classifications:
- `success`: Status code received within limits (e.g. 200 OK or followed redirect).
- `redirect_out_of_scope`: Redirection destination escapes approved scope.
- `redirect_loop`: Circular redirect detected.
- `redirect_limit_exceeded`: Redirections exceeded maximum hop count.
- `response_size_exceeded`: Response exceeded maximum byte limit.
- `http_protocol_error`: Malformed HTTP/1.1 response line or headers.
- `tls_certificate_expired`: Server certificate expired.
- `tls_certificate_not_yet_valid`: Server certificate not yet active.
- `tls_hostname_mismatch`: Server certificate does not match requested host.
- `tls_untrusted_chain`: Root CA not found in trust bundle.
- `tls_handshake_failed`: Incompatible TLS parameters or alert.
- `tcp_connection_failed`: Underlying TCP connect failed.
- `timeout`: Deadline exceeded.
- `cancelled`: Aborted by cancellation token.
- `malformed_input`: Syntax error in URL or port.
- `operational_failure`: OS error or memory exhaustion.

### 5. Local Synthetic HTTPS Fixtures (`src/probes/https_fixtures.zig`)
All acceptance criteria are verified through hermetic, zero-network-dependency unit tests in `MockHttpsConnector` and `https_fixtures.zig`:
- `success_200`: HTTP 200 OK with HSTS, CSP, and X-Content-Type-Options headers.
- `redirect_in_scope`: HTTP 301 followed to destination 200 OK.
- `redirect_out_of_scope`: HTTP 302 to unauthorized destination blocked by Scope Guard.
- `redirect_loop`: HTTP 302 circular loop trapped.
- `redirect_limit_exceeded`: Cascading redirect chain truncated at max_redirects.
- `oversized_response`: Response stream exceeding max_response_bytes terminated.
- `invalid_certificate`: TLS hostname mismatch rejected before HTTP stage.
- `timeout` and `cancelled`: Deadlines and cooperative cancellation verified.

### 6. Actionable Troubleshooting (`https_troubleshooting.zig`)
Diagnostic output provides structured guidance separating empirical facts (e.g., "Redirect destination escapes approved scope") from plausible hypotheses (e.g., "Target redirects to external OAuth/SSO provider") and concrete recommended actions.

## Consequences

### Positive
- Accurate visibility into network vs cryptographic vs application latency components.
- Strong defense against unintended network scanning: redirects cannot silently escape approved scope.
- Resource safety: strict response bounds prevent memory exhaustion and zip-bomb style attacks.
- Privacy-conscious: response bodies are never retained by default.
- Hermetic test suite runs in CI with zero public Internet dependencies.

### Limitations
- The probe engine currently evaluates HTTP/1.1 over TLS 1.3 or plaintext TCP. HTTP/2 and HTTP/3 multiplexing diagnostics are deferred to future extensions.
