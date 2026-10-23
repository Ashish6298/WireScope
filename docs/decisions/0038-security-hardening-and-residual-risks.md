# Architecture Decision Record (ADR) 0038: Security Hardening, Verification Engines, and Residual Risks

## Status
Accepted

## Context
Milestone 14 Phase 14.1 addresses rigorous security and reliability hardening across all WireScope subsystems before multi-platform verification and packaging. As a local-first, non-destructive network diagnostics and defensive cybersecurity assessment tool, WireScope must ensure:
1. Input parsing and boundary calculations are strictly constrained and fail safely when presented with malformed or oversized inputs.
2. Reconnaissance and audit operations cannot escape approved target scope via DNS rebinding, unapproved redirects, or broad CIDR expansion.
3. System resources are bounded, preventing unbounded memory allocation, socket descriptor exhaustion, or runaway probe loops.
4. Cancellation tokens are cooperatively respected across all execution stages, ensuring deterministic deallocation and clean socket closure.
5. Local storage and lab operations strictly respect filesystem sandbox boundaries, and interrupted writes leave no corrupted files.
6. Report generation redacts sensitive tokens and omits response bodies by default.
7. Residual technical risks are honestly recorded rather than claiming absolute security.

## Decision

### 1. Hardening & Property Fuzzing Engine (`src/core/hardening.zig`)
We implemented property-based and randomized fuzzing test suites to continuously verify defensive bounds:
- **Hostname Fuzzing (`fuzzHostnames`):** Validates RFC 1123/1035 invariants against 253-byte host limits, 63-byte label limits, consecutive dots, leading/trailing hyphens, control characters (`0x00`-`0x1F`), spaces, and symbols (`/`, `\`, `@`, etc.). All malformed strings safely return `error.MalformedHostname` or `error.EmptyTargetString` without panicking or leaking memory.
- **IPv4 Fuzzing (`fuzzIpv4`):** Tests octet values >255, non-numeric characters, invalid octet counts (<4 or >4), leading zeros, and trailing dots, confirming strict dotted-decimal normalization.
- **Port Specification Fuzzing (`fuzzPorts`):** Tests out-of-range ports (0, >65535), inverted ranges (`8080-80`), malformed separators (`80--443`), and ranges exceeding the configured safety cap (`max_ports: 100`).
- **Sandbox Path Fuzzing (`fuzzSandboxPaths`):** Tests directory traversal (`../`, `..\`, `foo/../../bar`), root escapes (`/etc/passwd`, `C:\Windows\System32`), colons, and null bytes against `validateContainedPath` and `validateSandboxPath`, verifying `StorageError.PathTraversalEscape`.
- **JSON Envelope Fuzzing:** Validates that truncated payloads, type mismatches, and corrupt envelopes safely return `error.JsonParseFailed` without panicking.

### 2. Scope-Escape Regression Protections
We codified regression tests verifying that WireScope cannot be coerced into scanning unapproved targets:
- **DNS Rebinding Prevention:** `verifyDnsScopeCompliance` verifies that if a loopback target (`localhost`) resolves to a public or remote IP (e.g. `8.8.8.8`), the operation aborts with `error.ScopeExpansionPrevented`.
- **Target Exclusion Precedence:** If a resolved IP matches an explicit exclusion, `verifyDnsScopeCompliance` aborts with `error.ResolvedTargetExcluded`.
- **HTTP Redirection Scope Guard:** Probes enforce `allow_redirect_scope_expansion: false` by default. Redirects to external hosts or ports are blocked pre-connection, recording finding `WS-AUDIT-HTTP-REDIRECT-SCOPE`.
- **Bounded Redirection Chains:** Redirect hops are capped at `max_redirects: 5` to prevent infinite loops.
- **Broad CIDR Gates:** Network prefixes < `/24` (e.g. `/16`, `/8`) are rejected by default with `error.ExcessiveCidrRange`.

### 3. Resource Bounds & Cancellation Cleanliness
- **Response Size Bounds:** HTTP headers and bodies are limited to `max_response_bytes: 1MB`, preventing memory exhaustion from streaming endpoints.
- **Cooperative Cancellation:** `CancellationToken` checks are verified across batch probes and socket loops. Cancelling terminates execution immediately and deterministically frees all memory and sockets with zero leaks.
- **Atomic File Writes:** Profile, baseline, assessment, and manifest updates write first to `{filename}.tmp.{timestamp}` and sync to disk before atomic rename. Interrupted or failing writes automatically unlink temporary files, leaving destinations untouched.
- **Report Redaction:** Sensitive credentials (Authorization Bearer/Basic headers, API keys, passwords) are masked by default as `[REDACTED]`.

### 4. Authoritative Residual Risks Catalog
In alignment with defensive honesty, WireScope exposes the `RESIDUAL_RISKS` registry in `src/core/hardening.zig` and documentation in `docs/security_hardening_and_residual_risks.md` covering:
1. **DNS Rebinding Window (TOCTOU):** Race condition between DNS verification and OS socket connect. Mitigation: pre-connect check; recommendation: static IP pinning or `/etc/hosts`.
2. **OS Privilege Boundaries:** Listener process attribution requires administrative rights on Windows and Linux. Unprivileged mode flags `WS-AUDIT-EXPOSURE-PERMISSION-LIMITED`.
3. **Host System Clock Reliance:** Certificate validity checking relies on local real-time clock. Skewed clocks cause false expiration/validity.
4. **Firewall / Middlebox Interference:** Injected TCP RST packets or silent drops cannot be distinguished from destination host behavior without remote captures.
5. **Local Filesystem Access Controls:** Storage files rely on OS permissions; no proprietary disk encryption is added.
6. **Local Hash Integrity Limitations:** SHA-256 manifests detect corruption or modification, not malicious author impersonation without external PKI signing.

## Consequences
- WireScope's test suite expands with comprehensive fuzz and regression suites covering all security boundary invariants.
- No unbounded operations remain in tested network or filesystem paths.
- Operators have explicit, transparent documentation of residual operational boundaries.
