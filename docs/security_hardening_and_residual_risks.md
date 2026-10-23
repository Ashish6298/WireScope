# WireScope Security Hardening, Invariants, and Residual Risks

## 1. Security Architecture & Invariants

WireScope is an evidence-driven, local-first network diagnostics and defensive cybersecurity assessment engine. It is designed to be safe for automation, strictly bounded in scope, and non-destructive. The following core security invariants are enforced at compile time and runtime:

### 1.1 Input Parsing & Boundary Invariants
- **Hostnames (RFC 1123 / RFC 1035):** Maximum length 253 characters; label lengths strictly between 1 and 63 characters; lowercase normalized; hyphens forbidden as leading or trailing characters in any label. Consecutive dots (`..`) and non-alphanumeric characters return `error.MalformedHostname`.
- **IP Addresses (IPv4 / IPv6):** Dotted-decimal octets strictly bounded between 0 and 255 without leading zeros. Non-numeric or overflow octets return `error.MalformedIpAddress`. Bracketed and raw IPv6 formats strictly validated.
- **CIDR Prefixes:** Prefixes < /24 (e.g. /16, /8) are rejected as `error.ExcessiveCidrRange` unless explicit broad CIDR permissions are enabled. Subnets > /32 return `error.MalformedCidr`.
- **Port Ranges:** Port numbers must be 1–65535. Zero or values > 65535 return `error.InvalidPortRange`. Inverted ranges (e.g. `8080-80`) return `error.InvalidPortRange`. Port counts exceeding the configured cap (default: 100) return `error.ExcessivePortCount`.
- **JSON Payloads:** All external, saved, or imported JSON records are parsed with bounded buffers (max 16 MB). Truncated, malformed, or schema-violating records fail safely returning structured `StorageError` or `ReportError`.

### 1.2 Scope Guard & Authorization Enforcement
- **Pre-Execution Validation:** Target validation and plan construction happen **before** any network socket is opened, DNS packet is transmitted, or probe is scheduled.
- **Authorization Boundary:** Non-loopback targets (any IP outside `127.0.0.0/8`, `::1`, or `localhost`) require explicit operator authorization (`--confirm-authorized` or configured profile `authorization_acknowledged: true`). Running in non-interactive mode without this flag immediately terminates with exit code `2` (`ExitCodes.invalid_input`).
- **Exclusion Precedence:** Excluded targets and subnets strictly override included targets. If all targets are excluded, plan generation halts with `error.AllTargetsExcluded`.

### 1.3 DNS-Derived Target & Rebinding Protections
- **Pre-Probe DNS Scope Check:** In multi-module assessments, hostnames resolving to IP addresses are verified against the approved target scope via `verifyDnsScopeCompliance`.
- **Rebinding Prevention:** If a loopback-scoped target (e.g. `localhost`) resolves to a public or remote IP (e.g. `8.8.8.8`), the operation is blocked with `error.ScopeExpansionPrevented`. If a resolved IP matches an explicit exclusion, it is blocked with `error.ResolvedTargetExcluded`.

### 1.4 HTTP Redirection Safety
- **Cross-Host Scope Guard:** By default, HTTP probes and audits refuse to follow redirects that leave the initial host (`allow_redirect_scope_expansion: false`). Redirections to unapproved external domains or different ports are blocked pre-connection and flagged as `WS-AUDIT-HTTP-REDIRECT-SCOPE`.
- **Bounded Redirection Chains:** Redirection chains are capped at `max_redirects: 5` (configurable up to 10). Circular loops or excessive hops trigger `WS-AUDIT-HTTP-REDIRECT-LOOP`.

### 1.5 Bounded Resource Consumption
- **Response Size Limits:** HTTP response headers and bodies are bounded to a maximum buffer size (`max_response_bytes: 1MB` default). Servers returning infinite streams or oversized responses are truncated and flagged as `http_response_oversized` without exhausting memory.
- **Concurrency & Probe Deadlines:** Probe scheduling enforces monotonic deadlines and hard concurrency bounds (`max_concurrent_probes = 32`).
- **Memory Ownership:** Zero memory leaks across all test runners, verified by Zig's `GeneralPurposeAllocator` in Debug and ReleaseSafe modes.

### 1.6 Cancellation & Resource Cleanup
- **Cooperative Cancellation:** The `CancellationToken` is checked before and after DNS, TCP, TLS, and HTTP operations.
- **Socket & Handle Release:** When an assessment is cancelled or timed out, all open sockets are deterministically closed across Windows (`closesocket`) and POSIX (`close`), and buffers are freed.

### 1.7 Local Persistence & Sandbox Containment
- **Atomic File Writes:** Profile, baseline, assessment, and manifest updates write first to `{filename}.tmp.{timestamp}` and sync to disk before atomic rename, preventing file corruption during power failure or unexpected crashes.
- **Directory Traversal Defense:** `validateContainedPath` and `validateSandboxPath` enforce that all storage and lab file operations remain strictly inside designated directories. Any attempt to use `..`, `/`, `\`, drive letters, or null bytes returns `StorageError.PathTraversalEscape` or `LabManagerError.SandboxEscapeDetected`.

### 1.8 Redaction & Default Output Safety
- **Credential Masking:** When `--redact` is selected, WireScope masks Authorization headers (Bearer, Basic), API keys, passwords, and sensitive tokens.
- **Default Privacy:** Default CLI output and JSON reports omit raw response bodies and credentials.

---

## 2. Documented Residual Risks and Technical Limitations

WireScope explicitly records residual technical risks and operational boundaries rather than claiming absolute security:

| Area | Residual Risk / Limitation | Operational Impact & Mitigation |
|---|---|---|
| **DNS Rebinding Window (TOCTOU)** | A hostile authoritative DNS server could return a loopback IP during initial scope check, and return a public IP during subsequent connection attempts. | **Mitigation:** WireScope validates resolved IPs immediately prior to socket connection. In high-assurance environments, pin static IP addresses or use local `/etc/hosts` mappings. |
| **Operating System Privilege Boundaries** | Local listener process attribution (mapping ports to process names/PIDs) requires administrative privileges on Windows and Linux. | **Limitation:** In unprivileged execution, WireScope identifies listening ports and bind addresses accurately, but reports process ownership as `WS-AUDIT-EXPOSURE-PERMISSION-LIMITED`. |
| **System Clock Reliance** | TLS certificate validity evaluation (`notBefore`, `notAfter`) relies on the local host's real-time system clock. | **Limitation:** If the host system clock is skewed, valid certificates may be falsely flagged as expired, or expired certificates may be evaluated as valid. Ensure NTP time synchronization on scanning nodes. |
| **Stateful Firewall & Middlebox Interference** | Intermediate firewalls or middleboxes may forge TCP RST packets or silently drop probes. | **Limitation:** WireScope cannot distinguish between an endpoint actively rejecting a port versus an intermediate firewall spoofing a RST packet without packet captures on the destination host. Potential causes are labeled as hypotheses. |
| **Filesystem Access Control (ACLs)** | Persisted assessment history, baselines, and integrity manifests rely on operating system permissions (user umask on Linux/macOS, ACLs on Windows). | **Mitigation:** WireScope stores records in per-user application directories (`%LOCALAPPDATA%\wirescope` or `~/.local/share/wirescope`). Users must protect their user accounts and avoid shared multi-user directory overrides. |
| **Local Hash Integrity Limitations** | Integrity manifests use SHA-256 hashes to detect accidental corruption or modification. | **Limitation:** A local hash alone does not prove author identity or protect against an attacker with write access to both the report and the manifest. For non-repudiation, sign manifests with an external GPG or Sigstore private key. |
