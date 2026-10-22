# Architecture Decision Record (ADR) 0021: Bounded TCP Port Checks and Conservative Service Identification

## Status
Accepted

## Context
Phase 8.3 of Milestone 8 requires implementing bounded TCP port checks and conservative service identification within explicitly authorized reconnaissance scopes:
1. Allow explicit ports and bounded ranges only. Reuse the shared TCP connector and scope guard.
2. Enforce concurrency limits, rate-limit delays, and per-probe timeouts.
3. Keep port state (`PortState`) separate from service identity (`ServiceIdentity`), confidence, and version evidence.
4. Uphold the defensive invariant: an open port does not automatically establish service identity. WireScope never assumes service identity based solely on port number.
5. Exact software versions are never reported without direct empirical evidence (such as self-reported Server headers or protocol identification strings). Speculative versions are strictly prohibited.
6. Implement a small, documented set of conservative, non-destructive protocol interactions (HTTP HEAD, SSH protocol identification banner, SMTP/FTP 220 greetings, and TLS handshake). Exploit payloads or malformed aggressive probes are forbidden.
7. Findings retain detection method and limitations.

## Decision

### 1. Port State vs. Service Identity Separation
Port state and service identity are maintained as distinct models in `src/recon/service.zig`:
- **`PortState`**: `open`, `closed` (TCP RST), `filtered_or_no_response` (timeout), `failed`, `cancelled`.
- **`ServiceIdentity`**:
  - `service_name`: Explicitly identified service name (`http`, `https`, `ssh`, `smtp`, `ftp`, or `null` if unrecognized).
  - `confidence`: `ConfidenceLevel` (`none`, `low`, `medium`, `high`, `confirmed`).
  - `version`: Software version string, populated *only* when an exact version string was observed in a banner or HTTP header; otherwise strictly `null`.
  - `banner`: Raw received protocol banner string.
  - `method`: `IdentificationMethod` (`none`, `default_port_hint`, `banner_grab`, `http_head`, `tls_handshake`).
  - `limitations`: Contextual notes documenting limitations (e.g., self-reported banners subject to server spoofing, or open port without confirmed identity).

### 2. Conservative Non-Destructive Identification Protocols
Service identification is strictly non-destructive:
- **HTTP**: Transmits standard `HEAD / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: WireScope/1.0\r\nConnection: close\r\n\r\n`. If response starts with `HTTP/`, service is confirmed (`confidence: .confirmed`, `method: .http_head`). If a `Server:` header is present, its value is extracted into `version`. If absent, `version` remains `null`.
- **SSH**: Reads initial greeting string. If it starts with `SSH-`, extracts protocol (`SSH-2.0`) and software version (e.g. `OpenSSH_8.9p1`) (`confidence: .confirmed`, `method: .banner_grab`).
- **SMTP / FTP**: Reads initial 220 banner greeting without sending commands (`confidence: .high`, `method: .banner_grab`).
- **TLS / HTTPS**: Validates TLS handshake on port 443 / 8443 (`confidence: .confirmed`, `method: .tls_handshake`).
- **Unrecognized / Silent Open Ports**: If no recognizable response is obtained, `service_name = null`, `confidence = .none`, `version = null`. The limitation explicitly notes that WireScope does not assume identity from port numbers alone.

### 3. Resource Bounds and Rate Limiting
- Reuses `AssessmentPlan` scope enforcement: only planned targets and planned ports (`plan.tasks`) are probed.
- Inter-probe rate limit delay (`rate_limit_delay_ms`) prevents burst network traffic.
- Monitored by `CancellationToken` for responsive operator interruption.

### 4. CLI and Output Formatting
- `wirescope discover <target> --ports <ports>` automatically executes bounded port checking and conservative service identification.
- Emits human-readable terminal output (`toTerminal`) with state, service, version, and limitations, plus machine-readable JSON (`toJson`).

## Consequences

### Positive
- Strict compliance with defensive security standards: no aggressive probes, no exploit payloads, no speculative version guesses.
- Clear separation between raw TCP socket state and application-layer service identity.
- Fully tested across controlled mock prober rules and live socket interactions.

### Negative
- Custom or non-standard services that do not reply to standard HTTP HEAD or send initial banners remain categorized as unrecognized (`confidence: none`).
