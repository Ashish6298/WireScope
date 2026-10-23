# Architecture Decision Record (ADR) 0037: Initial Diagnostic and Defensive Practice Exercises

## Status
Accepted

## Context
Milestone 13 Phase 13.2 requires implementing the six core practice lab scenarios specified in `wirescope_project.txt`:
1. DNS no-answer or timeout (`dns_failure`).
2. TCP connection refusal and bounded timeout (`tcp_refusal_timeout`).
3. TLS certificate expiration and hostname mismatch using isolated test-only fixtures (`tls_cert_issues`).
4. Unexpected local listening service detected via baseline diffing (`unexpected_listener`).
5. HTTP defensive security header policy violation on a controlled loopback endpoint (`http_security_header_violation`).
6. Remediation verification demonstrating observable change across consecutive assessments (`remediation_verification`).

To satisfy defensive training principles without offensive capabilities:
- Every scenario must run 100% locally on loopback without contacting public servers or requiring paid APIs.
- Each exercise must explicitly articulate:
  * Objective
  * Expected Evidence
  * Observed Evidence
  * Technical Interpretation
  * Operational Limitations
  * Defensive Resolution
- Test-only certificates and fixtures must be isolated from the system trust store.
- Remediations must be verified through baseline diffs showing that previous findings transition to resolved status.
- Zero credential attacks, exploits, or destructive behavior.

## Decision

### 1. Scenario Catalog and Execution Engine (`src/lab/exercises.zig`)
We implemented `runExercise` to orchestrate each scenario's lifecycle, observation capture, finding generation, and structured reporting:

- **Scenario 1 (`dns_failure`):** Simulates unresolvable domain queries targeting RFC 6761 reserved domain `unresolvable-lab.test`. Produces finding `WS-FINDING-DNS-FAILURE` with zero IP answers returned and deterministic classification.
- **Scenario 2 (`tcp_refusal_timeout`):** Allocates a closed loopback port and executes a connection probe. Verifies that the operating system returns immediate TCP RST refusal (WSAECONNREFUSED / ECONNREFUSED) in <5ms, generating `WS-FINDING-TCP-REFUSAL`.
- **Scenario 3 (`tls_cert_issues`):** Writes an isolated self-signed test certificate to `<data_dir>/lab/fixtures/test_cert_mismatch.pem` featuring SAN `CN=mismatch.lab.test` and an expired validity date. Handshake inspection flags hostname mismatch against `127.0.0.1` and certificate expiration, generating `WS-FINDING-TLS-SAN-MISMATCH` without altering host CA stores.
- **Scenario 4 (`unexpected_listener`):** Spawns a temporary loopback listener on an unapproved ephemeral port. Computes a baseline comparison against an approved profile, flagging the new socket as `ADDED` and generating `WS-FINDING-LISTENER-UNAPPROVED`.
- **Scenario 5 (`http_security_header_violation`):** Connects to `http_mock_vulnerable` loopback HTTP service. Evaluates response headers against defensive policy, flagging missing HSTS, CSP, and X-Frame-Options headers with `WS-FINDING-HTTP-MISSING-SECURITY-HEADERS`.
- **Scenario 6 (`remediation_verification`):** Executes a two-phase assessment. Phase 1 detects policy violations on the vulnerable service and captures Baseline 1. Remediation is applied by switching the service to `http_mock_hardened` (serving HSTS, CSP, X-Frame-Options: DENY, and X-Content-Type-Options: nosniff). Phase 2 re-audits the endpoint, confirms 100% policy pass, and verifies via baseline diff that `WS-FINDING-HTTP-MISSING-SECURITY-HEADERS` is marked **RESOLVED**.

### 2. Multi-Format Reporting
Each exercise output is rendered across:
- **Terminal Display:** Human-readable layout emphasizing findings, objectives, evidence, and actionable resolutions.
- **GitHub Markdown (`--format markdown`):** Formatted tables, alert callouts, and structured sections suitable for documentation and reports.
- **Machine-Readable JSON (`--format json`):** Versioned JSON schema with typed fields and explicit synthetic provenance markers.

### 3. Non-Destructive and Defensive Isolation Invariants
All operations remain strictly bounded:
- Ephemeral loopback sockets are closed immediately upon test completion.
- Reset and cleanup operations only touch files in the WireScope lab directory (`validateSandboxPath`).
- Public internet targets remain strictly rejected by `validateLabTarget`.

## Consequences

### Positive
- Operators can practice diagnosing and remediating real-world networking issues entirely on a disconnected laptop.
- The remediation feedback loop provides mathematical proof (via baseline diffs) that defensive hardening resolved the finding.
- Complete documentation integrity: each exercise explains evidence, interpretation, limitations, and resolution without ambiguous claims.

### Neutral / Trade-offs
- Loopback TCP refusal timing (<5ms) depends on host kernel response latency; tests allow bounded timing tolerances.
