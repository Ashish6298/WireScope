# WireScope v1.0.0 Release Notes

**Official General Availability (GA) Release**  
**Date:** November 22, 2026  
**Compiler:** Zig 0.13.0  
**Repository:** [https://github.com/Ashish6298/WireScope](https://github.com/Ashish6298/WireScope)

---

## 1. Executive Summary

WireScope is an evidence-driven, local-first network diagnostics and defensive cybersecurity assessment engine. Version `1.0.0` represents the first official production release, delivering a hardened, self-contained CLI and embeddable Zig library for systems administrators, network engineers, and defensive security teams.

All capabilities are non-destructive, strictly bounded in scope, require zero external cloud dependencies or paid APIs, and operate 100% locally with zero telemetry.

---

## 2. Included Capabilities & Feature Highlights

### 2.1 Core Network Diagnostics (`wirescope diagnose`)
- **DNS Resolution & Troubleshooting:** Direct query execution, RFC 1035 wire encoding, error classification (NXDOMAIN, SERVFAIL, REFUSED, TIMEOUT), and multi-resolver comparison detecting split-horizon disparities.
- **TCP Connectivity & Latency Statistics:** Microsecond-precision handshake timing, reliable differentiation between refusal (TCP RST) and timeout (silent drop), repeated measurements, RFC 3550 jitter calculation, sample standard deviation, and nearest-rank percentiles (p50, p75, p90, p95, p99).
- **TLS Certificate & Hostname Validation:** Native certificate-chain inspection, Subject Alternative Name (SAN) validation, expiration window calculation, self-signed detection, and handshake timing breakdown.
- **Host Network Introspection:** Local network interface enumeration, routing table and default gateway inspection, and listening socket inventory.

### 2.2 Defensive Security Auditing (`wirescope audit`)
- **HTTP Security Auditor:** Automated verification of HSTS (RFC 6797), Content Security Policy (CSP), X-Frame-Options, X-Content-Type-Options, cookie security flags (Secure, HttpOnly, SameSite), and server banner information disclosure.
- **Exposure Auditor:** Compares active TCP listeners against approved policy, flagging unapproved wildcard bindings (`0.0.0.0` or `::`).
- **Versioned Local Rules Engine:** Executes declarative defensive rules (`WS-AUDIT-HTTP-*`, `WS-AUDIT-EXPOSURE-*`) with detailed severity rationales, evidence strings, false-positive caveats, and actionable remediations.

### 2.3 Assessment Orchestration & Baselines (`wirescope baseline`, `wirescope policy`)
- **Multi-Module Orchestration:** Coordinated execution of DNS, TCP, TLS, and HTTP checks governed by unified assessment profiles.
- **State Baselines & Diffs:** Captures point-in-time network snapshots and produces deterministic diffs tracking new, changed, or closed services.
- **Remediation Tracking:** Tracks finding states across consecutive assessments (`OPEN`, `RESOLVED`, `RECURRING`).
- **Offline Policy Evaluation:** Evaluates network state against security policies completely offline.

### 2.4 Local Storage, History, and Integrity (`wirescope history`, `wirescope manifest`)
- **Versioned Atomic Storage:** Profile, baseline, assessment, and manifest persistence utilizing atomic write-to-temp-then-rename semantics (`atomicWriteFile`) preventing corruption on power loss.
- **History Retention & Recovery:** Query, inspect, compare, and purge assessment history with configurable bounded retention.
- **SHA-256 Integrity Manifests:** Cryptographic manifests detecting modified or missing report artifacts.

### 2.5 Multi-Format Reporting & Automation (`wirescope report`)
- **Versioned JSON Reports:** Deterministic JSON schema (`schema_version: 1`) with stable sorting and secret redaction.
- **Markdown & Terminal Exporters:** Human-readable terminal output and GitHub Flavored Markdown reports with callout alerts.
- **Scripting & CI Contracts:** Non-interactive flag (`-y, --non-interactive`), predictable exit codes (0–6), and zero unexpected prompts.

### 2.6 Isolated Practice Lab (`wirescope lab`)
- **Reproducible Local Exercises:** Six core practice scenarios operating 100% locally on loopback (`127.0.0.1`):
  1. `dns_failure`: DNS no-answer and resolver timeout simulation.
  2. `tcp_refusal_timeout`: TCP port refusal vs timeout differentiation.
  3. `tls_cert_issues`: Expired and hostname-mismatched certificate diagnostics using isolated test-only fixtures.
  4. `unexpected_listener`: Detection of unapproved local listening ports via baseline comparison.
  5. `http_security_header_violation`: Auditing missing security headers on a loopback service.
  6. `remediation_verification`: Verifying finding resolution after configuration fixes across consecutive runs.

---

## 3. Security Hardening & Invariants

WireScope enforces strict architectural and security invariants:
- **Zero Telemetry Guarantee:** Strictly local execution. WireScope never phones home, collects analytics, or sends tracking pings.
- **Scope Guard:** DNS rebinding attacks, unapproved HTTP redirects, and broad CIDR expansion (< /24) are blocked before connections occur.
- **Resource Limits:** HTTP responses bounded to 1 MB; JSON inputs bounded to 16 MB; thread pool bounded to 32 concurrent workers; maximum operations capped at 5,000 tasks.
- **Sandbox Confinement:** All file operations are validated against directory traversal (`../`, `..\`, absolute paths).
- **Redaction:** Authorization headers, passwords, and API keys are masked by default as `[REDACTED]`.

---

## 4. Verification Evidence

- **Automated Test Suite:** 294 / 294 unit, integration, and property tests passing.
- **Continuous Integration:** Fully automated multi-platform matrix builds passing on Windows (`x86_64`), Linux (`x86_64`), and macOS (`ARM64`).
- **Production Staging Test:** All modules verified with live OS sockets and networks in production test environment.
