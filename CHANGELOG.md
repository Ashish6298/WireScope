# Changelog

All notable changes to **WireScope** are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0-rc1] - 2026-10-23

### Milestone 14: Hardening, Cross-Platform Validation, and Release Preparation
- **Security Hardening & Fuzzing (Phase 14.1):**
  * Added PRNG-driven property fuzzing engines for hostnames, IPv4, ports, sandbox paths, and JSON envelopes (`src/core/hardening.zig`).
  * Codified scope-escape regression tests: DNS rebinding prevention, target exclusion precedence, redirect scope guards, and broad CIDR rejection.
  * Formalized and published authoritative Residual Risks catalog (`docs/security_hardening_and_residual_risks.md`).
- **Platform Validation & Benchmarking (Phase 14.2):**
  * Validated cross-compilation across 5 targets: `x86_64-windows`, `x86_64-linux`, `aarch64-linux`, `x86_64-macos`, `aarch64-macos`.
  * Established authoritative Platform & Feature Support Matrix (`docs/platform_support_and_matrix.md`).
  * Implemented reproducible performance benchmark suites (`src/core/benchmarks.zig`) measuring statistical processing, token redaction, JSON validation, and SHA-256 hashing.
- **Documentation & Release Candidate (Phase 14.3):**
  * Completed comprehensive documentation suite (`README.md`, `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`).
  * Prepared release candidate `v0.1.0-rc1` with recorded release blockers for Milestone 15.

### Milestone 13: Isolated Practice Lab
- **Lab Lifecycle & Isolation (Phase 13.1):**
  * Implemented `LabManager` with loopback service daemons, sandboxed state tracking (`active_state.json`), and atomic cleanup.
- **Defensive Diagnostic Exercises (Phase 13.2):**
  * Implemented all 6 core diagnostic and defensive exercises: DNS no-answer/timeout (`dns_failure`), TCP refusal/timeout (`tcp_refusal_timeout`), TLS certificate expiry/SAN mismatch (`tls_cert_issues`), unexpected local listener vs baseline (`unexpected_listener`), HTTP security header violation (`http_security_header_violation`), and remediation verification (`remediation_verification`).

### Milestone 12: Reporting and Automation Contracts
- **Versioned JSON Reports (Phase 12.1):**
  * Built deterministic JSON report serializer with stable sorting, redaction, and schema validation (`schema_version: 1`).
- **Markdown & Terminal Reports (Phase 12.2):**
  * Built human-readable terminal rendering and GitHub Flavored Markdown exporters with alert callouts and structured tables.
- **Safe Automation & Non-Interactive Mode (Phase 12.3):**
  * Published machine-readable automation contract, stable exit codes (0–6), and automation examples for Bash and PowerShell (`examples/automation/`).

### Milestone 11: Local Persistence, History, and Integrity
- **Versioned Local Storage (Phase 11.1):**
  * Added versioned storage manager with atomic file writes (`atomicWriteFile`) preventing corruption on power loss.
- **History Queries, Retention, and Recovery (Phase 11.2):**
  * Implemented history list, inspect, compare, export, and configurable bounded retention policies.
- **Report Integrity Manifests (Phase 11.3):**
  * Implemented SHA-256 report integrity manifests with modification and missing artifact detection.

### Milestone 10: Assessment Orchestration, Policies, and Baselines
- **Multi-Module Orchestration (Phase 10.1):**
  * Integrated DNS, TCP, TLS, and HTTP assessment modules into unified execution pipelines.
- **Explicit Baselines & Deterministic Diffs (Phase 10.2):**
  * Added state baseline captures and deterministic diffing detecting added, modified, and removed network services.
- **Findings Normalization (Phase 10.3):**
  * Structured finding model with status tracking (`OPEN`, `RESOLVED`, `RECURRING`) and false-positive caveats.
- **Offline Policy Evaluation (Phase 10.4):**
  * Configurable defensive exposure and header policies evaluated offline without network access.

### Milestone 9: Defensive Security Auditors
- **HTTP Security Auditor (Phase 9.1):**
  * Audits HSTS, CSP, X-Frame-Options, X-Content-Type-Options, cookie security attributes, and server version disclosure.
- **Local Exposure Auditor (Phase 9.2):**
  * Evaluates local TCP listening sockets against approved policy and detects unapproved wildcard binds (`0.0.0.0`).
- **Versioned Local Rules Engine (Phase 9.3):**
  * Engine executing declarative security rules with severity rationales and actionable remediations.

### Milestone 8: Authorized Reconnaissance
- Scope validation and assessment plan preview (`Phase 8.1`).
- Bounded host reachability discovery within explicit authorization (`Phase 8.2`).
- Conservative service identification via non-destructive protocol banners (`Phase 8.3`).
- Asset inventory tracking and diffing (`Phase 8.4`).

### Milestone 7: TLS and HTTPS Diagnostics
- TLS certificate-chain parsing, expiration calculations, and SAN validation (`Phase 7.1`).
- HTTPS timing stages and bounded response handling (`Phase 7.2`).

### Milestone 6: TCP Connectivity and Latency
- TCP connection probes differentiating refusal from timeout (`Phase 6.1`).
- Repeated measurements, RFC 3550 jitter, sample standard deviation, and percentiles (`Phase 6.2`).
- Actionable connectivity troubleshooting recommendations (`Phase 6.3`).

### Milestone 5: DNS Diagnostics
- DNS resolution, RFC 1035 wire encoding, and failure classification (`Phase 5.1`).
- Multi-resolver comparison and split-horizon detection (`Phase 5.2`).

### Milestone 4: Shared Probe Engine & Resource Controls
- Bounded thread pool scheduling with hard concurrency limits (`max_concurrency = 32`) and cooperative cancellation tokens (`Phase 4.1`).
- Normalized nanosecond timing stages and structured error categories (`Phase 4.2`).

### Milestone 3: Local Network Intelligence
- Network interface enumeration (`Phase 3.1`).
- Routing table and default gateway inspection (`Phase 3.2`).
- Local listening services inspection (`Phase 3.3`).

### Milestone 2: CLI, Configuration, and Profiles
- Command-line parsing, help system, version reporting, and exit code contracts (`Phase 2.1`).
- Versioned configuration profiles and scope guard definitions (`Phase 2.2`).

### Milestone 1: Project Skeleton & Core Contracts
- Architecture layout, static library, and executable build configuration in Zig (`Phase 1.1`).
- Typed results, error classification, and memory ownership rules (`Phase 1.2`).

### Milestone 0: Repository Reconnaissance & Technical Feasibility
- Repository baseline established (`Phase 0.1`).
- Zig compiler pinned to version `0.13.0` (`Phase 0.2`).
