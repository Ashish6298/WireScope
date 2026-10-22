# WireScope

> **Local-First Network Diagnostics and Defensive Cybersecurity Toolkit**

WireScope is an evidence-driven, local-first network diagnostics and defensive cybersecurity toolkit written in **Zig**. It combines practical everyday networking utilities (DNS, TCP, TLS, routing, interface inspection) with defensive exposure audits, baseline change tracking, and an isolated local practice lab.

---

## Key Principles

- **Local-First & Zero Hosted Dependency:** No remote control plane, cloud database, telemetry, accounts, or paid APIs. All data stays local.
- **Evidence-Driven Findings:** Raw network observations are preserved and separated from interpretation. Missing headers or open ports are never falsely classified as exploitable vulnerabilities without proof.
- **Strict Scope Guard:** Every assessment requires explicit, bounded target configuration. No unbounded scanning, credential brute-forcing, exploit execution, or stealth/evasion techniques.
- **Dual Interface:** Reusable, embeddable Zig library paired with a lightweight CLI.

---

## Toolchain & Build Prerequisites

- **Primary Language:** Zig
- **Pinned Compiler Version:** `0.13.0` (Official Stable Release)
- **Supported Host & Target OS:** Windows, Linux, macOS

### Building from Source

```bash
# Verify compiler version
zig version
# Must output: 0.13.0

# Build the project (produces library and CLI binary in zig-out/)
zig build

# Run comprehensive test suite
zig build test

# Run the CLI binary
zig build run -- help
zig build run -- version

# Format codebase
zig build fmt
```

---

## Project Status & Milestone Roadmap

Current Development Branch: `ashish`

| Milestone | Title | Status |
| :--- | :--- | :--- |
| **Milestone 0** | **Repository Reconnaissance & Technical Feasibility** | **COMPLETED** |
| ↳ Phase 0.1 | Inspect repository and establish a baseline | **COMPLETED** |
| ↳ Phase 0.2 | Pin Zig and validate uncertain APIs | **COMPLETED** |
| **Milestone 1** | **Project Skeleton and Core Contracts** | **COMPLETED** |
| ↳ Phase 1.1 | Establish module layout and local build commands | **COMPLETED** |
| ↳ Phase 1.2 | Define typed results, errors, and ownership rules | **COMPLETED** |
| **Milestone 2** | **CLI, Configuration, and Profiles** | **COMPLETED** |
| ↳ Phase 2.1 | Implement CLI parsing, help, version, and exit codes | **COMPLETED** |
| ↳ Phase 2.2 | Add versioned configuration and assessment profiles | **COMPLETED** |
| **Milestone 3** | **Local Network Intelligence** | **COMPLETED** |
| ↳ Phase 3.1 | Enumerate network interfaces | **COMPLETED** |
| ↳ Phase 3.2 | Inspect routes and default gateways | **COMPLETED** |
| ↳ Phase 3.3 | Inspect local listening services | **COMPLETED** |
| **Milestone 4** | **Shared Probe Engine and Resource Controls** | **COMPLETED** |
| ↳ Phase 4.1 | Build bounded scheduling, deadlines, and cancellation | **COMPLETED** |
| ↳ Phase 4.2 | Normalize timing, errors, and operation metadata | **COMPLETED** |
| **Milestone 5** | **DNS Diagnostics** | **COMPLETED** |
| ↳ Phase 5.1 | Implement DNS resolution and failure classification | **COMPLETED** |
| ↳ Phase 5.2 | Add DNS troubleshooting and optional resolver comparison | **COMPLETED** |
| **Milestone 6** | **TCP Connectivity and Latency** | **COMPLETED** |
| ↳ Phase 6.1 | Implement TCP connectivity probes | **COMPLETED** |
| ↳ Phase 6.2 | Add repeated measurements and statistical summaries | **COMPLETED** |
| ↳ Phase 6.3 | Provide actionable connectivity troubleshooting | **COMPLETED** |
| **Milestone 7** | **TLS and HTTPS Diagnostics** | **COMPLETED** |
| ↳ Phase 7.1 | Implement certificate-chain and hostname validation | **COMPLETED** |
| ↳ Phase 7.2 | Add HTTPS timing and bounded response handling | **COMPLETED** |
| **Milestone 8** | **Authorized Reconnaissance** | **COMPLETED** |
| ↳ Phase 8.1 | Implement scope validation and plan preview | **COMPLETED** |
| ↳ Phase 8.2 | Build host and service discovery within policy | **COMPLETED** |
| ↳ Phase 8.3 | Add service and version fingerprinting | **COMPLETED** |
| ↳ Phase 8.4 | Add discovery diffs and inventory export | **COMPLETED** |
| **Milestone 9** | **Defensive Security Auditors** | **COMPLETED** |
| ↳ Phase 9.1 | Audit HTTP security configuration | **COMPLETED** |
| ↳ Phase 9.2 | Build a local exposure auditor | **COMPLETED** |
| ↳ Phase 9.3 | Implement the versioned local rules engine | **COMPLETED** |
| **Milestone 10** | **Assessment Orchestration, Policies, and Baselines** | **IN PROGRESS** |
| ↳ Phase 10.1 | Orchestrate multi-module assessments | **COMPLETED** |
| ↳ Phase 10.2 | Implement explicit baselines and deterministic diffs | **COMPLETED** |
| ↳ Phase 10.3 | Normalize findings and remediation tracking | **COMPLETED** |
| ↳ Phase 10.4 | Implement offline policy evaluation | Pending |
| **Milestone 11** | Local Persistence, History, and Integrity | Pending |
| **Milestone 12** | Reporting and Automation Contracts | Pending |
| **Milestone 13** | Isolated Practice Lab | Pending |
| **Milestone 14** | Hardening, Cross-Platform Validation, and Release Prep | Pending |
| **Milestone 15** | GitHub Actions CI/CD (Final Milestone) | Pending |

---

## Architecture Decision Records (ADRs)

- [ADR 0001: Baseline Environment and Feasibility Setup](docs/decisions/0001-baseline-and-feasibility.md)
- [ADR 0002: Pinned Zig Version and API Feasibility Validation](docs/decisions/0002-pinned-zig-and-api-feasibility.md)
- [ADR 0003: Module Layout and Build System Architecture](docs/decisions/0003-module-layout-and-build-system.md)
- [ADR 0004: Typed Results, Error Model, and Memory Ownership](docs/decisions/0004-typed-results-and-ownership-model.md)
- [ADR 0005: CLI Command Parser, Capability Reporting, and Exit Codes](docs/decisions/0005-cli-command-parser-and-exit-codes.md)
- [ADR 0006: Versioned Configuration, Assessment Profiles, and Scope Guard](docs/decisions/0006-configuration-and-assessment-profiles.md)
- [ADR 0007: Network Interface Enumeration and Platform Adapters](docs/decisions/0007-network-interface-enumeration.md)
- [ADR 0008: Routing Table and Default Gateway Inspection](docs/decisions/0008-routing-table-and-gateway-inspection.md)
- [ADR 0009: Local Listening Services Inspection](docs/decisions/0009-listening-services-inspection.md)
- [ADR 0010: Shared Probe Engine Scheduling, Deadlines, and Cancellation](docs/decisions/0010-probe-engine-scheduling-deadlines-and-cancellation.md)
- [ADR 0011: Normalized Timing, Errors, and Operation Metadata](docs/decisions/0011-normalized-timing-errors-and-operation-metadata.md)
- [ADR 0012: DNS Resolution and Failure Classification](docs/decisions/0012-dns-resolution-and-failure-classification.md)
- [ADR 0013: DNS Troubleshooting and Resolver Comparison](docs/decisions/0013-dns-troubleshooting-and-resolver-comparison.md)
- [ADR 0014: TCP Connectivity Probes and Lifecycle](docs/decisions/0014-tcp-connectivity-probes.md)
- [ADR 0015: TCP Repeated Measurements and Statistical Summaries](docs/decisions/0015-tcp-repeated-measurements-and-statistics.md)
- [ADR 0016: Actionable Connectivity Troubleshooting](docs/decisions/0016-actionable-connectivity-troubleshooting.md)
- [ADR 0017: TLS Certificate-Chain and Hostname Validation](docs/decisions/0017-tls-certificate-and-hostname-validation.md)
- [ADR 0018: HTTPS Timing and Bounded Response Handling](docs/decisions/0018-https-timing-and-bounded-response-handling.md)
- [ADR 0019: Scope Validation and Assessment Plan Preview](docs/decisions/0019-scope-validation-and-plan-preview.md)
- [ADR 0020: Bounded Host Discovery and Reachability States](docs/decisions/0020-bounded-host-discovery.md)
- [ADR 0021: Bounded TCP Port Checks and Conservative Service Identification](docs/decisions/0021-tcp-port-checks-and-conservative-service-identification.md)
- [ADR 0022: Asset and Exposure Inventory](docs/decisions/0022-asset-and-exposure-inventory.md)
- [ADR 0023: Defensive HTTP Security Configuration Auditor](docs/decisions/0023-http-security-configuration-auditor.md)
- [ADR 0024: Defensive Local Exposure Auditor](docs/decisions/0024-local-exposure-auditor.md)
- [ADR 0025: Versioned Local Rules Engine](docs/decisions/0025-versioned-local-rules-engine.md)
- [ADR 0026: Multi-Module Assessment Orchestrator](docs/decisions/0026-multi-module-assessment-orchestrator.md)
- [ADR 0027: Explicit Baselines and Deterministic Diffs](docs/decisions/0027-explicit-baselines-and-deterministic-diffs.md)
- [ADR 0028: Normalize Findings and Remediation Tracking](docs/decisions/0028-normalize-findings-and-remediation-tracking.md)

---

## License

All rights reserved / local-first defensive tooling.
