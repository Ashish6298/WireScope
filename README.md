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
| **Milestone 3** | **Local Network Intelligence** | **In Progress** |
| ↳ Phase 3.1 | Enumerate network interfaces | **COMPLETED** |
| ↳ Phase 3.2 | Inspect routes and default gateways | **COMPLETED** |
| ↳ Phase 3.3 | Inspect local listening services | Pending |
| **Milestone 4** | Shared Probe Engine and Resource Controls | Pending |
| **Milestone 5** | DNS Diagnostics | Pending |
| **Milestone 6** | TCP Connectivity and Latency | Pending |
| **Milestone 7** | TLS and HTTPS Diagnostics | Pending |
| **Milestone 8** | Authorized Reconnaissance | Pending |
| **Milestone 9** | Defensive Security Auditors | Pending |
| **Milestone 10** | Assessment Orchestration, Policies, and Baselines | Pending |
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

---

## License

All rights reserved / local-first defensive tooling.
