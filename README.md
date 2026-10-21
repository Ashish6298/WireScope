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

# Run unit tests
zig test poc/minimal_test.zig

# Build proof-of-concept tests
zig test poc/timing_poc.zig
zig test poc/dns_poc.zig
zig test poc/tcp_poc.zig
zig test poc/tls_poc.zig
zig test poc/listeners_poc.zig
zig test poc/interfaces_poc.zig -liphlpapi # Windows
```

---

## Project Status & Milestone Roadmap

Current Development Branch: `ashish`

| Milestone | Title | Status |
| :--- | :--- | :--- |
| **Milestone 0** | **Repository Reconnaissance & Technical Feasibility** | **In Progress** |
| ↳ Phase 0.1 | Inspect repository and establish a baseline | **COMPLETED** |
| ↳ Phase 0.2 | Pin Zig and validate uncertain APIs | **COMPLETED** |
| **Milestone 1** | Project Skeleton and Core Contracts | Pending |
| **Milestone 2** | CLI, Configuration, and Profiles | Pending |
| **Milestone 3** | Local Network Intelligence | Pending |
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

---

## License

All rights reserved / local-first defensive tooling.
