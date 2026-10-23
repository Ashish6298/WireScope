# Architecture Decision Record (ADR) 0040: Documentation, License, and Release Candidate

## Status
Accepted

## Context
Milestone 14 Phase 14.3 requires finalizing comprehensive user-facing and developer documentation, establishing formal licensing, creating a security reporting policy, preparing release notes for Release Candidate 1 (`v0.1.0-rc1`), and explicitly tracking known release blockers for the final milestone.

To deliver an enterprise-grade open-source network diagnostics and defensive auditing tool, WireScope must ensure:
1. All core capabilities, CLI syntax, exit codes, library embedding patterns, data models, and configuration profiles are documented without placeholders.
2. An open, permissive, and standard open-source license is chosen.
3. A formal security disclosure and vulnerability handling process is published.
4. Release candidate `v0.1.0-rc1` is prepared and verified locally without premature CI/CD implementation (reserved for Milestone 15).

## Decision

### 1. Permissive Open-Source Licensing
We adopted the standard **MIT License** (`LICENSE`), granting open usage, modification, distribution, and commercial inclusion while preserving contributor copyright and disclaiming warranty.

### 2. Security Disclosure Policy (`SECURITY.md`)
We published a formal security policy establishing:
- Primary security contact: `security@wirescope.dev` with confidential triage.
- 48-hour response commitment and 90-day coordinated disclosure turnaround.
- Explicit definition of in-scope boundaries (scope escapes, sandbox directory traversal, unbounded memory/resource consumption, credential leaks).
- Safe harbor protections for good-faith defensive security researchers.

### 3. Contribution Guidelines (`CONTRIBUTING.md`)
We established contribution instructions emphasizing:
- Strict defensive philosophy: prohibition of exploits, brute-forcers, denial-of-service weapons, and stealth/evasion mechanisms.
- Memory safety: zero memory leaks enforced via Zig's `GeneralPurposeAllocator`.
- Offline test isolation: prohibition of live public-network dependencies in tests.

### 4. Comprehensive README & Reference Architecture
We restructured `README.md` into a definitive manual covering:
- Architecture & Module Subsystems (`core`, `platform`, `probes`, `recon`, `audit`, `policy`, `assessment`, `storage`, `reporting`, `lab`, `cli`).
- Installation & Build Instructions across Windows, Linux, and macOS.
- Complete CLI Command Reference with all options and subcommands.
- Published Exit Codes Contract (0: Success, 1: Operational Failure, 2: Invalid Input, 3: Target Unreachable, 4: Policy Violation, 5: Permission Limited, 6: Cancelled).
- Library Usage & Embeddability Examples in Zig.
- Assessment Profile & Defensive Rule JSON Formats.
- Local Storage Data Layout and Retention Policies.
- Platform Support Matrix & Residual Risks.
- Troubleshooting Guide.

### 5. Release Candidate 1 (`v0.1.0-rc1`) & Release Blockers
We formalized Release Candidate 1 with `docs/release_notes_v0.1.0_rc1.md` and `CHANGELOG.md`. Known release blockers for final GA release are explicitly identified and assigned to Milestone 15:
1. Multi-platform GitHub Actions CI/CD pipeline.
2. Automated test execution on physical Linux and macOS runners.
3. Automated release artifact packaging and checksum generation.

## Consequences
- WireScope possesses full product documentation and legal foundations.
- Developers, operators, and security researchers have clear contracts for usage, contribution, and vulnerability disclosure.
- The project is fully prepared for Milestone 15 (GitHub Actions CI/CD).
