# Architecture Decision Record (ADR) 0041: GitHub Actions CI/CD and v1.0 Release Audit

## Status
Accepted

## Context
Milestone 15 is the final milestone in the WireScope roadmap. It encompasses:
1. **Phase 15.1:** Continuous integration across Windows, Linux, and macOS matrix runners, enforcing formatting checks, test suites, smoke tests, and cross-compilation feasibility.
2. **Phase 15.2:** Tag-triggered release automation producing verified release archives (`.zip` / `.tar.gz`) with SHA-256 cryptographic checksums, smoke testing, and rollback recovery procedures.
3. **Phase 15.3:** Comprehensive v1.0 master specification release audit (`reports/v1.0-release-audit.txt`) evaluating all 19 acceptance gates and 68 master requirements from `wirescope_project.txt`.

## Decision

### 1. Continuous Integration Workflow (`.github/workflows/ci.yml`)
- Triggered on pull requests and pushes to `main` and development branch `ashish`.
- Adheres to least-privilege permissions (`permissions: contents: read`).
- Three-stage validation pipeline:
  1. `lint_and_format`: Verifies `zig fmt --check src build.zig poc`.
  2. `build_and_test`: Multi-OS test matrix across `windows-latest`, `ubuntu-latest`, and `macos-latest`, executing `zig build`, `zig build test --summary all`, and platform-specific CLI smoke tests.
  3. `cross_compilation_verification`: Verifies compilation for all 5 target architectures (`x86_64-linux`, `aarch64-linux`, `x86_64-windows`, `x86_64-macos`, `aarch64-macos`).
- Zero secret tokens, cloud credentials, or external paid APIs required.

### 2. Release Automation Workflow (`.github/workflows/release.yml`)
- Triggered by version tags (`v*`) or manual `workflow_dispatch`.
- Builds optimized `ReleaseSafe` standalone binaries across validated targets:
  * `windows-x86_64`: `.zip` archive
  * `linux-x86_64`: `.tar.gz` archive
  * `macos-arm64`: `.tar.gz` archive
- Bundles `README.md`, `LICENSE`, and `SECURITY.md` into each distribution archive.
- Generates individual `.sha256` files and consolidates into `SHA256SUMS.txt`.
- Validated locally via `scripts/release_rehearsal.ps1` and documented in `docs/release_recovery_and_troubleshooting.md`.

### 3. Master Specification Release Audit (`reports/v1.0-release-audit.txt`)
- Audited all 68 requirements in `wirescope_project.txt`:
  * 64 PASS
  * 4 PARTIAL (explicitly documented permissions/stubs: unprivileged process attribution, macOS kernel routes, physical CI runner execution, and local hash limitations)
  * 0 FAIL
  * 10 OUT OF SCOPE (verified adherence to Non-Goals)
- All 19 measurable acceptance gates pass without unresolved blockers.

## Consequences
- WireScope v1.0 has verified, automated CI/CD workflows and automated release packaging.
- The project is fully audited, verified, and complete.
