# Contributing to WireScope

Thank you for your interest in contributing to **WireScope**! This document provides guidelines for contributing code, documentation, and test fixtures.

---

## 1. Code of Conduct & Defensive Philosophy

WireScope is strictly a **defensive network diagnostics and cybersecurity assessment tool**:
- **Prohibited:** Pull requests introducing offensive exploitation tools, vulnerability weaponization, denial-of-service stress tools, credential brute-forcing, stealth/evasion techniques, or payload delivery will be rejected immediately.
- **Mandatory:** All assessment capabilities must be bounded, non-destructive, evidence-driven, and require explicit operator authorization for non-loopback targets.
- **Privacy:** No cloud telemetry, phone-home mechanisms, or remote analytics may be added. WireScope is 100% local-first.

---

## 2. Development Prerequisites

- **Zig Compiler:** Version `0.13.0` (Official Stable Release).
  * Windows: Download from `https://ziglang.org/download/0.13.0/`
  * Linux/macOS: Install via package manager or direct tarball download.
- **Git:** Git 2.30+

---

## 3. Local Build & Test Commands

WireScope uses standard `zig build` workflows:

```bash
# 1. Build library and executable
zig build

# 2. Run all unit, integration, and benchmark tests (290 tests)
zig build test --summary all

# 3. Format all source code according to standard Zig formatting
zig build fmt

# 4. Run CLI binary locally
./zig-out/bin/wirescope --help
```

---

## 4. Branching & Git Conventions

- **Active Development Branches:** Work in progress is maintained on branch `ashish`. Production baseline is on `main`.
- **Commit Messages:** Follow Conventional Commits:
  * `feat(subsystem): description`
  * `fix(subsystem): description`
  * `docs(subsystem): description`
  * `test(subsystem): description`
  * `refactor(subsystem): description`
- Do not commit generated build caches (`.zig-cache/`, `zig-out/`).

---

## 5. Coding & Architectural Invariants

When adding or modifying code, ensure compliance with WireScope's core invariants:

1. **Memory Safety & Leaks:**
   - Every allocation must have an unambiguous ownership model and paired cleanup (`errdefer` / `defer`).
   - Every test must pass cleanly under Zig's `std.testing.allocator` (which uses `GeneralPurposeAllocator` with leak detection).
2. **Explicit Bounded Inputs:**
   - Never parse network inputs with unbounded buffers. Cap HTTP response bodies at 1 MB, JSON records at 16 MB, hostnames at 253 bytes, and port ranges at configured caps.
3. **Scope Guard Integrity:**
   - Any new network check or probe must integrate with `AssessmentPlan` scope validation. DNS-derived targets must call `verifyDnsScopeCompliance`.
4. **Offline Test Isolation:**
   - Tests must **never** connect to public internet IPs or live external hostnames. Use `127.0.0.1`, RFC 6761 reserved names (`.test`), mock connectors, or synthetic lab fixtures.
5. **No Speculative Security Claims:**
   - Distinguish network observations from conclusions. Do not mark an endpoint "vulnerable" without verifiable proof. Caveat findings with false-positive explanations and operational limitations.

---

## 6. Pull Request Checklist

Before submitting a Pull Request, verify:
- [ ] `zig build` compiles cleanly with zero warnings or errors.
- [ ] `zig build test --summary all` passes 100% (290+ tests, 0 failures, 0 memory leaks).
- [ ] `zig build fmt` was executed.
- [ ] Documentation updated in `README.md` or `docs/`.
- [ ] New functionality accompanied by unit tests and an Architecture Decision Record (ADR) if architectural changes were introduced.
- [ ] No public internet dependencies in any test.
