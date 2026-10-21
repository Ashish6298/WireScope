# Architecture Decision Record (ADR) 0001: Baseline Environment and Feasibility Setup

## Status
Accepted

## Context
Phase 0.1 of Milestone 0 requires establishing a repository baseline, inspecting pre-existing files and build configurations, recording environmental capabilities and blockers, and initializing project tracking infrastructure without altering or overwriting existing user assets.

The repository at `D:\wsl` initially contained only two specification documents:
- `wirescope_project.txt`: Master project specification.
- `wirescope_phase.txt`: Detailed phased implementation roadmap.

## Decision
1. **Repository Tracking:**
   - Initialized a Git repository (`git init`) on branch `main` to ensure clean change tracking, deterministic diffs, and adherence to milestone discipline.
   - Preserved `wirescope_project.txt` and `wirescope_phase.txt` completely untouched.

2. **Directory Conventions:**
   - Dedicated `report/` for phase milestone delivery text reports as specified by user instructions.
   - Established `docs/decisions/` for Architecture Decision Records (ADRs).

3. **Toolchain & Compiler Dependency Management:**
   - An environment audit confirmed that `git` (v2.49.0.windows.1), `curl.exe` (v8.21.0), and `tar.exe` are present.
   - `zig` is not currently found on the system `PATH`.
   - Technical blocker identified: Prior to implementing Milestone 0 Phase 0.2 (proof of concepts) and Milestone 1 (build skeleton), a stable Zig compiler release (e.g., Zig 0.13.0 or 0.12.0) must be downloaded, pinned, and placed in the environment.

## Consequences
- Clean starting baseline established with zero unverified assumptions.
- Pre-existing files are fully preserved.
- Direct path forward defined for Phase 0.2 (pinning Zig and creating feasibility proof-of-concept programs).
