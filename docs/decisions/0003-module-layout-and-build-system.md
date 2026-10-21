# Architecture Decision Record (ADR) 0003: Module Layout and Build System Architecture

## Status
Accepted

## Context
Phase 1.1 of Milestone 1 requires establishing a clear, extensible module layout separating the public library from CLI rendering and argument parsing. It also requires local build, test, and format commands using Zig 0.13.0, ensuring strict separation of concerns, deterministic compilation, and zero cloud or server dependencies.

## Decision

### 1. Module Layout Separation
The codebase is structured under `src/` to enforce clean architectural boundaries:
- `src/root.zig`: Public library root module exporting sub-packages (`core`, `platform`, `probes`, `assessment`, `policy`, `storage`, `reporting`, `lab`).
- `src/main.zig`: CLI entrypoint. Consumes `wirescope` library via Zig module imports. Does not contain duplicated diagnostic or networking logic.
- `src/cli/`: CLI command parsing, terminal formatting, and exit code mapping.
- `src/core/`: Common domain models, typed outcome categories, errors, and metadata.
- `src/probes/`: Centralized network probe contracts (DNS, TCP, TLS, HTTP).
- `src/platform/`: OS abstraction layer (Windows, Linux, macOS).
- `src/assessment/`: Scope validation, assessment planning, and execution contracts.
- `src/policy/`: Versioned policy engine and rule evaluation models.
- `src/storage/`: Local persistence, schema versioning, and baseline storage.
- `src/reporting/`: Multi-format report generation (terminal, JSON, Markdown).
- `src/lab/`: Local isolated practice lab scenarios and loopback fixtures.

### 2. Build Pipeline Commands
Configured `build.zig` with native steps:
- `zig build`: Compiles the `wirescope` static library and CLI executable into `zig-out/`.
- `zig build test`: Executes both library unit tests and CLI integration tests.
- `zig build run -- [args]`: Runs the CLI executable with command-line arguments.
- `zig build fmt`: Verifies and formats all Zig sources in `src/`, `build.zig`, and `poc/`.

### 3. Exit Code Conventions
- `0`: Success / no violations
- `1`: Findings or policy violations detected
- `2`: Invalid user input or unrecognized command
- `3`: Operational failure or runtime error
- `4`: Cancelled by user or deadline

## Consequences
- Clean, decoupled boundary between CLI and library. External Zig programs can consume `wirescope` as a standard Zig module without subprocess overhead.
- All testing and building run 100% locally with zero external network or server dependencies.
