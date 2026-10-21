# Architecture Decision Record (ADR) 0005: CLI Command Parser, Capability Reporting, and Exit Codes

## Status
Accepted

## Context
Phase 2.1 of Milestone 2 requires implementing a consistent command parser and subcommand dispatch mechanism. The CLI must:
1. Support `--help`, `--version`, capability reporting, and common timeout/format options.
2. Provide stable, machine-readable exit codes.
3. Reject invalid inputs prior to any network or disk activity.
4. Separate machine-readable JSON output on `stdout` from human-readable diagnostic messages on `stderr`.
5. Maintain thorough automated unit and smoke tests.

## Decision

### 1. Command Parser Architecture
Structured under `src/cli/`:
- `exit_codes.zig`: Stable integer constants (`0: success`, `1: findings_or_violations`, `2: invalid_input`, `3: operational_failure`, `4: cancelled`).
- `args.zig`: Custom zero-dependency argument tokenizer and validator. Parses flags (`--format`, `--timeout`, `--output`, `--non-interactive`, `--dry-run`, `--help`, `--version`) and positional subcommand tokens.
- `help.zig`: Structured root help and per-subcommand manual pages (`diagnose`, `audit`, `discover`, `baseline`, `policy`, `lab`).
- `capabilities.zig`: Platform capability inspection matrix supporting both human-readable terminal output and pure JSON.
- `root.zig`: Top-level CLI dispatcher managing `stdout` and `stderr` streams and mapping errors to exit codes.

### 2. Stream Hygiene & No-Noise Invariant
When `--format json` is passed:
- `stdout` strictly receives parseable JSON payloads.
- `stderr` is reserved exclusively for errors, warnings, and diagnostic progress messages.

### 3. Early Input Validation
Input validation takes place immediately upon argument parsing before any socket opening or network probe initialization:
- Unknown flags return `error.UnknownOption` (Exit Code 2).
- Non-numeric or out-of-range timeouts return `error.InvalidTimeout` (Exit Code 2).
- Unsupported formats return `error.InvalidFormat` (Exit Code 2).
- Missing option parameters return `error.MissingOptionValue` (Exit Code 2).

## Consequences
- CLI argument parsing is fully automated and tested with zero external dependencies.
- Scripts can reliably invoke `wirescope ... --format json` and pipe stdout directly to `jq` without stream corruption.
- Stable exit code contracts enable automated CI/CD and defensive policy evaluation pipelines.
