# Architecture Decision Record (ADR) 0035: CLI Automation and Scripting Contracts

## Status
Accepted

## Context
Phase 12.3 of Milestone 12 requires hardening and documenting the WireScope CLI interface for scripts, local automation, and continuous integration pipelines. Script-driven environments impose strict operational requirements:
1. **Predictable Non-Interactive Execution:** Commands must execute deterministically without blocking on unexpected stdin prompts.
2. **Deterministic Exit Codes:** The CLI must return stable exit codes accurately reflecting operational success, security violations, user configuration errors, infrastructure failures, or cancellations.
3. **Pristine Machine-Readable Streams:** When JSON output is requested, `stdout` must remain uncorrupted by diagnostic logs, debug banners, or progress text. All human messages and errors must be directed to `stderr`.
4. **Scope and Authorization Safety Invariant:** Non-interactive mode must never bypass security boundaries or authorization confirmations. Remote network operations must require explicit `--confirm-authorized` flags or configured profile authorization.
5. **Completely Local Operation:** Automation pipelines must function offline without external dependencies, remote databases, or paid APIs.

## Decision

### 1. Published Exit Code Mapping (`src/cli/exit_codes.zig`)
WireScope strictly enforces a five-state process exit contract:
- **`0` (`ExitCodes.success`):** Command succeeded without policy violations or findings. All evaluated rules passed, reports validated, and baselines created cleanly.
- **`1` (`ExitCodes.findings_or_violations`):** Assessment or policy evaluation succeeded, but one or more defensive security findings (medium, high, or critical) or policy violations were detected. Automation scripts use this code to fail CI pull-request quality gates.
- **`2` (`ExitCodes.invalid_input`):** Malformed inputs, unknown options, broad CIDR violations, unauthorized remote targets without `--confirm-authorized`, or attempts to overwrite existing files without `--force`.
- **`3` (`ExitCodes.operational_failure`):** Unrecoverable runtime errors such as missing files, storage failures, or operational assessment crashes.
- **`4` (`ExitCodes.cancelled`):** The operation was cancelled early due to an operator signal or deadline expiration.

### 2. Stream Separation Guarantee
- `stdout`: Reserved exclusively for requested machine-readable output (`--format json`, `--format markdown`, or primary terminal displays).
- `stderr`: Dedicated to error messages, authorization warnings, schema validation diagnostic failures, and operational trace logs.

### 3. Non-Interactive Mode (`--non-interactive`, `-y`)
The `--non-interactive` flag instructs WireScope to operate headlessly. Since the architecture uses no blocking stdin reads, commands run to immediate completion. However, non-interactive mode explicitly forbids silent elevation or assumed authorization: attempting to assess or scan remote targets without `--confirm-authorized` immediately halts with exit code `2`.

### 4. Bounded Local Execution
Automation contracts are supported entirely through local storage, synthetic fixtures, and local loopback diagnostics without contacting external servers or requiring API tokens.

## Consequences

### Positive
- Predictable and robust integration into Bash, PowerShell, Python, and CI runner environments.
- Protection against silent scope escapes or unintended remote scanning in automated scripts.
- Machine-readable JSON output can be directly piped into tools like `jq` or `ConvertFrom-Json` without manual sanitization.

### Neutral / Trade-offs
- CI/CD pipelines assessing remote endpoints must explicitly provide `--confirm-authorized` in their job step definitions.
