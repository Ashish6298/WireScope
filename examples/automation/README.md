# WireScope Automation and Scripting Examples

This directory provides runnable example scripts and automation patterns demonstrating safe, non-interactive integration of WireScope into CI/CD pipelines, local security audits, and automation workflows.

## Published Exit Code Contract

WireScope returns deterministic process exit codes matching the Master Specification:

| Exit Code | Constant | Meaning | Script Action |
| :---: | :--- | :--- | :--- |
| **`0`** | `ExitCodes.success` | Operation completed cleanly; all policy rules compliant; report valid | Proceed to next step |
| **`1`** | `ExitCodes.findings_or_violations` | Operation completed, but defensive security findings or policy violations were detected | Fail quality gate / trigger security review |
| **`2`** | `ExitCodes.invalid_input` | Missing arguments, unrecognized command, out-of-scope targets, unauthorized remote target, or unforced file overwrite attempt | Abort pipeline / fix input parameters |
| **`3`** | `ExitCodes.operational_failure` | OS I/O error, network unreachable, storage failure, or assessment execution error | Alert operator / retry transient network issue |
| **`4`** | `ExitCodes.cancelled` | Operation cancelled by user signal (SIGINT/SIGTERM) or deadline timeout | Perform clean teardown |

---

## Safety Invariant: Non-Interactive Mode Does Not Bypass Scope Policy

When running in non-interactive mode (`--non-interactive` or `-y`), WireScope will **never**:
1. Prompt for interactive stdin input or hang unexpectedly.
2. Silently bypass scope boundaries or authorization policies.

If an assessment or discovery target is remote (non-loopback) and has not been explicitly authorized with `--confirm-authorized`, WireScope halts immediately with exit code **`2`** (`invalid_input`) and logs the requirement to `stderr`.

---

## Machine-Readable Output Contract

When `--format json` is requested:
- `stdout` strictly contains only valid, uncorrupted JSON parseable by `jq`, `ConvertFrom-Json`, or standard language parsers.
- Diagnostic logs, operational errors, and progress indicators are routed exclusively to `stderr`.

---

## Example Scripts

- **`check_local_policy.sh` / `.ps1`**: Evaluates local host security policy offline using saved observations or controlled fixtures. Ideal for pull request quality gates.
- **`assess_authorized_target.sh` / `.ps1`**: Executes a complete assessment against an explicitly authorized target, validates the resulting JSON against the report schema, and exports a Markdown audit report.
- **`verify_safety_gate.sh` / `.ps1`**: Demonstrates that unauthorized remote targets fail safely with exit code 2 and will not run without `--confirm-authorized`.
