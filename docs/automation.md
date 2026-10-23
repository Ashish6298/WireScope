# WireScope Automation, Scripting, and Non-Interactive Usage Guide

This document defines the operational contract, exit codes, output conventions, and safety boundaries for integrating WireScope into continuous integration (CI/CD) pipelines, local automated quality gates, scheduled audits, and headless scripts.

---

## 1. Non-Interactive Invocation

WireScope supports fully automated, non-interactive execution via the global flag:
```bash
wirescope <command> [subcommand] [arguments] --non-interactive [options]
# Alternatively using the shorthand:
wirescope <command> [subcommand] [arguments] -y [options]
```

### Automation Guarantees:
- **Zero Blocking Prompts:** WireScope never blocks on `stdin` or prompts for user interaction in non-interactive mode.
- **Safety Limits Strictly Enforced:** Non-interactive mode **never** bypasses scope authorization or safety constraints. If a remote target scope requires authorization acknowledgement, the command immediately exits with error code `2` (`invalid_input`) rather than assuming authorization or prompting interactively.
- **Offline / Local Execution:** Scripted checks require no external internet access, remote telemetry servers, or paid API keys.

---

## 2. Published Exit Code Contract

WireScope returns deterministic process exit codes matching `src/cli/exit_codes.zig`:

| Exit Code | Name | Semantic Meaning | Recommended Automation Action |
| :---: | :--- | :--- | :--- |
| **`0`** | `success` | Operation completed cleanly; 0 policy violations or critical findings detected; schema valid. | Continue pipeline execution to subsequent job steps. |
| **`1`** | `findings_or_violations` | Execution succeeded, but defensive security findings (medium, high, or critical) or policy violations were detected. | Fail CI pull-request quality gate; notify security team or block merge. |
| **`2`** | `invalid_input` | Malformed target, unknown option, out-of-scope CIDR, unauthorized remote target, schema violation, or unforced file overwrite attempt. | Abort pipeline immediately; log configuration or argument defect. |
| **`3`** | `operational_failure` | Operating system error, storage failure, missing input file, or internal task execution failure. | Alert infrastructure team; retry if transient network error. |
| **`4`** | `cancelled` | Execution was interrupted by deadline expiration or operator signal (SIGINT/SIGTERM). | Perform graceful task cleanup; do not treat as a policy defect. |

---

## 3. Machine-Readable JSON Output Contract

When `--format json` is requested:
1. **Clean `stdout` Stream:** Only pure, valid JSON is written to standard output (`stdout`). Stray progress text, informational messages, and diagnostic banners are strictly forbidden from stdout.
2. **Diagnostic Separation:** All errors, authorization warnings, and diagnostic notes are routed to standard error (`stderr`).
3. **Parseability:** Output can be directly piped into `jq`, PowerShell (`ConvertFrom-Json`), or Python without text filtering or regex stripping.

### Shell Pipeline Example:
```bash
# Evaluate local security policy and filter failing rules
wirescope policy check --format json --non-interactive \
  | jq '.rule_evaluations[] | select(.outcome == "fail")'
```

### PowerShell Example:
```powershell
$report = wirescope policy check --format json --non-interactive | ConvertFrom-Json
if ($LASTEXITCODE -eq 1) {
    Write-Warning "Security policy failed with $($report.failed_count) violations!"
}
```

---

## 4. Assessment Profiles and Safety Guard

WireScope executes assessments through versioned profiles:
- **`loopback-diagnostics`:** Safe local loopback tests (DNS localhost resolution, local TCP sockets, and local active listener audit). Always authorized without confirmation.
- **`local-security-audit`:** Host exposure audit, listener inventory, and policy compliance verification.
- **Remote Targets:** Non-loopback targets (e.g. `192.168.1.5` or `api.corp.internal`) require explicit authorization acknowledgement via `--confirm-authorized`.

### Safety Gate Invariant:
Attempting to run a remote assessment or discovery without `--confirm-authorized` in non-interactive mode will fail immediately with code `2`:
```bash
# This FAILS safely with exit code 2 (invalid_input)
wirescope discover 192.168.1.0/24 --non-interactive

# This SUCCEEDS non-interactively because authorization is explicitly confirmed
wirescope discover 192.168.1.0/24 --confirm-authorized --preview --format json --non-interactive
```

---

## 5. Report Artifact Management

When generating or exporting reports in automated scripts:
- **Safe Atomic Overwrite:** Passing `-o <path>` / `--output <path>` prevents accidental overwriting unless `--force` is provided. If `<path>` exists without `--force`, WireScope exits with code `2`.
- **Atomic Writes:** WireScope writes to `<path>.tmp.<timestamp>`, flushes to disk via `fsync`, and atomically replaces the destination. Interrupted scripts will never leave partially written or corrupted report files.
- **Redaction Disclaimer:** Using `--redact` sanitizes credential patterns, bearer tokens, and IP addresses, inserting a reproducibility disclaimer.

---

## 6. Runnable Script Templates

Pre-built script templates are available in the repository under `examples/automation/`:
- `examples/automation/check_local_policy.sh` / `.ps1`
- `examples/automation/assess_authorized_target.sh` / `.ps1`
- `examples/automation/verify_safety_gate.sh` / `.ps1`
