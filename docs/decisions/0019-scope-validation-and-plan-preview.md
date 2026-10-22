# Architecture Decision Record (ADR) 0019: Scope Validation and Assessment Plan Preview

## Status
Accepted

## Context
Phase 8.1 of Milestone 8 requires implementing strict scope validation, target normalization, operational safety caps, and a deterministic assessment plan preview before any active network reconnaissance probes are dispatched:
1. Normalize hostnames (RFC 1123), IP addresses (dotted-decimal), and CIDRs (/24 to /32 allowed; < /24 prohibited).
2. Calculate the exact planned host/port/check operation count before execution. Reject malformed, oversized, or out-of-policy scope.
3. Display the plan preview and require explicit configuration/confirmation for broader or remote assessments.
4. Guarantee that DNS resolution cannot silently expand the approved scope or bypass exclusion lists.
5. Record an explicit authorization acknowledgement for remote assessments (`--confirm-authorized`), while documenting prominently that WireScope cannot verify legal permission.
6. Provide clear, actionable, safety-related error messages explaining any rejected scope.

## Decision

### 1. Target Normalization and Syntax Validation (`src/recon/scope.zig`)
All inputs are validated and normalized prior to any probe scheduling:
- **Hostnames**: Validated against RFC 1123 / RFC 1035 (lowercase normalized, 1-253 chars, labels 1-63 chars, hyphen restrictions enforced, trailing FQDN dot stripped). Malformed hostnames return `error.MalformedHostname`.
- **IPv4 Addresses**: Parsed with strict octet boundary checks (0-255). Canonical dotted-decimal normalization without leading zeros. Malformed addresses return `error.MalformedIpAddress`.
- **CIDR Expansion**: Bounded prefix range `/24` to `/32` supported. CIDRs with prefix `< 24` (such as `/16` or `/8`) are rejected with `error.ExcessiveCidrRange` to prevent accidental unbounded or Internet-wide scanning.
- **Port Specifications**: Parsed via `parsePortSpec()`, supporting comma-delimited lists and numeric ranges (e.g. `80,443,8080-8085`). Deduplicated and sorted ascendingly. Values must be between 1 and 65535.
- **Exclusions**: Parsed and normalized into IP addresses, subnets, and hostnames. Targets matching any exclusion entry are filtered out during normalization. If all targets are excluded, `error.AllTargetsExcluded` is returned.

### 2. Operational Safety Caps (`ScopeCaps`)
Reconnaissance is constrained by default safety caps:
- **`max_hosts`**: 256 hosts maximum (configurable via `--max-hosts`).
- **`max_ports`**: 100 ports maximum (configurable via `--max-ports`).
- **`max_operations`**: 5000 operations maximum (configurable via `--max-operations`).
Exceeding any cap aborts plan generation with `error.ExcessiveHostCount`, `error.ExcessivePortCount`, or `error.ExcessiveOperationCount`.

### 3. Remote Authorization Acknowledgement and Legal Disclaimer
- Targets classified as loopback (`127.0.0.1`, `localhost`, `::1`) are permitted without explicit acknowledgement.
- Remote non-loopback targets require explicit operator authorization acknowledgement (`--confirm-authorized` or `authorization_acknowledged: true`). If missing, execution is halted with `error.MissingAuthorizationAcknowledgement`.
- WireScope includes a mandatory legal disclaimer in all preview and output interfaces:
  > *"WireScope cannot verify legal permission or ownership; operators bear sole legal responsibility for ensuring explicit written authorization before assessing remote targets."*

### 4. 1:1 Equivalence: Preview vs. Actual Execution Plan (`src/recon/plan.zig`)
- `AssessmentPlan.create()` deterministically calculates the exact ordered array of `PlannedTask` items.
- The total operations count (`plan.total_operations`) is identical to `plan.tasks.len`.
- Preview modes (`--preview`, `--dry-run`) serialize this exact task list without issuing network packets.
- Output formats include structured human-readable terminal format (`toTerminal`) and machine-readable JSON format (`toJson`).

### 5. DNS Scope Expansion Invariant
DNS resolution cannot be used to covertly expand scope or evade exclusions:
- `verifyDnsScopeCompliance(plan, resolved_ips)` evaluates all IPs returned from DNS resolution.
- If a resolved IP matches any entry in `plan.scope.exclusions`, `error.ResolvedTargetExcluded` is returned.
- If a target is loopback-confined and resolves to an external IP, `error.ScopeExpansionPrevented` is returned.

### 6. Safety Error Explanations (`explainScopeError()`)
Rejection reasons are mapped to descriptive, human-readable explanations that inform the operator why the scope was rejected and how to adjust configurations safely.

## Consequences

### Positive
- Prevents accidental denial of service, network flooding, or out-of-bounds scanning.
- Eliminates discrepancy between displayed preview and actual probe execution.
- Ensures operators are legally reminded of authorization responsibilities.
- Cross-platform, fully tested under Zig 0.13.0 with zero external dependencies.

### Negative
- Broad assessments require explicit overrides of `--max-hosts` and `--max-operations`.
- Remote target testing in scripts must pass `--confirm-authorized`.
