# Architecture Decision Record (ADR) 0033: Versioned JSON Reports

## Status
Accepted

## Context
Phase 12.1 of Milestone 12 requires implementing versioned JSON reports for assessments. Downstream consumers, automation pipelines, and CI/CD quality gates rely on structured machine-readable reports rather than parsing terminal output. To support deterministic testing, auditing, and integration, the JSON reports must:
- Comply with an explicit, versioned schema covering assessment metadata, scope, checks, observations, assets, findings, policy results, limitations, and completion state.
- Order all collections deterministically.
- Support volatile field normalization for bit-for-bit golden fixture comparisons.
- Accurately represent partial and cancelled assessment states without discarding prior successful observations.
- Prevent leakage of secrets, passwords, tokens, or raw response bodies.
- Ensure stdout contains only valid JSON when JSON output format is requested.

## Decision

### 1. Versioned Schema Specification (`src/reporting/schema.zig`)
The report schema is versioned (`REPORT_SCHEMA_VERSION = 1`) and defined by schema identifier `https://wirescope.dev/schemas/assessment-report-v1.json`. The canonical root structure comprises:
```json
{
  "schema_version": 1,
  "report_type": "wirescope_assessment_report",
  "tool": {
    "name": "wirescope",
    "version": "0.1.0-dev"
  },
  "metadata": {
    "assessment_id": "asm-101",
    "profile_id": "local-security-audit",
    "profile_name": "Local Security Audit",
    "started_at_ms": 1710000000000,
    "completed_at_ms": 1710000005000,
    "duration_ms": 5000,
    "status": "completed|partial|failed|cancelled",
    "manifest_hash": "<64-hex-sha256>"
  },
  "scope": {
    "targets": ["127.0.0.1"],
    "ports": [80, 443],
    "exclusions": [],
    "rate_limit_rps": 10,
    "timeout_ms": 5000,
    "allow_out_of_scope_redirects": false
  },
  "completion_state": {
    "tasks_planned": 10,
    "tasks_executed": 10,
    "tasks_succeeded": 9,
    "tasks_failed": 1,
    "is_complete": true,
    "interruption_reason": null
  },
  "checks": [ ... ],
  "observations": {
    "dns": [ ... ],
    "tcp": [ ... ],
    "tls": [ ... ],
    "http": [ ... ],
    "listeners": [ ... ]
  },
  "assets": [ ... ],
  "findings": [ ... ],
  "policy_results": [ ... ],
  "limitations": [ ... ],
  "task_failures": [ ... ]
}
```

### 2. Deterministic Sorting of Unordered Collections
To guarantee deterministic JSON serialization across operating systems, runs, and memory layouts:
- **Targets**: Sorted lexicographically.
- **Ports**: Sorted numerically ascending.
- **Findings**: Sorted primarily by severity rank (`critical` -> `high` -> `medium` -> `low` -> `info`), secondarily by `rule_id`, and tertiarily by `target`.
- **Checks**: Sorted by `sequence_id` ascending.
- **Policy Results**: Sorted by `rule_id`, then `target`.
- **Observations**:
  * DNS sorted by target hostname.
  * TCP sorted by target host, then port.
  * TLS sorted by target host, then port.
  * HTTP sorted by target URL.
  * Listeners sorted by address, then port, then transport.
- **Limitations**: Sorted by category, then component.

### 3. Volatile Field Normalization (`normalizeJsonReport`)
To allow automated regression and golden testing against pinned fixtures, `normalizeJsonReport()` parses and normalizes non-deterministic fields:
- `started_at_ms` -> `1710000000000`
- `completed_at_ms` -> `1710000005000`
- `duration_ms` -> `5000`
- `manifest_hash` -> `"0000000000000000000000000000000000000000000000000000000000000000"`
- Latency and check durations -> `10`
- Ephemeral listener PIDs -> `1234`

### 4. Representation of Partial and Cancelled Assessments
- **Partial Assessments**: Marked with `"status": "partial"` and `"is_complete": false`. Prior successful observations are preserved in the `observations` block, while failed tasks are recorded in `task_failures` with explicit error descriptions.
- **Cancelled Assessments**: Marked with `"status": "cancelled"` and `"is_complete": false`, recording an explicit cancellation reason (e.g. `"Assessment cancelled by operator SIGINT"`).

### 5. Confidentiality & Sanitization Invariant
WireScope JSON reports strictly omit:
- HTTP response bodies (`response_body`, `body_content`, `raw_payload`).
- Passwords, bearer tokens, or client credentials.
- Schema validator (`validateReportJson`) scans for and actively rejects any report containing forbidden secret or body fields with `SchemaValidationError.SecretOrResponseBodyExposed`.

### 6. Clean CLI Stdout Guarantee
When `--format json` is requested, `stdout` is reserved exclusively for valid, parseable JSON. All operational progress, diagnostics, errors, or cancellation warnings are routed strictly to `stderr`.

## Consequences

### Positive
- Robust, versioned contract for machine ingestion, automation pipelines, and CI/CD tools.
- Deterministic golden test fixtures across platforms.
- Complete audit trail of partial failures and cancellations without loss of collected evidence.
- Verified protection against credential and response payload leakage.
