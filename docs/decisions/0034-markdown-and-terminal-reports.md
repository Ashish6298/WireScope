# Architecture Decision Record (ADR) 0034: Markdown and Terminal Reports

## Status
Accepted

## Context
Phase 12.2 of Milestone 12 requires human-readable Markdown and formatted Terminal report generation from the structured assessment model (`AssessmentReportData`). While automation pipelines consume JSON reports (ADR 0033), human operators, security auditors, and engineers require clean, structured, and informative visual summaries for review, documentation, pull requests, and terminal workflows.

To prevent misinterpretation, leakage, or unverified claims, the Markdown and Terminal reports must adhere to several strict architectural principles:
1. **Model Fidelity:** Render reports directly from the structured `AssessmentReportData` rather than scraping console logs or ad-hoc strings.
2. **Clear Observation vs. Finding Distinction:** Neutral empirical telemetry (responsive ports, DNS records, TLS certificates, HTTP status codes) must never be conflated with security findings or vulnerabilities.
3. **Evidence-Bounded Claims:** Reports must never make claims that exceed collected empirical evidence (e.g., stating "No findings detected within tested scope", and never asserting "Endpoint is secure" or "System is immune to attack").
4. **Execution State Prominence:** Partial, failed, or cancelled runs must be prominently flagged with clear callouts/badges, displaying interruption reasons and reiterating that incomplete evidence does not imply the absence of vulnerabilities.
5. **Configurable Redaction:** Sensitive credentials, authorization tokens, passwords, and optional IP/domain addresses must be redactable on demand, with a prominent warning notice that redaction reduces report reproducibility.
6. **Safe File Output:** Support explicit output paths (`--output` / `-o`) with atomic writes and safe overwrite protection (preventing accidental overwrites unless `--force` is specified).
7. **Secret & Response Body Omission:** Sensitive values and HTTP response bodies must remain omitted by default.

## Decision

### 1. Unified Structured Rendering Pipeline
Both Markdown (`src/reporting/markdown.zig`) and Terminal (`src/reporting/terminal.zig`) renderers consume the canonical `AssessmentReportData` struct. A universal JSON parser (`src/reporting/parser.zig`) allows CLI commands (`wirescope report markdown <report.json>`, `wirescope report terminal <report.json>`, `wirescope report export <report.json>`) to reconstruct `AssessmentReportData` in an arena allocator with clean lifecycle management.

### 2. Observation vs. Finding Separation
The rendered outputs enforce a strict visual and semantic separation:
- **Section 1: Empirical Network Observations (Neutral Data):**
  Preceded by an explicit disclaimer stating that observations record raw network telemetry and do not imply vulnerabilities. Organizes DNS, TCP, TLS, HTTP, and active listener telemetry into structured tables or formatted bullet lists.
- **Section 2: Defensive Security Findings (Policy Violations):**
  Preceded by an explanation that findings identify configuration gaps or rule violations evaluated against deterministic rule sets.
  - If zero findings exist, the report emits:
    `No security findings detected within the tested scope. (Note: The absence of findings does not guarantee that an endpoint is secure or vulnerability-free. It confirms only that no configured defensive rules were triggered by the collected evidence within tested parameters.)`
  - When findings exist, each finding documents: Title, Rule ID, Version, Severity, Confidence, Target, Severity Rationale, Observed Evidence, and Actionable Remediation Guidance.

### 3. Execution State Visual Indicators
Reports explicitly communicate execution completeness:
- **Completed:** Marked `[COMPLETE]` with confirmation that all planned tasks executed within scope.
- **Partial (Incomplete):** Marked with a `[WARNING]` callout and banner explaining that tasks were interrupted, preserving completed observations while warning that incomplete evidence does not imply absence of risk.
- **Cancelled:** Marked with a `[CAUTION]` banner indicating operator cancellation (e.g., SIGINT/SIGTERM).
- **Failed:** Marked with a `[CAUTION]` banner detailing operational failures and preserving unaffected telemetry.

### 4. Redaction Engine & Reproducibility Notice (`src/reporting/redact.zig`)
The redaction engine inspects credential tokens (`password`, `secret`, `token`, `bearer`, `api_key`, `authorization`), custom patterns, and optional IPv4 addresses. Whenever redaction is enabled (`--redact`), the report embeds a mandatory disclaimer:
> `WARNING: Redaction was applied to this report. Redacting sensitive data may alter evidence strings, token values, or endpoint references, which can reduce report reproducibility during audit verification.`

### 5. Safe Atomic File Writing (`src/reporting/writer.zig`)
When `--output <path>` is passed:
1. `std.fs.cwd().access(path, .{})` checks if the target file already exists.
2. If it exists and `--force` is not passed, execution halts safely with `error.FileAlreadyExists` and exit code 2 (`invalid_input`), preventing accidental data loss.
3. If writing proceeds, content is written to a unique temporary file (`<path>.tmp.<timestamp>`), synced to physical media via `file.sync()`, and atomically renamed over the destination path.

## Consequences

### Positive
- Consistent presentation across CLI terminal output, JSON machine automation, and GitHub Flavored Markdown reports.
- Elimination of false claims: audit consumers receive honest, evidence-bounded assessments.
- Reliable protection of existing files through atomic temp-and-rename safe writing.
- Safe redaction for public sharing with transparent reproducibility warnings.

### Neutral / Trade-offs
- Redaction introduces slight string transformation overhead and reduces byte-for-byte reproducibility across independent audit teams.
- Safe overwrite requires operators to explicitly pass `--force` when updating report files.
