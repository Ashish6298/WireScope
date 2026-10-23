# Architecture Decision Record (ADR) 0028: Normalize Findings and Remediation Tracking

## Status
Accepted

## Context
Phase 10.3 of Milestone 10 requires establishing normalized, stable identities for defensive security findings, deduplicating recurring findings across assessments while preserving full evidentiary history, supporting explicit finding lifecycles (`new`, `confirmed`, `accepted`, `fixed`, `reopened`, `not_applicable`), and maintaining an audit log of status transitions.

Critical Architectural Invariants:
1. **Stable Finding Identity**: Finding identifiers must be deterministic and stable across independent assessments of comparable targets. Identical rule violations on the same canonical resource must always yield identical finding IDs (`WS-FND-{hex16}`).
2. **Evidence Preservation across Deduplication**: When duplicate findings are ingested from successive scans, they must not be silently discarded or overwritten. All observed evidence entries (`assessment_id`, timestamps, raw proof) must be preserved in an immutable historical ledger.
3. **Explicit Remediation Lifecycle**: Track state transitions through an explicit state machine:
   - `new`: Initial observation in an assessment.
   - `confirmed`: Re-observed in subsequent assessment runs, confirming persistence.
   - `accepted`: Documented risk acceptance by security operator with explicit rationale.
   - `fixed`: Verified resolved via positive verification evidence.
   - `reopened`: Re-observed after previously being marked `fixed` or `accepted`.
   - `not_applicable`: Finding marked inapplicable due to compensatory controls or environmental context.
4. **Fix Verification Invariant**: A missing observation, scanner error, or probe timeout must **never** be treated as proof that an issue has been fixed. Confirming a finding as `fixed` requires affirmative verification evidence (`.verified_fixed`). Absence of evidence or timeouts must be classified strictly as `.inconclusive`, preserving the finding's active status.

## Decision

### 1. Finding Identity Derivation
Implemented in `src/assessment/findings.zig`:
- The identifier is derived via `SHA-256(canonical_rule_id ++ ":" ++ canonical_affected_target)`.
- The first 8 bytes of the digest (16 hexadecimal characters) are formatted with prefix `WS-FND-`:
  ```
  generateFindingId("WS-RULE-TLS-MIN-VERSION", "https://legacy.lan:443") -> "WS-FND-be17963d11e9bb64"
  ```
- Target strings are canonically trimmed and lowercased to avoid trivial identity mismatches (e.g., casing in hostnames).

### 2. Evidence Preservation and History
- **`EvidenceEntry`**: Records each observation event with:
  - `assessment_id`: Unique identifier of the executing assessment run.
  - `observed_at_ms`: Unix timestamp of observation.
  - `evidence_text`: Full captured evidence string.
- When `ingestFinding` encounters an existing finding ID:
  - Appends the new `EvidenceEntry` to `evidence_history`.
  - Increments `occurrence_count`.
  - Updates `last_seen_ms`.
  - Automatically transitions status `new` -> `confirmed` (or `fixed`/`accepted` -> `reopened`).

### 3. Remediation & Verification State Machine
- **`StatusTransition`**: Maintains an append-only audit trail capturing:
  - `from_status` and `to_status`.
  - `transitioned_at_ms`.
  - `reason`: Operator or automated evaluation rationale.
  - `supporting_evidence`: Optional contextual proof.
- **`verifyFix`**:
  - Requires affirmative observation results from a re-test.
  - If the re-test proves the vulnerability is no longer present (`is_remediated == true`), status transitions to `fixed`.
  - If re-test encounters a timeout, connection failure, or inconclusive outcome, returns `FixVerificationOutcome.inconclusive`. Current status is preserved; the issue is not marked fixed.

### 4. Integration and CLI Dispatch
- Re-exported via `wirescope.assessment.FindingsTracker`.
- Exposed via CLI subcommand: `wirescope audit findings [--format terminal|json|markdown]`.

## Consequences

### Positive
- Cross-assessment tracking of security gaps with consistent IDs.
- Elimination of duplicate tickets while retaining complete observation records.
- Complete auditability for compliance and security reviews through status transition history.
- Protection against false closures caused by transient network outages or aborted scans.
