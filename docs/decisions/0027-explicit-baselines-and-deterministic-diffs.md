# Architecture Decision Record (ADR) 0027: Explicit Baselines and Deterministic Diffs

## Status
Accepted

## Context
Phase 10.2 of Milestone 10 requires implementing named baseline snapshots captured from assessment runs, deterministic diff comparisons classifying new, removed, changed, unchanged, or inconclusive items, volatile field normalization, and explicit baseline mutation controls.

Key architectural and product invariants:
1. **Explicit Mutation Only**: Baselines are never overwritten automatically. Creating, updating, or deleting a baseline snapshot requires an explicit command. Updating creates a new version (`version + 1`) rather than destructively erasing prior snapshots.
2. **Version Retention**: Prior baseline versions remain available according to a documented retention policy (default: 5 versions retained per named baseline).
3. **Volatile Field Normalization**: Ephemeral fields (such as volatile process PIDs, millisecond network latency RTTs, ephemeral execution order, and randomized session tokens) are normalized out prior to comparison to prevent false positive diff noise.
4. **Strict Diff Determinism**: Diff entries are sorted lexicographically by canonical item key. Running repeated diffs over identical inputs produces byte-for-byte identical output.
5. **Incomplete Evidence Invariant**: Lack of observation or network timeouts must never be treated as proof of service removal. If an assessment was interrupted or encountered errors, unobserved baseline items are classified strictly as `inconclusive`, not `removed`.

## Decision

### 1. Module Layout and Architecture
Implemented in `src/assessment/baseline.zig` and re-exported via `src/assessment/root.zig`:
- **`NormalizedBaselineItem`**: Canonical representation of an observed resource:
  - `key`: Unique deterministic identifier (e.g. `listener:tcp:127.0.0.1:8080`, `dns:example.com`, `tcp:127.0.0.1:443`).
  - `item_type`: `BaselineItemType` (`listener`, `dns`, `tcp_service`, `tls_config`, `http_config`).
  - `summary`: Human-readable summary.
  - `details`: Normalized stable configuration string.
- **`BaselineSnapshot`**: Named snapshot capturing:
  - `name`: Baseline chain name.
  - `version`: Monotonically increasing version integer (`v1`, `v2`, ...).
  - `created_at_ms`: Epoch creation time.
  - `assessment_id`: Source assessment identifier.
  - `profile_id`: Source profile identifier.
  - `items`: Slice of `NormalizedBaselineItem`.
  - `snapshot_hash`: Cryptographic SHA-256 digest over normalized items and metadata.
- **`DiffClassification`**:
  - `new_item`: Observed in new assessment, absent in baseline.
  - `removed_item`: Present in baseline, confirmed absent in complete observation.
  - `changed_item`: Present in both, but properties or configurations differ.
  - `unchanged_item`: Present in both with identical normalized state.
  - `inconclusive`: Present in baseline, but new assessment was incomplete or timed out.
- **`BaselineDiffReport`**: Composite diff result with item counts, sorted entries, and multi-format renderers (`.toTerminal()`, `.toJson()`, `.toMarkdown()`).
- **`BaselineManager`**:
  - `create(name, assessment)`: Creates initial version (`v1`). Rejects duplicate name.
  - `update(name, assessment)`: Explicitly increments version (`vN+1`), pruning versions exceeding retention limit.
  - `inspect(name, ?version)`: Retrieves specific or latest version.
  - `compare(name, ?version, assessment)`: Computes deterministic diff against chosen baseline version.
  - `delete(name, ?version)`: Deletes specific version or entire named baseline.
  - `list(writer)`: Lists all managed baselines, latest versions, and SHA-256 digests.

### 2. Normalization Engine
- **Listeners**: Formats key as `listener:{proto}:{address}:{port}`. Omits volatile host PID numbers and execution timestamps.
- **DNS**: Answers are sorted lexicographically before hashing to eliminate resolver answer ordering jitter.
- **TCP**: Normalizes RTT latency into stable boolean reachability state (`open=true/false`).
- **TLS**: Buckets remaining certificate days into stable validity state (`proto={version};valid_chain={bool};hostname_matches={bool}`).
- **HTTP**: Normalizes status code and security headers (`status={code};hsts={val};csp={val};nosniff={val}`).

## Consequences

### Positive
- Robust configuration drift detection across systems without noise from volatile network metrics.
- Comprehensive version history enabling regression tracking against historical baselines.
- Zero false removals caused by transient timeouts or partial scanner failures.
- Deterministic, machine-readable JSON and Markdown diff outputs for automated CI/CD and audit reporting.

### Verification
- 181 library unit tests passing cleanly with zero memory leaks.
- Dedicated unit tests in `src/assessment/baseline.zig` testing:
  - Full CRUD lifecycle (create, list, inspect, update, delete) and version retention limits.
  - Changed listener, DNS, and TLS state detection.
  - Incomplete assessment handling verifying that incomplete evidence does NOT imply removal.
- CLI integration tests in `src/cli/root.zig` exercising `wirescope baseline save`, `wirescope baseline list`, and `wirescope baseline diff`.
