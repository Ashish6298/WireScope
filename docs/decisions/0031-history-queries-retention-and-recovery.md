# Architecture Decision Record (ADR) 0031: History Queries, Retention, and Recovery

## Status
Accepted

## Context
Phase 11.2 of Milestone 11 requires adding history operations, configurable bounded retention, safe deletion, and recovery mechanisms to WireScope. Specifically:
- WireScope must support listing, inspecting, comparing, exporting, and deleting historical assessments completely offline.
- Retention policies must be configurable and bounded, pruning oldest records beyond a specified limit.
- Assessments interrupted by user aborts (SIGINT), crashes, or process terminations must be preserved as incomplete records rather than dropped or left in corrupt states.
- Deletions and cleanups must strictly operate only on WireScope-owned paths and records; path traversal (`../`, `..\`, absolute paths, drive colons) must be rejected with dedicated sandbox containment errors.
- Locking, concurrent access assumptions, and recovery limits must be documented.

## Decision

### 1. Offline History Operations (`src/storage/history.zig`, `src/cli/root.zig`)
We implemented the `HistoryManager` and CLI command `wirescope history`:
- `listHistory()`: Enumerates all historical assessments from the local storage hierarchy, sorts them in reverse chronological order (newest first), and parses summary fields (`assessment_id`, `profile_id`, `status`, `succeeded`, `failed`, `findings`, `created_at_ms`).
- `inspectHistory(id)`: Loads and validates the full `RecordEnvelope` and underlying JSON payload for a specific assessment run.
- `compareHistory(id1, id2)`: Performs a deterministic comparative analysis between two historical runs, computing task outcome changes, finding count deltas, and execution time differences.
- CLI multi-format export: Supports `-f terminal`, `-f json`, and `-f markdown` for offline reporting and automated pipeline consumption.

### 2. Configurable Bounded Retention (`RetentionPolicy`, `applyRetention`)
- Bounded retention is governed by `RetentionPolicy { max_records: usize }` (default: 50 records).
- When `applyRetention` or `wirescope history prune` is invoked, the history entries are evaluated in chronological order, and the oldest assessment records exceeding `max_records` are pruned safely.
- Accompanying report manifests associated with pruned assessment records are also removed.

### 3. Sandbox Containment & Path Traversal Defense (`validateContainedPath`)
- Implemented `StoragePaths.validateContainedPath(allocator, sub_dir, file_name)`.
- Rejects any candidate record ID or file name containing:
  - Directory traversal sequences (`..`)
  - Forward slashes (`/`)
  - Backward slashes (`\`)
  - Drive or protocol colons (`:`)
  - Empty strings
- Ensures all file deletions and lookups remain strictly jailed within the platform-specific WireScope base directory (`%LOCALAPPDATA%\wirescope`, `~/.local/share/wirescope`, or `~/Library/Application Support/wirescope`).
- Unauthorized escape attempts immediately fail with `StorageError.PathTraversalEscape`.

### 4. Interrupted Assessment Preservation & Orphaned Write Recovery
- **Preserving Interrupted Runs**: `saveInterruptedAssessment()` persists an incomplete record with status `"interrupted"`, capturing partial metrics (tasks succeeded, tasks failed) and an explicit interruption reason (e.g., `"Process terminated by operator signal SIGINT"`).
- **Recovering Interrupted Writes**: In the event of a sudden power loss or process kill during atomic writes, partial `.tmp.` files may linger. `recoverInterruptedWrites()` scans all WireScope directories (`assessments`, `profiles`, `findings`, `baselines`, `manifests`) and safely cleans up orphaned temporary files while leaving committed `.json` records untouched.

### 5. Locking & Concurrency Model
- WireScope operates as a local CLI tool designed for single-user workstation and CI/CD runner workflows.
- Atomic file writes rely on OS-level atomic filesystem rename primitives (`ReplaceFileW` on Windows, `rename()` on POSIX), eliminating the need for complex inter-process locking daemons.
- Ephemeral temporary write files incorporate microsecond timestamps to prevent collisions if separate processes run concurrently.
- Deletions use non-blocking atomic file unlinks.

## Consequences

### Positive
- Fully offline history exploration and comparison without network access or external database dependencies.
- Bounded disk footprint through automatic and manual retention pruning.
- High resilience against crashes and sudden interruptions: partial work is preserved, and temporary debris is safely recoverable.
- Guaranteed protection against directory traversal vulnerabilities during record lookups and deletions.
