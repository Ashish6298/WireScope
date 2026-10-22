# Architecture Decision Record (ADR) 0030: Versioned Local Storage

## Status
Accepted

## Context
Phase 11.1 of Milestone 11 requires implementing versioned local storage. Profiles, assessments, observations, findings, baselines, and report manifests must be persisted using local files without any external or remote database service. The storage subsystem must implement atomic safe writes, schema validation, backward-compatible migration paths, actionable corruption handling, and platform-specific storage directories with restrictive permissions.

Key Architectural Invariants:
1. **Local-Only Zero-Remote Architecture**: All storage is strictly filesystem-based, residing on the local host. Zero cloud services, daemon processes, or external database engines are required.
2. **Process Restart Survival**: Persisted records must survive process termination, reboot, and memory clearance, being accurately reconstructible upon application restart.
3. **Atomic Safe Writes**: Writes use the write-to-temp-then-atomic-rename pattern (`file.sync()` before atomic rename). Power failure, crash, or write interruption prior to rename leaves the target file completely untouched and never exposes partially written or corrupted records.
4. **Actionable Corruption & Truncation Errors**: Truncated, malformed, or tampered files return clear, actionable errors (`TruncatedRecord`, `CorruptRecord`, `ChecksumMismatch`, `UnsupportedFutureVersion`) rather than crashing or panicking.
5. **Schema Versioning & Automatic Migration**: All records are wrapped in a versioned envelope (`CURRENT_SCHEMA_VERSION = 2`). Legacy schema v1 records are automatically detected, upgraded with computed SHA-256 integrity checksums, and migrated to schema v2.
6. **OS-Specific Directory Hierarchy**:
   - Windows: `%LOCALAPPDATA%\wirescope` or `%USERPROFILE%\.wirescope`
   - Linux: `$XDG_DATA_HOME/wirescope` or `~/.local/share/wirescope`
   - macOS: `~/Library/Application Support/wirescope`

## Decision

### 1. Unified Record Envelope & Schema Validation (`src/storage/schema.zig`)
Every stored record is encapsulated in a canonical envelope:
```json
{
  "schema_version": 2,
  "record_type": "profile|assessment|observations|findings|baseline|manifest",
  "record_id": "...",
  "created_at_ms": 1710000000000,
  "checksum": "sha256-hex-digest",
  "payload": { ... }
}
```
Validation rules:
- Files under 10 bytes or lacking closing brace return `StorageError.TruncatedRecord`.
- Malformed JSON returns `StorageError.CorruptRecord`.
- Envelopes with `schema_version == 1` are migrated to v2 by generating payload checksums.
- Envelopes with future `schema_version > 2` return `StorageError.UnsupportedFutureVersion`.
- SHA-256 checksums are verified on read; mismatched digests return `StorageError.ChecksumMismatch`.

### 2. Atomic Safe Writes (`src/storage/atomic.zig`)
Implemented `atomicWriteFile`:
- Creates `{file_name}.tmp.{timestamp}` in the same directory.
- Writes the serialized envelope.
- Calls `file.sync()` to force physical persistence.
- Atomically renames temporary file to destination path.
- Incomplete temporary files are cleaned up on error.

### 3. Local Storage Manager (`src/storage/store.zig`)
Implemented `LocalStorage`:
- `saveProfileJson` / `loadProfileJson`
- `saveAssessmentJson` / `loadAssessmentJson`
- `saveBaselineJson` / `loadBaselineJson`
- `saveFindingsJson` / `loadFindingsJson`
- `saveManifestJson` / `loadManifestJson`
- `listRecords`: safely enumerates files excluding ephemeral `.tmp.` markers.

## Consequences

### Positive
- Reliable, offline-first persistence without third-party dependencies.
- Robust protection against torn writes and corrupted state.
- Automated migration paths for continuous schema evolution.
