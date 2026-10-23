# Architecture Decision Record (ADR) 0032: Report Integrity Manifests

## Status
Accepted

## Context
Phase 11.3 of Milestone 11 requires generating and verifying report integrity manifests. Reporting artifacts (such as JSON reports, Markdown summaries, observations, and findings) are frequently shared across teams, stored in archives, or ingested into automation pipelines. To detect accidental modification, filesystem bit-rot, truncation, or localized tampering, WireScope must generate reproducible manifests referencing all produced artifacts with their cryptographic digests.

Additionally, the system must explicitly document the cryptographic boundaries and limitations of local hashes: a local hash alone does NOT prove author identity, establish non-repudiation, or protect against an adversary with filesystem write access who can modify both report artifacts and the manifest simultaneously.

## Decision

### 1. Versioned Manifest Schema (`src/storage/manifest.zig`)
We implemented the `ReportManifest` structure wrapped in a canonical, versioned schema (`MANIFEST_SCHEMA_VERSION = 1`):
```json
{
  "schema_version": 1,
  "tool_name": "wirescope",
  "tool_version": "0.1.0-dev",
  "manifest_id": "mnf-asm-101",
  "assessment_id": "asm-101",
  "created_at_ms": 1710000000000,
  "configuration": {
    "profile_id": "local-security-audit",
    "profile_name": "Local Security Audit",
    "target_count": 1,
    "ports_count": 4,
    "rate_limit_rps": 10,
    "timeout_ms": 5000
  },
  "manifest_hash": "<64-hex-sha256-digest>",
  "limitations_notice": "<cryptographic-caveat-string>",
  "artifacts": [
    {
      "path": "report.json",
      "artifact_type": "json_report",
      "hash_algo": "sha256",
      "hash": "<64-hex-sha256-digest>",
      "size_bytes": 12480
    }
  ]
}
```

### 2. Hash Algorithm & Canonical Digest Calculation
- **Algorithm**: Standard SHA-256 (`std.crypto.hash.sha2.Sha256`), producing 64-character lowercase hexadecimal digests.
- **Artifact Hashing**: Raw binary content of each artifact file is hashed to produce `artifact.hash` and byte size `artifact.size_bytes`.
- **Manifest Integrity Hash**: A canonical digest (`manifest_hash`) is computed over `wirescope-report-manifest-v1:`, assessment ID, profile ID, and sorted artifact paths and digests. This guarantees that tampering with the manifest metadata or altering artifact mappings is immediately detectable.

### 3. Verification Engine & Failure Classification
Implemented `verifyManifest(allocator, manifest, artifacts_dir)` returning `ManifestVerificationResult`:
- **`intact`**: File exists, byte size matches `expected_size`, and SHA-256 digest matches `expected_hash`.
- **`modified`**: File exists, but SHA-256 digest or size does not match manifest record (tampering or truncation detected).
- **`missing`**: Artifact file referenced in manifest is absent from disk.
- **`unreadable`**: File exists but cannot be accessed due to operating system permissions or I/O failure.
- **`path_traversal_rejected`**: Artifact path attempts to escape sandbox (`..`, `/`, `\`, `:`).

### 4. Path Traversal & Sandbox Isolation
- Manifests must not reference arbitrary system files outside their intended artifact directory.
- `isSafeContainedPath` rejects directory traversals (`..`), drive colons (`:`), and absolute paths.

### 5. Cryptographic Limitations & Security Advisory
Every manifest, CLI output, and generated documentation prominently features the `HASH_LIMITATIONS_NOTICE`:
> **Cryptographic Integrity Notice:** WireScope report manifests use SHA-256 digests to detect accidental modification, transmission corruption, filesystem bit-rot, or localized tampering. However, a local hash alone does NOT prove author identity, establish non-repudiation, or protect against an adversary with filesystem write access who can alter both report artifacts and this manifest simultaneously. Author verification and provenance require external digital signatures (e.g., Ed25519, GPG, or X.509 PKI) and out-of-band trust anchors.

### 6. CLI Command Integration (`wirescope manifest`)
Added CLI commands:
- `wirescope manifest verify <manifest_path>`: Verifies on-disk artifacts against manifest digests. Returns exit code `0` on complete success, or exit code `1` (`ExitCodes.findings_or_violations`) if any artifact is modified, missing, or compromised.
- `wirescope manifest inspect <manifest_path>`: Inspects and displays manifest metadata and referenced artifacts.
- Supports `--format terminal`, `--format json`, and `--format markdown`.

## Consequences

### Positive
- Reliable offline verification of assessment report packages.
- Accurate detection and classification of modified, tampered, or missing artifacts.
- Clear separation between integrity verification (hashes) and identity/provenance (digital signatures).
- Safe from directory traversal exploits during verification.
