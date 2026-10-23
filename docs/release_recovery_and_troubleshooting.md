# WireScope Release Recovery & Troubleshooting Guide

This guide documents operational procedures for diagnosing, recovering from, and rolling back partial or failed release workflows in GitHub Actions or local packaging.

---

## 1. Overview of Release Invariants

WireScope releases strictly adhere to the following invariants:
- **Validated Targets Only:** Artifacts are published only for validated target architectures (`windows-x86_64`, `linux-x86_64`, `macos-arm64`).
- **Cryptographic Checksums:** Every release archive is paired with an individual `.sha256` checksum and consolidated in `SHA256SUMS.txt`.
- **Pre-Release Labeling:** Any release tag containing `-rc` or `-dev` is automatically tagged as a GitHub Pre-release.
- **Zero Secrets / Zero Paid APIs:** Release builds do not require credentials, third-party code signing tokens, or paid cloud services.

---

## 2. Common Release Failure Modes & Recovery

### 2.1 Failure During Matrix Build Step
- **Symptom:** One OS matrix job (e.g. macOS or Linux) fails compilation or smoke tests.
- **Root Cause:** Target platform-specific syntax error or toolchain failure.
- **Recovery Procedure:**
  1. Inspect the specific matrix job log in GitHub Actions.
  2. Fix the underlying compiler issue on branch `ashish`.
  3. Delete the remote tag:
     ```bash
     git push --delete origin v0.1.0-rc1
     git tag -d v0.1.0-rc1
     ```
  4. Retag the corrected commit and push:
     ```bash
     git tag v0.1.0-rc1
     git push origin v0.1.0-rc1
     ```

### 2.2 Failure During GitHub Release Publishing
- **Symptom:** Binaries build successfully, but the `publish_github_release` job fails (e.g. network timeout or GitHub API rate limit).
- **Recovery Procedure:**
  1. Trigger the workflow manually via GitHub Actions **Workflow Dispatch** (`release.yml`), specifying the tag name (e.g. `v0.1.0-rc1`).
  2. Alternatively, download the built artifacts from the GitHub Actions run summary and publish manually via the GitHub Web UI or GitHub CLI:
     ```bash
     gh release create v0.1.0-rc1 release_assets/* --notes-file docs/release_notes_v0.1.0_rc1.md --prerelease
     ```

### 2.3 Partial Release or Corrupted Asset
- **Symptom:** A release exists on GitHub, but an asset file is incomplete or its checksum does not match `SHA256SUMS.txt`.
- **Recovery Procedure:**
  1. Edit the release on GitHub and delete the corrupt asset.
  2. Recompute the correct SHA-256 hash locally:
     - Windows (PowerShell):
       ```powershell
       Get-FileHash -Path wirescope-v0.1.0-rc1-windows-x86_64.zip -Algorithm SHA256
       ```
     - Linux / macOS (Bash):
       ```bash
       sha256sum wirescope-v0.1.0-rc1-linux-x86_64.tar.gz
       ```
  3. Re-upload the verified file and updated `SHA256SUMS.txt`.

---

## 3. Local Release Rehearsal & Verification

Before tagging or publishing any release, verify artifact packaging and checksum generation locally using `scripts/release_rehearsal.ps1` (Windows) or `scripts/release_rehearsal.sh` (Linux/macOS):

```powershell
# Run local release rehearsal on Windows
powershell.exe -File scripts/release_rehearsal.ps1 -Version "0.1.0-rc1"
```

The rehearsal script performs:
1. Compilation of the release binary with `-Doptimize=ReleaseSafe`.
2. Binary smoke tests (`--help`, `version`, `capabilities`).
3. Packaging into `.zip` / `.tar.gz` archive with `README.md`, `LICENSE`, and `SECURITY.md`.
4. Generation and verification of SHA-256 checksums.
5. Verification that extracted binaries execute identically to build output.
