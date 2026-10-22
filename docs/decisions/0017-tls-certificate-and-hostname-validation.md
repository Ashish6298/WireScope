# Architecture Decision Record (ADR) 0017: TLS Certificate-Chain and Hostname Validation

## Status
Accepted

## Context
Phase 7.1 of Milestone 7 requires implementing TLS diagnostics with certificate-chain and hostname validation:
1. Implement TLS using a documented trust-store strategy supported by the pinned Zig toolchain (0.13.0) and target platforms (Windows, Linux, macOS).
2. Verify certificate chains and hostnames by default according to RFC 5280 and RFC 6125.
3. Represent expiry, hostname mismatch, untrusted chains, handshake failure, and inability to verify with granular error classifications.
4. Strictly disallow implicit verification disabling; bypassing verification requires explicit user-supplied CLI flags (`--insecure` or `--insecure-skip-verify`).
5. Support custom CA root bundles via `--ca-bundle <path>` for private PKI, enterprise inspection, and laboratory testing.
6. Provide test-only certificates for hermetic integration tests without live network dependencies or real credentials.
7. Separate observed diagnostic facts from unverified hypotheses in actionable troubleshooting output.

## Decision

### 1. Documented Trust-Store Strategy
We leverage Zig 0.13.0 standard library's `std.crypto.Certificate.Bundle`:
- **Windows**: Dynamically queries the OS Root Certificate Store via Windows CryptoAPI (`crypt32.dll` -> `CertOpenSystemStoreW(null, "ROOT")` and `CertEnumCertificatesInStore`). Root certificates are loaded into the in-memory bundle.
- **Linux**: Scans standard distribution root certificate files in priority order (`/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`, `/etc/ssl/ca-bundle.pem`, `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`, `/etc/ssl/cert.pem`) and directory locations (`/etc/ssl/certs`, `/etc/pki/tls/certs`).
- **macOS**: Queries Apple Security Framework keychains via `rescanMac()`.
- **Custom CA Bundle**: When `--ca-bundle <path>` is passed, `Bundle.addCertsFromFilePath(allocator, cwd, path)` imports PEM/DER certificates from the specified file.
- **Failure Resilience**: If platform trust stores are missing or empty in restricted containers, `rescan` handles `error.FileNotFound` gracefully and falls back to explicit CA configuration.

### 2. Strict Verification Invariant (No Implicit Bypass)
In `TlsConfig`:
- `verify_certificates: bool = true` (Default)
- `insecure_skip_verify: bool = false` (Default)
Verification cannot be disabled implicitly or by omission. When `--insecure` or `--insecure-skip-verify` is explicitly provided:
1. `verification_bypassed = true` is explicitly recorded in `TlsProbeResult` and serialized into `OperationEnvelope`.
2. Terminal output issues prominent warnings: `WARNING: Certificate and hostname verification was bypassed by explicit option!`.
3. Troubleshooting context notes that remote identity is unverified and susceptible to on-path interception.

### 3. Granular Failure Classification (`TlsFailureCategory`)
We introduced `TlsFailureCategory` mapping directly to `OutcomeCategory` and `ErrorCode`:

| Failure Category | Outcome Category | Error Code | Description |
| :--- | :--- | :--- | :--- |
| **`success`** | `.success` | `.none` | Handshake established, hostname matched, valid trust chain |
| **`certificate_expired`** | `.operational_failure` | `.tls_certificate_expired` | System clock is beyond certificate `notAfter` date |
| **`certificate_not_yet_valid`**| `.operational_failure` | `.tls_certificate_expired` | System clock precedes certificate `notBefore` date |
| **`hostname_mismatch`** | `.operational_failure` | `.tls_hostname_mismatch` | Target hostname not in Subject Alternative Names (SAN) or CN |
| **`untrusted_chain`** | `.operational_failure` | `.tls_untrusted_root` | Issuer CA not found in trust bundle, or signature is invalid |
| **`handshake_failure`** | `.operational_failure` | `.tls_handshake_failed` | Protocol/cipher mismatch, illegal parameter, or alert |
| **`inability_to_verify`** | `.unsupported_capability` | `.unsupported_platform_api` | Unsupported cryptographic curve or signature algorithm |
| **`tcp_connection_failed`** | `.operational_failure` | `.connection_refused` | Underlying TCP connection failed before TLS handshake |
| **`cancelled`** | `.cancelled` | `.operation_cancelled` | Aborted by user interrupt or assessment deadline |
| **`malformed_input`** | `.invalid_input` | `.parse_error` | Malformed target, invalid hostname, or out-of-range port |
| **`operational_failure`** | `.operational_failure` | `.internal_error` | OS socket failure or resource exhaustion |

### 4. Hermetic Test Seams and Synthetic Fixtures (`tls_fixtures.zig`)
To avoid public network dependencies and prevent reliance on live credentials in CI:
- **`TEST_ROOT_CA_PEM`**: Self-signed root CA certificate (`CN=WireScope Test Root CA`).
- **`TEST_VALID_SERVER_PEM`**: Issued by Test Root CA with `CN=localhost`, SAN `DNS:localhost, IP:127.0.0.1`.
- **`TEST_MISMATCH_SERVER_PEM`**: Issued by Test Root CA with `CN=other.test`, SAN `DNS:other.test`.
- **`TEST_UNTRUSTED_SERVER_PEM`**: Issued by an untrusted rogue CA (`CN=WireScope Rogue Root CA`).
- **`TEST_BADSIG_SERVER_PEM`**: Issued by Test Root CA but with corrupted signature bytes.
- **`MockTlsConnector`**: In-memory connector testing both preset failure modes and real cryptographic evaluation of supplied PEM certificates using `std.crypto.Certificate.parse`, `parsed.verifyHostName`, and `bundle.verify`.

### 5. Separate Timing Stages
Timing stages are cleanly isolated using monotonic nanoTimestamp:
- `connect_time_ns`: Time taken for the TCP 3-way handshake.
- `tls_handshake_ns`: Time taken for the TLS ClientHello / ServerHello / Certificate exchange.
- `total_elapsed_ns`: Total monotonic time from invocation to completion.
- Timings are never conflated into an ambiguous single number.

### 6. Actionable Diagnostic Troubleshooting (`tls_troubleshooting.zig`)
`generateTlsTroubleshooting()` translates `TlsProbeResult` into structured diagnostic guidance separating:
- **`summary`**: Objective, concise evaluation status.
- **`observed_facts`**: Verifiable empirical evidence (e.g. "Server presented certificate whose Subject/SAN does not match target host").
- **`hypotheses`**: Clearly labeled possible explanations (e.g. "Hypothesis 1: Target host is an IP address or alias not covered in certificate SAN").
- **`recommended_actions`**: Prescriptive remediation steps (e.g. "Verify target FQDN matches Subject Alternative Names").

## Consequences

### Positive
- Strict adherence to defensive cybersecurity standards: no silent downgrade or implicit verification bypass.
- Cross-platform root trust store integration (Windows CryptoAPI, Linux system bundles, macOS keychain, custom PEM files).
- Zero public network dependency for CI tests through hermetic test fixtures.
- Clear separation of TCP connect timing from TLS cryptographic handshake timing.
- Machine-readable JSON output conforms strictly to `OperationEnvelope` schema.

### Limitations
- The pinned Zig 0.13.0 standard library TLS implementation supports TLS 1.3 clients natively. Legacy TLS 1.0/1.1/1.2 servers that do not support TLS 1.3 will report `handshake_failure`.
- OCSP stapling and CRL revocation checks are not currently evaluated by the native Zig 0.13.0 standard library X.509 bundle.
