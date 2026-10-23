# WireScope

> **Local-First Network Diagnostics and Defensive Cybersecurity Toolkit**

WireScope is an evidence-driven, local-first network diagnostics and defensive cybersecurity assessment platform written in **Zig 0.13.0**. It combines practical everyday networking utilities (DNS resolution, TCP connectivity, TLS validation, network routing, and interface inspection) with structured defensive security auditing, baseline drift tracking, report integrity verification, and an isolated loopback practice lab.

WireScope operates as both an embeddable Zig library (`wirescope`) and a high-performance, self-contained command-line interface executable (`wirescope.exe` / `wirescope`).

---

## Table of Contents

1. [Key Principles & Defensive Philosophy](#key-principles--defensive-philosophy)
2. [Architecture & Subsystems](#architecture--subsystems)
3. [Installation & Build Prerequisites](#installation--build-prerequisites)
4. [CLI Command Reference](#cli-command-reference)
5. [CLI Exit Codes Contract](#cli-exit-codes-contract)
6. [Library Usage & Embedding Examples](#library-usage--embedding-examples)
7. [Assessment Profiles & Safety Caps Format](#assessment-profiles--safety-caps-format)
8. [Defensive Rules & Finding Format](#defensive-rules--finding-format)
9. [Local Storage Layout & Retention](#local-storage-layout--retention)
10. [Safety & Authorization Model](#safety--authorization-model)
11. [Platform Support Matrix](#platform-support-matrix)
12. [Residual Risks & Limitations](#residual-risks--limitations)
13. [Troubleshooting Guide](#troubleshooting-guide)
14. [Project Roadmap & Status](#project-roadmap--status)
15. [Architecture Decision Records (ADRs)](#architecture-decision-records-adrs)
16. [Security, License, and Contributing](#security-license-and-contributing)

---

## Key Principles & Defensive Philosophy

- **Local-First & Zero Hosted Dependency:** No remote control plane, cloud telemetry, external databases, user accounts, or paid SaaS APIs. All data stays strictly on the local machine.
- **Evidence-Driven Findings:** Raw network observations are preserved and separated from interpretation. Missing security headers or open ports are never falsely classified as exploitable vulnerabilities without verifiable evidence.
- **Strict Scope Guard:** Every assessment requires explicit, bounded target configuration. WireScope strictly prohibits unbounded network sweeps, credential brute-forcing, exploit execution, or stealth/evasion techniques.
- **Memory Safety & Resource Caps:** Zero memory leaks verified by Zig's `GeneralPurposeAllocator`, bounded HTTP response bodies (1 MB), thread pool limits (32 workers), and pre-dispatch operation caps (5,000 tasks).
- **Dual Interface:** Reusable, embeddable Zig library paired with a lightweight, standalone CLI binary.

---

## Architecture & Subsystems

WireScope is organized into modular subsystems under `src/`:

```
src/
├── root.zig           # Main library entry point re-exporting all public APIs
├── main.zig           # Standalone CLI binary entry point and argument dispatcher
├── core/              # Shared data contracts, timing, stats, errors, and outcomes
│   ├── outcome.zig    # OutcomeCategory (success, refusal, timeout, failure, etc.)
│   ├── errors.zig     # Structured error classification and JSON serialization
│   ├── stats.zig      # Latency statistics, jitter (RFC 3550), stddev, percentiles
│   ├── hardening.zig  # Property fuzzing engines and scope-escape regression tests
│   └── benchmarks.zig # Reproducible local performance benchmark suites
├── platform/          # Host OS network and socket introspection adapters
│   ├── windows.zig    # Windows native APIs (iphlpapi, ws2_32)
│   ├── linux.zig      # Linux sysfs (/sys/class/net) and procfs (/proc/net)
│   └── macos.zig      # macOS BSD socket adapters and loopback stubs
├── probes/            # Low-level network transport diagnostic probes
│   ├── dns.zig        # RFC 1035 DNS resolution, resolver comparison, wire parser
│   ├── tcp.zig        # TCP connectivity probes, repeated timing measurements
│   ├── tls.zig        # TLS handshake validation, SAN matching, certificate expiry
│   └── https.zig      # HTTPS timing stages and bounded HTTP response reading
├── recon/             # Bounded reconnaissance and asset discovery
│   ├── scope.zig      # Target parsing, RFC 1123 hostname rules, CIDR validation
│   ├── plan.zig       # Deterministic assessment plan generator and preview
│   └── service.zig    # Conservative banner identification (HTTP Server, SSH)
├── audit/             # Defensive security configuration auditors
│   ├── http_audit.zig # HSTS, CSP, XFO, cookie security, banner audits
│   └── exposure_audit.zig # Local listener inspection and policy compliance
├── policy/            # Declarative exposure and security rule evaluation
├── assessment/        # Multi-module assessment orchestrator and baseline diffing
├── storage/           # Versioned local persistence, history queries, and atomic writes
├── reporting/         # Multi-format report generation (terminal, JSON, Markdown)
└── lab/               # Isolated local practice lab scenarios and loopback daemons
```

---

## Installation & Build Prerequisites

- **Language:** Zig
- **Pinned Compiler Version:** `0.13.0` (Official Stable Release)
- **Supported Host & Target Operating Systems:** Windows (x86_64), Linux (x86_64, aarch64), macOS (x86_64, aarch64)

### Building from Source

```bash
# 1. Verify pinned compiler version
zig version
# Expected: 0.13.0

# 2. Build library and CLI executable (outputs to zig-out/bin/wirescope)
zig build

# 3. Run all unit, integration, and benchmark tests (290 tests)
zig build test --summary all

# 4. Format all source files
zig build fmt
```

### Cross-Compilation

WireScope compiles cleanly across target architectures without external toolchains:

```bash
# Linux x86_64
zig build -Dtarget=x86_64-linux

# Linux ARM64
zig build -Dtarget=aarch64-linux

# macOS x86_64
zig build -Dtarget=x86_64-macos

# macOS Apple Silicon (ARM64)
zig build -Dtarget=aarch64-macos
```

---

## CLI Command Reference

```
Usage:
  wirescope <command> [subcommand] [target] [options]
```

### Top-Level Commands

| Command | Subcommands / Usage | Description |
|---|---|---|
| `diagnose` | `dns <host>`, `tcp <target>`, `tls <target>`, `interfaces`, `routes`, `listeners` | Execute network transport diagnostics and host network inspection. |
| `audit` | `http <url>`, `local`, `rules` | Perform defensive security configuration audits. |
| `discover` | `<target> [--ports <ports>] [--preview]` | Perform bounded asset discovery within explicit operator scope. |
| `baseline` | `capture`, `diff <b1> <b2>`, `list` | Manage point-in-time network snapshots and compute deterministic diffs. |
| `policy` | `check [--profile <path>]` | Evaluate local security rules and exposure policies offline. |
| `history` | `list`, `inspect <id>`, `compare <id1> <id2>`, `delete <id>` | Query, inspect, compare, and manage stored assessment history. |
| `manifest` | `verify <path>`, `generate <dir>` | Verify or generate SHA-256 report artifact integrity manifests. |
| `report` | `generate <id>`, `validate <path>`, `normalize <path>` | Generate, validate against schema, or normalize assessment reports. |
| `lab` | `run <scenario>`, `list`, `status`, `reset` | Execute reproducible local practice lab exercises on loopback. |
| `capabilities` | `[--format <term\|json\|md>]` | Inspect platform capabilities, OS details, and supported features. |
| `version` | `[--format <term\|json\|md>]` | Display WireScope version, compiler version, and build mode. |
| `help` | `[<command>]` | Show comprehensive CLI help. |

### Global Flags

- `-f, --format <term|json|md>`: Output format (default: `term`).
- `-t, --timeout <ms>`: Operation timeout in milliseconds (default: `5000`).
- `-o, --output <path>`: Write report output to explicit file path with safe containment.
- `-y, --non-interactive`: Disable interactive confirmation prompts for script automation.
- `--dry-run`: Preview assessment plan and planned tasks without sending network probes.
- `-h, --help`: Display command help information.
- `-v, --version`: Display version information.

---

## CLI Exit Codes Contract

WireScope provides predictable, machine-readable process exit codes for scripts and automation pipelines:

| Exit Code | Identifier | Description |
|---|---|---|
| `0` | `success` | Operation completed successfully with no policy failures. |
| `1` | `operational_failure` | General runtime error, unexpected exception, or socket failure. |
| `2` | `invalid_input` | Missing arguments, malformed targets, or authorization unacknowledged. |
| `3` | `target_unreachable` | Host or service could not be reached (NXDOMAIN, timeout, refused). |
| `4` | `policy_violation` | One or more security policy checks or exposure rules failed. |
| `5` | `permission_limited` | Required OS privileges (e.g. Administrator / root) were unavailable. |
| `6` | `cancelled` | Operation was cooperatively cancelled or aborted prior to completion. |

---

## Library Usage & Embedding Examples

WireScope is fully embeddable in Zig applications as a native package module:

### Example: DNS Resolution & Troubleshooting
```zig
const std = @import("std");
const wirescope = @import("wirescope");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Perform DNS diagnosis
    var res = try wirescope.probes.dns.resolveHostname(allocator, "localhost", 2000);
    defer res.deinit(allocator);

    std.debug.print("Resolved {s}: {d} answer(s)\n", .{ res.hostname, res.answers.len });
    for (res.answers) |ip| {
        std.debug.print("  -> {s}\n", .{ip});
    }
}
```

### Example: TCP Probe with Statistical Latency Analysis
```zig
const std = @import("std");
const wirescope = @import("wirescope");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const connector = wirescope.probes.tcp.RealTcpConnector.connector();
    var cancel = wirescope.probes.types.CancellationToken.init();

    // Execute batch probe: 5 samples on port 80
    var batch = try wirescope.probes.tcp.executeTcpBatchProbe(
        allocator,
        connector,
        "127.0.0.1",
        80,
        5,      // count
        10,     // interval ms
        1000,   // timeout ms
        &cancel,
    );
    defer batch.deinit(allocator);

    std.debug.print("TCP Success: {d}/{d} samples\n", .{ batch.stats.successful_samples, batch.stats.total_samples });
    if (batch.stats.mean_ns) |mean| {
        std.debug.print("Mean Latency: {d} us\n", .{mean / 1000});
    }
}
```

---

## Assessment Profiles & Safety Caps Format

Assessment configurations are defined using versioned JSON profiles (`schema_version: 1`):

```json
{
  "schema_version": 1,
  "profile_id": "strict-loopback-audit",
  "name": "Strict Loopback Defensive Audit",
  "scope": {
    "targets": ["127.0.0.1", "localhost"],
    "exclusions": ["127.0.0.99"],
    "ports": "80,443,8080-8085",
    "authorization_acknowledged": true
  },
  "caps": {
    "max_hosts": 256,
    "max_ports": 100,
    "max_operations": 5000,
    "allow_broad_cidrs": false
  },
  "probes": {
    "timeout_ms": 3000,
    "max_redirects": 5,
    "allow_redirect_scope_expansion": false,
    "verify_certificates": true
  }
}
```

---

## Defensive Rules & Finding Format

Security findings generated by WireScope follow a structured schema with severity rationale, evidence, and false-positive caveats:

```json
{
  "rule_id": "WS-AUDIT-HTTP-HSTS-MISSING",
  "title": "Strict-Transport-Security Header Missing",
  "severity": "medium",
  "confidence": "high",
  "affected_target": "https://localhost:8443/",
  "evidence": "Response headers did not include 'Strict-Transport-Security'",
  "severity_rationale": "Without HSTS, initial connections remain susceptible to man-in-the-middle SSL-stripping attacks.",
  "false_positive_caveat": "Internal containerized services terminated behind an upstream TLS reverse proxy may deliberately omit HSTS.",
  "limitations": "Evaluated root response only; internal redirects may apply distinct security policies.",
  "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to web server configuration."
}
```

---

## Local Storage Layout & Retention

WireScope persists all history, baselines, and manifests in standard per-user directories:
- **Windows:** `%LOCALAPPDATA%\wirescope` or `%USERPROFILE%\.wirescope`
- **Linux:** `$XDG_DATA_HOME/wirescope` or `~/.local/share/wirescope`
- **macOS:** `~/Library/Application Support/wirescope`

### Directory Structure
```
<wirescope_data_dir>/
├── profiles/          # Custom and imported assessment profiles (.json)
├── assessments/       # Serialized assessment reports (.json)
├── observations/      # Raw network probe measurements
├── findings/          # Tracked finding records and remediation states
├── baselines/         # Captured network state snapshots
├── manifests/         # SHA-256 report integrity manifests
└── lab/               # Isolated practice lab fixtures and active state
```

### Atomic Writes & Retention
All file updates use write-to-temp-then-rename (`{file}.tmp.{timestamp}`), ensuring interrupted writes never corrupt existing records. Configurable retention policies (`max_records`, `max_age_days`) automatically prune aged history.

---

## Safety & Authorization Model

1. **Loopback Exemption:** Assessments restricted to loopback addresses (`127.0.0.1`, `localhost`, `::1`) run automatically without explicit prompts.
2. **Remote Authorization Boundary:** Probing any non-loopback IP address or external hostname strictly requires operator authorization via `--confirm-authorized` or setting `-y, --non-interactive` with a configured profile. Running non-interactively against remote targets without authorization immediately terminates with exit code `2`.
3. **Broad CIDR Protection:** Network prefixes `< /24` (e.g. `/16`, `/8`) are rejected by default with `error.ExcessiveCidrRange`.
4. **Scope Guard:** DNS resolution cannot expand loopback scope to public IPs (DNS rebinding defense). HTTP probes will not follow cross-host redirects by default.

---

## Platform Support Matrix

| Subsystem | Windows (x86_64) | Linux (x86_64, aarch64) | macOS (x86_64, aarch64) |
|---|---|---|---|
| **Compilation** | Native Tested | Cross-Compiled | Cross-Compiled |
| **Unit & Integration Tests** | 290/290 Passed | Host Cross-Runner | Host Cross-Runner |
| **Interface Enumeration** | Native (`iphlpapi`) | Supported (`/sys/class/net`) | Supported (loopback fallback) |
| **Routing Inspection** | Native (`GetBestRoute`) | Supported (`/proc/net/route`) | Subprocess Fallback |
| **Listening Sockets** | Native (`GetExtendedTcpTable`) | Supported (`/proc/net/tcp`) | Supported |
| **Process Attribution** | Permission-Limited | Permission-Limited | Unsupported |
| **DNS, TCP, TLS, HTTP** | Native Tested | Supported | Supported |
| **Practice Lab Lifecycles** | Native Tested | Supported | Supported |
| **Integrity Manifests** | Native Tested | Supported | Supported |

*See [`docs/platform_support_and_matrix.md`](docs/platform_support_and_matrix.md) for detailed capability descriptions.*

---

## Residual Risks & Limitations

WireScope explicitly records residual technical limitations rather than claiming absolute security:
1. **DNS Rebinding TOCTOU:** Race condition between pre-connect DNS scope check and OS socket connection.
2. **OS Privilege Boundaries:** Correlating local listening sockets with owning process binaries requires Administrator / root privileges.
3. **System Clock Reliance:** TLS certificate validity checking relies on local host system clock accuracy.
4. **Middlebox RST Injection:** Intermediate firewalls may forge TCP RST packets, mimicking a closed port.
5. **Filesystem Permissions:** Saved history relies on OS user-level ACLs/umask.
6. **Local Hash Integrity:** SHA-256 manifests detect accidental alteration, not malicious local author impersonation without PKI signing.

*See [`docs/security_hardening_and_residual_risks.md`](docs/security_hardening_and_residual_risks.md) for full documentation.*

---

## Troubleshooting Guide

### Common Issues & Resolutions

- **`Exit Code 2 (invalid_input)` on Remote Targets:**
  * *Cause:* Assessing remote hosts without authorization acknowledgment.
  * *Fix:* Add `--confirm-authorized` to command invocation or set `"authorization_acknowledged": true` in the assessment profile.
- **`WS-AUDIT-EXPOSURE-PERMISSION-LIMITED` in Local Exposure Audits:**
  * *Cause:* Running WireScope as an unprivileged user prevents querying process ownership.
  * *Fix:* Run terminal with elevated privileges (Administrator on Windows, `sudo` on Linux).
- **TCP Probe Timeout vs Refusal:**
  * *Refusal (< 5 ms):* The host network stack is reachable, but no service is listening on the port.
  * *Timeout (>= timeout_ms):* Host is unreachable or an intermediate packet filter silently dropped the probe.
- **Lab Socket Allocation Conflicts:**
  * *Cause:* Another daemon is already bound to the ephemeral practice lab port.
  * *Fix:* Run `wirescope lab reset` to clear active lab state.

---

## Project Roadmap & Status

Current Branch: `ashish`

| Milestone | Title | Status |
| :--- | :--- | :--- |
| **Milestone 0** | Repository Reconnaissance & Technical Feasibility | **COMPLETED** |
| **Milestone 1** | Project Skeleton and Core Contracts | **COMPLETED** |
| **Milestone 2** | CLI, Configuration, and Profiles | **COMPLETED** |
| **Milestone 3** | Local Network Intelligence | **COMPLETED** |
| **Milestone 4** | Shared Probe Engine and Resource Controls | **COMPLETED** |
| **Milestone 5** | DNS Diagnostics | **COMPLETED** |
| **Milestone 6** | TCP Connectivity and Latency | **COMPLETED** |
| **Milestone 7** | TLS and HTTPS Diagnostics | **COMPLETED** |
| **Milestone 8** | Authorized Reconnaissance | **COMPLETED** |
| **Milestone 9** | Defensive Security Auditors | **COMPLETED** |
| **Milestone 10** | Assessment Orchestration, Policies, and Baselines | **COMPLETED** |
| **Milestone 11** | Local Persistence, History, and Integrity | **COMPLETED** |
| **Milestone 12** | Reporting and Automation Contracts | **COMPLETED** |
| **Milestone 13** | Isolated Practice Lab | **COMPLETED** |
| **Milestone 14** | **Hardening, Cross-Platform Validation, and Release Prep** | **COMPLETED** |
| ↳ Phase 14.1 | Perform security and reliability hardening | **COMPLETED** |
| ↳ Phase 14.2 | Validate behavior on Linux, macOS, and Windows | **COMPLETED** |
| ↳ Phase 14.3 | Complete documentation, license, and release candidate | **COMPLETED** |
| **Milestone 15** | GitHub Actions CI/CD (Final Milestone) | Pending |

---

## Architecture Decision Records (ADRs)

- [ADR 0001: Baseline Environment and Feasibility Setup](docs/decisions/0001-baseline-and-feasibility.md)
- [ADR 0002: Pinned Zig Version and API Feasibility Validation](docs/decisions/0002-pinned-zig-and-api-feasibility.md)
- [ADR 0003: Module Layout and Build System Architecture](docs/decisions/0003-module-layout-and-build-system.md)
- [ADR 0004: Typed Results, Error Model, and Memory Ownership](docs/decisions/0004-typed-results-and-ownership-model.md)
- [ADR 0005: CLI Command Parser, Capability Reporting, and Exit Codes](docs/decisions/0005-cli-command-parser-and-exit-codes.md)
- [ADR 0006: Versioned Configuration, Assessment Profiles, and Scope Guard](docs/decisions/0006-configuration-and-assessment-profiles.md)
- [ADR 0007: Network Interface Enumeration and Platform Adapters](docs/decisions/0007-network-interface-enumeration.md)
- [ADR 0008: Routing Table and Default Gateway Inspection](docs/decisions/0008-routing-table-and-gateway-inspection.md)
- [ADR 0009: Local Listening Services Inspection](docs/decisions/0009-listening-services-inspection.md)
- [ADR 0010: Shared Probe Engine Scheduling, Deadlines, and Cancellation](docs/decisions/0010-probe-engine-scheduling-deadlines-and-cancellation.md)
- [ADR 0011: Normalized Timing, Errors, and Operation Metadata](docs/decisions/0011-normalized-timing-errors-and-operation-metadata.md)
- [ADR 0012: DNS Resolution and Failure Classification](docs/decisions/0012-dns-resolution-and-failure-classification.md)
- [ADR 0013: DNS Troubleshooting and Resolver Comparison](docs/decisions/0013-dns-troubleshooting-and-resolver-comparison.md)
- [ADR 0014: TCP Connectivity Probes and Lifecycle](docs/decisions/0014-tcp-connectivity-probes.md)
- [ADR 0015: TCP Repeated Measurements and Statistical Summaries](docs/decisions/0015-tcp-repeated-measurements-and-statistics.md)
- [ADR 0016: Actionable Connectivity Troubleshooting](docs/decisions/0016-actionable-connectivity-troubleshooting.md)
- [ADR 0017: TLS Certificate-Chain and Hostname Validation](docs/decisions/0017-tls-certificate-and-hostname-validation.md)
- [ADR 0018: HTTPS Timing and Bounded Response Handling](docs/decisions/0018-https-timing-and-bounded-response-handling.md)
- [ADR 0019: Scope Validation and Assessment Plan Preview](docs/decisions/0019-scope-validation-and-plan-preview.md)
- [ADR 0020: Bounded Host Discovery and Reachability States](docs/decisions/0020-bounded-host-discovery.md)
- [ADR 0021: Bounded TCP Port Checks and Conservative Service Identification](docs/decisions/0021-tcp-port-checks-and-conservative-service-identification.md)
- [ADR 0022: Asset and Exposure Inventory](docs/decisions/0022-asset-and-exposure-inventory.md)
- [ADR 0023: Defensive HTTP Security Configuration Auditor](docs/decisions/0023-http-security-configuration-auditor.md)
- [ADR 0024: Defensive Local Exposure Auditor](docs/decisions/0024-local-exposure-auditor.md)
- [ADR 0025: Versioned Local Rules Engine](docs/decisions/0025-versioned-local-rules-engine.md)
- [ADR 0026: Multi-Module Assessment Orchestrator](docs/decisions/0026-multi-module-assessment-orchestrator.md)
- [ADR 0027: Explicit Baselines and Deterministic Diffs](docs/decisions/0027-explicit-baselines-and-deterministic-diffs.md)
- [ADR 0028: Normalize Findings and Remediation Tracking](docs/decisions/0028-normalize-findings-and-remediation-tracking.md)
- [ADR 0029: Offline Policy Evaluation](docs/decisions/0029-offline-policy-evaluation.md)
- [ADR 0030: Versioned Local Storage](docs/decisions/0030-versioned-local-storage.md)
- [ADR 0031: History Queries, Retention, and Recovery](docs/decisions/0031-history-queries-retention-and-recovery.md)
- [ADR 0032: Report Integrity Manifests](docs/decisions/0032-report-integrity-manifests.md)
- [ADR 0033: Versioned JSON Reports](docs/decisions/0033-versioned-json-reports.md)
- [ADR 0034: Markdown and Terminal Reports](docs/decisions/0034-markdown-and-terminal-reports.md)
- [ADR 0035: CLI Automation and Scripting Contracts](docs/decisions/0035-cli-automation-and-scripting-contracts.md)
- [ADR 0036: Practice Lab Lifecycle and Isolation](docs/decisions/0036-lab-lifecycle-and-isolation.md)
- [ADR 0037: Initial Diagnostic and Defensive Practice Exercises](docs/decisions/0037-initial-diagnostic-and-defensive-exercises.md)
- [ADR 0038: Security Hardening, Verification Engines, and Residual Risks](docs/decisions/0038-security-hardening-and-residual-risks.md)
- [ADR 0039: Platform Support Matrix and Performance Validation](docs/decisions/0039-platform-support-matrix-and-performance-validation.md)
- [ADR 0040: Documentation, License, and Release Candidate](docs/decisions/0040-documentation-license-and-release-candidate.md)

---

## Security, License, and Contributing

- **Security Reporting:** See [SECURITY.md](SECURITY.md) for vulnerability disclosure guidelines.
- **Contributing Guidelines:** See [CONTRIBUTING.md](CONTRIBUTING.md) for developer requirements.
- **Changelog:** See [CHANGELOG.md](CHANGELOG.md) for version history.
- **Release Notes:** See [docs/release_notes_v0.1.0_rc1.md](docs/release_notes_v0.1.0_rc1.md) for Release Candidate 1 notes.
- **License:** Licensed under the [MIT License](LICENSE).
