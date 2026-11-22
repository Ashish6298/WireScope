<a id="top"></a>
<div align="center">

```text
  ██╗    ██╗ ██╗ ██████╗  ███████╗ ███████╗  ██████╗  ██████╗  ██████╗  ███████╗
  ██║    ██║ ██║ ██╔══██╗ ██╔════╝ ██╔════╝ ██╔════╝ ██╔═══██╗ ██╔══██╗ ██╔════╝
  ██║ █╗ ██║ ██║ ██████╔╝ █████╗   ███████╗ ██║      ██║   ██║ ██████╔╝ █████╗  
  ██║███╗██║ ██║ ██╔══██╗ ██╔══╝   ╚════██║ ██║      ██║   ██║ ██╔═══╝  ██╔══╝  
  ╚███╔███╔╝ ██║ ██║  ██║ ███████╗ ███████║ ╚██████╗ ╚██████╔╝ ██║      ███████╗
   ╚══╝╚══╝  ╚═╝ ╚═╝  ╚═╝ ╚══════╝ ╚══════╝  ╚═════╝  ╚═════╝  ╚═╝      ╚══════╝
```

### *Local-First Network Diagnostics & Defensive Security Toolkit*

<p align="center">
  <b>A deterministic, evidence-driven network engineering engine and non-root defensive security toolkit written in pure Zig. Combines everyday diagnostics with offline security audits, baseline drift tracking, SHA-256 report integrity manifests, and an isolated loopback practice lab.</b>
</p>

```text
  [01] Transport Probes  ──►  [02] Defensive Auditing  ──►  [03] Baseline Drift  ──►  [04] Verified Reports
```

<br/>

<table>
  <tr>
    <td align="center"><a href="https://ziglang.org/"><img src="https://img.shields.io/badge/Language-Zig_0.13.0-F7A41D?style=plastic&logo=zig&logoColor=white" alt="Zig 0.13.0"/></a></td>
    <td align="center"><a href="https://github.com/Ashish6298/WireScope/releases"><img src="https://img.shields.io/badge/Release-v1.0.0-007EC6?style=plastic&logo=github&logoColor=white" alt="Release v1.0.0"/></a></td>
    <td align="center"><a href="#testing--verification"><img src="https://img.shields.io/badge/Tests-294%2F294_Passed-00C853?style=plastic&logo=checkmarx&logoColor=white" alt="Tests Passed"/></a></td>
    <td align="center"><a href="#zero-telemetry--privacy"><img src="https://img.shields.io/badge/Telemetry-Zero_%28100%25_Local%29-17A2B8?style=plastic&logo=openaccess&logoColor=white" alt="Zero Telemetry"/></a></td>
  </tr>
  <tr>
    <td align="center"><a href="#platform-support-matrix"><img src="https://img.shields.io/badge/Platform-Windows_%7C_Linux_%7C_macOS-2962FF?style=plastic&logo=linux&logoColor=white" alt="Multi-Platform"/></a></td>
    <td align="center"><a href="docs/decisions/"><img src="https://img.shields.io/badge/Architecture-Architecture_Decisions-7F77DD?style=plastic&logo=diagramsdotnet&logoColor=white" alt="Architecture Decision Records"/></a></td>
    <td align="center"><a href="CODE_OF_CONDUCT.md"><img src="https://img.shields.io/badge/Contributor-Covenant_v2.1-E91E63?style=plastic&logo=handshake&logoColor=white" alt="Contributor Covenant"/></a></td>
    <td align="center"><a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-F5A623?style=plastic&logo=open-source-initiative&logoColor=white" alt="MIT License"/></a></td>
  </tr>
</table>

<br>

</div>

## 🧭 Navigation

<pre>
# SYSTEM NAVIGATION MAP
 ├── <b>[01] FOUNDATION & PHILOSOPHY</b>
 │    ├── ❯ <a href="#what-is-wirescope"><b>What is WireScope?</b></a>
 │    ├── ❯ <a href="#core-architectural-pillars"><b>Core Architectural Pillars</b></a>
 │    ├── ❯ <a href="#why-wirescope-over-traditional-tools"><b>Benchmark: WireScope vs Traditional CLI Tools</b></a>
 │    └── ❯ <a href="#quick-start-guide"><b>Quick Start Guide</b></a>
 │
 ├── <b>[02] INTERACTIVE CONSOLE & WORKFLOWS</b>
 │    ├── ❯ <a href="#interactive-3x3-card-grid-console"><b>Interactive 3x3 Card Grid Console</b></a>
 │    ├── ❯ <a href="#terminal-ui-showcase"><b>Terminal UI & Modern Palette Showcase</b></a>
 │    └── ❯ <a href="#cli-command-reference"><b>Complete CLI Command Reference</b></a>
 │
 ├── <b>[03] CORE SUBSYSTEMS & DIAGNOSTICS</b>
 │    ├── ❯ <a href="#transport-diagnostics-engine"><b>Transport Diagnostics Engine (DNS, TCP, TLS, HTTPS)</b></a>
 │    ├── ❯ <a href="#defensive-security-auditors"><b>Defensive Security Auditors (HTTP & Exposure)</b></a>
 │    ├── ❯ <a href="#baseline-drift-engine"><b>Baseline Snapshots & Deterministic Diffs</b></a>
 │    ├── ❯ <a href="#isolated-loopback-practice-lab"><b>Isolated Practice Lab & Training Scenarios</b></a>
 │    └── ❯ <a href="#storage-manifest-integrity"><b>Storage Layout & SHA-256 Manifest Integrity</b></a>
 │
 └── <b>[04] GOVERNANCE & ENGINEERING CONTRACTS</b>
      ├── ❯ <a href="#cli-exit-codes-contract"><b>CLI Machine Exit Codes Contract</b></a>
      ├── ❯ <a href="#platform-support-matrix"><b>Platform Support Matrix</b></a>
      ├── ❯ <a href="#library-usage-embedding"><b>Zig Native Library Embedding</b></a>
      ├── ❯ <a href="#testing--verification"><b>Testing, Fuzzing & Hardening</b></a>
      ├── ❯ <a href="#architecture-decision-records"><b>Architecture Decision Records</b></a>
      ├── ❯ <a href="#code-of-conduct"><b>Code of Conduct</b></a>
      └── ❯ <a href="#license"><b>License & Security</b></a>
</pre>

<br>

<a id="what-is-wirescope"></a>
## 💡 What is WireScope?

> **WireScope** is an open-source, evidence-driven network engineering and defensive cybersecurity platform built in pure Zig. It eliminates the fragile patchwork of `dig`, `curl`, `netstat`, `nmap`, and ad-hoc shell scripts by providing a unified, local-first engine that measures network ground truth without cloud telemetry, root requirements, or offensive payloads.

WireScope functions as both a high-performance standalone CLI binary (`wirescope` / `wirescope.exe`) and an embeddable Zig native module (`@import("wirescope")`).

<br/>

<a id="core-architectural-pillars"></a>
### 🏛️ Core Architectural Pillars

<table>
  <tr>
    <th width="28%" align="left"><b>Pillar</b></th>
    <th width="72%" align="left"><b>Technical Architecture & Guarantees</b></th>
  </tr>
  <tr>
    <td><b>🔒 100% Local & Zero Telemetry</b></td>
    <td>No external telemetry daemons, remote tracking beacons, SaaS backends, or cloud accounts. All measurements, baselines, and findings reside exclusively in local OS user storage.</td>
  </tr>
  <tr>
    <td><b>⚖️ Evidence-Driven Findings</b></td>
    <td>Strict separation between raw physical measurements (latency samples, handshake certificates, wire records) and interpretive analysis. No phantom vulnerabilities or ungrounded claims.</td>
  </tr>
  <tr>
    <td><b>🛡️ Strict Scope Guard & Non-Root</b></td>
    <td>Operates effectively without root/administrator privileges. Bounded targets, loopback exemptions, broad CIDR blocks (< /24) rejected by default, and strict zero-exploit safety caps.</td>
  </tr>
  <tr>
    <td><b>⚡ Memory Safety & Bounded Resources</b></td>
    <td>Zero memory leaks validated across all operations with Zig's <code>GeneralPurposeAllocator</code>. Bounded response bodies (1 MB), thread pool limits (32 workers), and pre-dispatch caps (5,000 tasks).</td>
  </tr>
  <tr>
    <td><b>🔏 Cryptographic Provenance</b></td>
    <td>Every generated assessment report includes a reproducible SHA-256 integrity manifest for tamper detection, compliance verification, and deterministic auditing.</td>
  </tr>
</table>

<br>

<a id="why-wirescope-over-traditional-tools"></a>
## ⚔️ Why WireScope over Traditional CLI Tools?

> Traditional networking utilities are fragmented across dozens of platform-dependent binaries, lack standardized structured output, leak DNS queries, and lack defensive baseline tracking.

```text
[TRADITIONAL WORKFLOW]
  dig + netstat + curl + nmap ──► Script Fragility ──► Format Inconsistency ──► Missing Evidence ❌

[WIRESCOPE ENGINE]
  Unified Zig Engine ──► Bounded Probes ──► Offline Rules ──► Baseline Drift ──► Verified Artifacts ✅
```

### 📊 Capability Benchmark Matrix

```text
🔒 Local-First Zero Telemetry
   • Traditional Tools   ░░░░░░░░░░  [0/10]  (Scattered, variable telemetry in modern utilities)
   • Cloud Auditing APIs ██░░░░░░░░  [2/10]  (Exposes network topology to third-party clouds)
   • ⬢ WIRESCOPE         ██████████  [10/10] (100% Offline, Zero Network Leaks, No Telemetry)

⚡ Evidence-Grounded Observations
   • Ping / Curl         ████░░░░░░  [4/10]  (Raw text, no structured evidence retention)
   • Security Scanners   ██████░░░░  [6/10]  (Heuristic guessing, high false-positive rates)
   • ⬢ WIRESCOPE         ██████████  [10/10] (Cryptographically verifiable observation chains)

📉 Baseline Drift & Diffing
   • Ping / Curl         ░░░░░░░░░░  [0/10]  (No temporal memory or diff capability)
   • Port Scanners       ███░░░░░░░  [3/10]  (Requires external diff scripts on output files)
   • ⬢ WIRESCOPE         ██████████  [10/10] (Native point-in-time snapshots and JSON diffs)

🛡️ Non-Root Safety Scope Guard
   • Raw Packet Scanners █░░░░░░░░░  [1/10]  (Requires raw socket root privileges)
   • Standard Tools      █████░░░░░  [5/10]  (Unbounded sweeps, accidental CIDR expansion)
   • ⬢ WIRESCOPE         ██████████  [10/10] (Strict scope guard, non-root auditing, safe bounds)

🧪 Isolated Practice Lab
   • Traditional Tools   ░░░░░░░░░░  [0/10]  (Requires external docker/vm testbeds)
   • ⬢ WIRESCOPE         ██████████  [10/10] (Zero-dependency loopback practice exercises)
```

<br>

<a id="quick-start-guide"></a>
## ⚡ Quick Start Guide

### 1. Prerequisites

- **Language:** Zig
- **Pinned Compiler:** `0.13.0` (Official Stable Release)
- **Supported Architectures:** Windows (`x86_64`), Linux (`x86_64`, `aarch64`), macOS (`x86_64`, `aarch64`)

### 2. Build from Source

```bash
# Clone the repository
git clone https://github.com/Ashish6298/WireScope.git
cd WireScope

# Build the self-contained ReleaseSafe binary
zig build -Doptimize=ReleaseSafe

# Binary output is placed in:
# ./zig-out/bin/wirescope (Linux/macOS) or .\zig-out\bin\wirescope.exe (Windows)

# Run full test suite (294 unit and integration tests)
zig build test --summary all
```

### 3. Immediate 1-Command Verification

```bash
# Launch the guided interactive card grid console
wirescope menu

# Check what this machine exposes locally (read-only, non-root)
wirescope audit local

# Diagnose DNS resolution with RFC-compliant breakdown
wirescope diagnose dns localhost
```

<br>

<a id="interactive-3x3-card-grid-console"></a>
## 🎮 Interactive 3x3 Card Grid Console

WireScope features a terminal console built with a 3x3 keyboard-navigable card grid rendered in **24-bit TrueColor** with rounded borders.

Launch it instantly from any terminal:
```bash
wirescope menu
```

```text
  ██╗    ██╗ ██╗ ██████╗  ███████╗ ███████╗  ██████╗  ██████╗  ██████╗  ███████╗
  ██║    ██║ ██║ ██╔══██╗ ██╔════╝ ██╔════╝ ██╔════╝ ██╔═══██╗ ██╔══██╗ ██╔════╝
  ██║ █╗ ██║ ██║ ██████╔╝ █████╗   ███████╗ ██║      ██║   ██║ ██████╔╝ █████╗  
  ██║███╗██║ ██║ ██╔══██╗ ██╔══╝   ╚════██║ ██║      ██║   ██║ ██╔═══╝  ██╔══╝  
  ╚███╔███╔╝ ██║ ██║  ██║ ███████╗ ███████║ ╚██████╗ ╚██████╔╝ ██║      ███████╗
   ╚══╝╚══╝  ╚═╝ ╚═╝  ╚═╝ ╚══════╝ ╚══════╝  ╚═════╝  ╚═════╝  ╚═╝      ╚══════╝

  Local-First Network Diagnostics & Defensive Security Toolkit
  Zero Telemetry | Non-Root Auditing | Deterministic Outcomes

  ╭──────────────────────╮  ╭──────────────────────╮  ╭──────────────────────╮
  │         [1]          │  │         [2]          │  │         [3]          │
  │    Audit Exposure    │  │      TCP Check       │  │     DNS Diagnose     │
  │   ports, listeners   │  │   host:port probe    │  │    A/AAAA records    │
  ╰──────────────────────╯  ╰──────────────────────╯  ╰──────────────────────╯
  ╭──────────────────────╮  ╭──────────────────────╮  ╭──────────────────────╮
  │         [4]          │  │         [5]          │  │         [6]          │
  │      Interfaces      │  │    Routing Table     │  │   Security Policy    │
  │     IPv4 / IPv6      │  │   routes, gateway    │  │    offline rules     │
  ╰──────────────────────╯  ╰──────────────────────╯  ╰──────────────────────╯
  ╭──────────────────────╮  ╭──────────────────────╮  ╭──────────────────────╮
  │         [7]          │  │         [8]          │  │         [0]          │
  │     Practice Lab     │  │     Capabilities     │  │         Exit         │
  │  loopback training   │  │   features, rights   │  │         quit         │
  ╰──────────────────────╯  ╰──────────────────────╯  ╰──────────────────────╯

  arrows move    enter run    1-8 jump and run    0 / q exit
```

- **Controls:** Arrow keys (`↑`, `↓`, `←`, `→`) or Vim navigation (`h`, `j`, `k`, `l`) navigate between cards.
- **Instant Hotkeys:** Press `1`–`8` to immediately jump and run any diagnostics drill.
- **Direct Exit:** Press `0`, `q`, or `Esc` to cleanly exit back to your prompt.
- **Non-Interactive Fallback:** Detects piped inputs (`echo 0 | wirescope menu`) and gracefully falls back to non-TTY automation mode.

<br>

<a id="terminal-ui-showcase"></a>
## 🎨 Terminal UI Showcase

### 1. Hub Screen (`wirescope`)

```text
  GET STARTED

    $ wirescope menu            guided interactive console
    $ wirescope audit local     check what this machine exposes
    $ wirescope diagnose dns example.com

  WHAT IT DOES

    ▸ Diagnoses DNS, TCP, TLS, interfaces and routes
    ▸ Audits local exposure and security policy, read-only
    ▸ Saves baselines and reports you can verify later

  ────────────────────────────────────────────────────────────────────────────
  v1.0.0  ·  run wirescope help for every command
```

### 2. Rounded Grouped Help Reference (`wirescope help`)

```text
  wirescope <command> [subcommand] [target] [options]

  ╭─ assess ─────────────────────────────────────────────────────────────────╮
  │ diagnose      Run network diagnostics (dns, tcp, tls, interfaces, routes)│
  │ audit         Run defensive security audits (tls, http, local)           │
  │ policy        Evaluate local security rules and exposure policies        │
  │ discover      Bounded asset discovery within explicit scope              │
  ╰──────────────────────────────────────────────────────────────────────────╯

  ╭─ track ──────────────────────────────────────────────────────────────────╮
  │ baseline      Save and compare baseline state snapshots                  │
  │ history       Query, inspect, compare and prune history                  │
  │ manifest      Verify report integrity manifests                          │
  │ report        Generate, validate and normalize reports                   │
  ╰──────────────────────────────────────────────────────────────────────────╯

  ╭─ practice ───────────────────────────────────────────────────────────────╮
  │ lab           Run reproducible local practice scenarios                  │
  ╰──────────────────────────────────────────────────────────────────────────╯

  ╭─ system ─────────────────────────────────────────────────────────────────╮
  │ capabilities  Inspect platform capabilities                              │
  │ version       Show version and compiler information                      │
  │ help          Show help for a command                                    │
  ╰──────────────────────────────────────────────────────────────────────────╯
```

### 3. Styled Version Card (`wirescope --version`)

```text
  ╭─ wirescope v1.0.0 ───────────────────────────────────────────────────────╮
  │  compiler    zig 0.13.0                                                  │
  │  platform    windows-x86_64                                              │
  │  telemetry   none (zero network tracking)                                │
  ╰──────────────────────────────────────────────────────────────────────────╯
```

<br>

<a id="cli-command-reference"></a>
## 💻 Complete CLI Command Reference

```bash
wirescope <command> [subcommand] [target] [options]
```

### Commands Matrix

| Command | Subcommands / Usage | Description |
|---|---|---|
| `diagnose` | `dns <host>`, `tcp <target>`, `tls <target>`, `interfaces`, `routes`, `listeners` | Execute network transport diagnostics and local interface/routing inspections. |
| `audit` | `http <url>`, `local`, `rules` | Perform defensive security audits against HTTP services or host exposures. |
| `policy` | `check [--profile <path>]` | Evaluate offline security policies, exposure limits, and hardening rules. |
| `baseline` | `capture`, `diff <b1> <b2>`, `list` | Snapshot network state and compute deterministic diffs to detect baseline drift. |
| `discover` | `<target> [--ports <range>] [--preview]` | Bounded asset discovery within explicit operator scope. |
| `lab` | `run <scenario>`, `list`, `status`, `reset` | Launch reproducible local practice lab exercises on loopback. |
| `history` | `list`, `inspect <id>`, `compare <id1> <id2>`, `delete <id>` | Query, inspect, compare, and prune stored historical assessment reports. |
| `manifest` | `verify <path>`, `generate <dir>` | Generate or cryptographically verify SHA-256 report integrity manifests. |
| `report` | `generate <id>`, `validate <path>`, `normalize <path>` | Generate, schema-validate, and normalize assessment reports. |
| `capabilities` | `[--format <term\|json\|md>]` | Inspect platform network capabilities and OS privilege boundaries. |
| `version` | `[--format <term\|json\|md>]` | Display WireScope compiler, platform, and telemetry metadata. |
| `help` | `[<command>]` | Render command help reference. |

### Global Flags

- `-f, --format <term|json|md>`: Output format (default: `term`).
- `-t, --timeout <ms>`: Operation timeout in milliseconds (default: `5000`).
- `-o, --output <path>`: Write report output to explicit file path with directory containment.
- `-y, --non-interactive`: Disable interactive confirmation prompts for automated scripts.
- `--no-color`: Disable ANSI/TrueColor terminal formatting.
- `--dry-run`: Preview planned tasks without executing socket operations.
- `-h, --help`: Display help screen.
- `-v, --version`: Display version card.

<br>

<a id="transport-diagnostics-engine"></a>
## 🔬 Transport Diagnostics Engine

### 1. DNS Resolution & Diagnostic Breakdown
RFC 1035 wire parser and OS resolver comparison (`getaddrinfo` vs direct recursive query). Detects latency, NXDOMAIN, TTL degradation, and authoritative responses:
```bash
wirescope diagnose dns example.com
```

### 2. TCP Port Connectivity & Statistical Latency
Repeated sampling, statistical distribution analysis, jitter calculation (RFC 3550), and fast distinction between refusal (`RST`) and silent drop (`TIMEOUT`):
```bash
wirescope diagnose tcp 127.0.0.1:80
```

### 3. TLS Handshake & Certificate Validation
Validates TLS 1.2 / 1.3 handshakes, certificate expiration, Subject Alternative Names (SAN) matching, and cipher suite support:
```bash
wirescope diagnose tls example.com:443
```

### 4. Interfaces & Routing Table Inspection
Reads platform adapter data, MAC addresses, IPv4/IPv6 assignments, and default gateway routes without running shell scripts:
```bash
wirescope diagnose interfaces
wirescope diagnose routes
```

<br>

<a id="defensive-security-auditors"></a>
## 🛡️ Defensive Security Auditors

### 1. Local Exposure Audit (`wirescope audit local`)
Inspects open listening ports (`TCP`/`UDP`), identifies non-loopback bindings (`0.0.0.0`, `::`), evaluates whether exposures violate defensive rules, and checks process attribution within non-root boundaries.

### 2. Defensive HTTP Security Header Audit (`wirescope audit http <url>`)
Evaluates web endpoints against strict defensive security baselines:
- **HSTS:** `Strict-Transport-Security` enforcement and max-age validation.
- **CSP:** `Content-Security-Policy` presence and restrictive directives.
- **Framing:** `X-Frame-Options` and `frame-ancestors` clickjacking defenses.
- **MIME:** `X-Content-Type-Options: nosniff` validation.
- **Cookies:** `Secure`, `HttpOnly`, and `SameSite` attribute enforcement.
- **Information Leakage:** Server banners and technology fingerprint disclosures.

<br>

<a id="baseline-drift-engine"></a>
## 📉 Baseline Snapshots & Deterministic Diffs

WireScope allows capturing known-good network states and computing deterministic diffs over time:

```bash
# Capture current listening ports and network state as baseline
wirescope baseline capture --name "production-base"

# Later, compare active state against the baseline
wirescope baseline diff production-base current
```

Any newly opened port, removed service, or configuration drift is flagged with an explicit structured delta.

<br>

<a id="isolated-loopback-practice-lab"></a>
## 🧪 Isolated Loopback Practice Lab

WireScope includes a built-in, zero-dependency practice lab that spins up isolated loopback fixtures (`127.0.0.1`) for reproducible training without touching live production networks:

```bash
# List available lab drills
wirescope lab list

# Execute a training scenario
wirescope lab run dns_failure
wirescope lab run tcp_refusal_timeout
wirescope lab run unexpected_listener
wirescope lab run http_security_header_violation

# Reset lab fixtures
wirescope lab reset
```

<br>

<a id="storage-manifest-integrity"></a>
## 🔏 Storage Layout & SHA-256 Manifest Integrity

WireScope stores data using standard per-user local directories:
- **Windows:** `%LOCALAPPDATA%\wirescope` or `%USERPROFILE%\.wirescope`
- **Linux:** `$XDG_DATA_HOME/wirescope` or `~/.local/share/wirescope`
- **macOS:** `~/Library/Application Support/wirescope`

### Directory Layout
```text
<wirescope_data_dir>/
├── profiles/          # Custom and imported assessment profiles (.json)
├── assessments/       # Serialized assessment reports (.json)
├── observations/      # Raw network measurements
├── findings/          # Tracked findings and remediation states
├── baselines/         # Point-in-time network snapshots
├── manifests/         # SHA-256 report integrity manifests
└── lab/               # Isolated practice lab fixtures
```

### Atomic Writes & Tamper Detection
- **Atomic File Writes:** All storage writes use write-to-temporary-then-rename (`{file}.tmp.{timestamp}`), preventing corrupt states if interrupted.
- **SHA-256 Integrity Manifests:** Generated reports produce an associated `.manifest.json` recording cryptographic digests of all artifacts for tamper detection.

<br>

<a id="cli-exit-codes-contract"></a>
## 🚦 CLI Exit Codes Contract

Predictable, machine-readable exit codes for CI/CD pipelines and script automation:

| Code | Identifier | Description |
|---|---|---|
| `0` | `success` | Operation completed successfully with no policy failures. |
| `1` | `operational_failure` | General runtime error, unexpected exception, or socket failure. |
| `2` | `invalid_input` | Missing arguments, malformed targets, or authorization unacknowledged. |
| `3` | `target_unreachable` | Target service unreachable (NXDOMAIN, timeout, connection refused). |
| `4` | `policy_violation` | One or more security policy checks or exposure rules failed. |
| `5` | `permission_limited` | Required OS privileges (e.g. Administrator / root) were unavailable. |
| `6` | `cancelled` | Operation cooperatively cancelled or timed out. |

<br>

<a id="platform-support-matrix"></a>
## 🖥️ Platform Support Matrix

| Subsystem | Windows (`x86_64`) | Linux (`x86_64`, `aarch64`) | macOS (`x86_64`, `aarch64`) |
|---|---|---|---|
| **Compilation** | Native Tested | Cross-Compiled | Cross-Compiled |
| **Unit & Integration Tests** | 294/294 Passed | Host Cross-Runner | Host Cross-Runner |
| **Interface Enumeration** | Native (`iphlpapi`) | Supported (`/sys/class/net`) | Supported (loopback fallback) |
| **Routing Inspection** | Native (`GetBestRoute`) | Supported (`/proc/net/route`) | Subprocess Fallback |
| **Listening Sockets** | Native (`GetExtendedTcpTable`) | Supported (`/proc/net/tcp`) | Supported |
| **Process Attribution** | Permission-Limited | Permission-Limited | Unsupported |
| **DNS, TCP, TLS, HTTP** | Native Tested | Supported | Supported |
| **Practice Lab Lifecycles** | Native Tested | Supported | Supported |
| **Integrity Manifests** | Native Tested | Supported | Supported |

<br>

<a id="library-usage-embedding"></a>
## 📦 Zig Native Library Embedding

WireScope is completely modular and can be consumed as a native Zig package:

```zig
const std = @import("std");
const wirescope = @import("wirescope");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 1. Perform DNS diagnosis
    var dns_res = try wirescope.probes.dns.resolveHostname(allocator, "localhost", 2000);
    defer dns_res.deinit(allocator);

    std.debug.print("DNS Resolved: {s} -> {d} answers\n", .{ dns_res.hostname, dns_res.answers.len });

    // 2. Execute TCP latency batch probe
    const connector = wirescope.probes.tcp.RealTcpConnector.connector();
    var cancel = wirescope.probes.types.CancellationToken.init();

    var batch = try wirescope.probes.tcp.executeTcpBatchProbe(
        allocator,
        connector,
        "127.0.0.1",
        80,
        5,      // sample count
        10,     // interval ms
        1000,   // timeout ms
        &cancel,
    );
    defer batch.deinit(allocator);

    if (batch.stats.mean_ns) |mean| {
        std.debug.print("TCP Mean Latency: {d} us\n", .{mean / 1000});
    }
}
```

<br>

<a id="testing--verification"></a>
## 🧪 Testing, Fuzzing & Hardening

WireScope undergoes rigorous multi-layer verification:
- **294 Unit & Integration Tests:** Covering DNS RFC parsing, TCP timeouts, TLS hostname validation, and storage corruption recovery.
- **Memory Safety:** Tested continuously with Zig's `GeneralPurposeAllocator` ensuring zero leaks.
- **Scope-Escape Fuzzing:** Automated tests verifying that loopback-restricted scopes cannot escape to external CIDRs or follow remote redirect hops.

Run the test suite:
```bash
zig build test --summary all
```

<br>

<a id="architecture-decision-records"></a>
## 📑 Architecture Decision Records

> WireScope’s design principles, security invariants, and technical tradeoffs are documented in formal Architecture Decision Records located in [`docs/decisions/`](docs/decisions/). Organized by functional domain:

<details>
<summary><b>📂 Core Architecture, Platform & Runtime Foundation</b></summary>
<br/>

<table>
  <tr>
    <th width="45%"><b>Architecture Decision</b></th>
    <th width="55%"><b>Key Technical Rationale & Scope</b></th>
  </tr>
  <tr>
    <td><a href="docs/decisions/0001-baseline-and-feasibility.md"><b>Baseline Environment and Feasibility Setup</b></a></td>
    <td>Repository initialization, Zig toolchain validation, and zero-telemetry operational constraints.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0002-pinned-zig-and-api-feasibility.md"><b>Pinned Compiler Version and API Feasibility</b></a></td>
    <td>Pins compiler to stable Zig 0.13.0 with zero external libc runtime dependencies.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0003-module-layout-and-build-system.md"><b>Subsystem Layout and Modular Build Architecture</b></a></td>
    <td>Decomposes WireScope into a standalone CLI client and embeddable native Zig library.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0004-typed-results-and-ownership-model.md"><b>Typed Results, Error Classification, and Memory Ownership</b></a></td>
    <td>Explicit allocator discipline, structured OutcomeCategory states, and zero-leak guarantees.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0005-cli-command-parser-and-exit-codes.md"><b>Command-Line Interface Engine and Exit Codes Contract</b></a></td>
    <td>Zero-dependency POSIX/GNU flag parser and standardized machine-readable exit codes.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0006-configuration-and-assessment-profiles.md"><b>Assessment Profiles and Scope Guard Enforcement</b></a></td>
    <td>Versioned JSON profile schemas, non-root constraints, and broad CIDR range defenses.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0007-network-interface-enumeration.md"><b>Network Interface Enumeration and OS Adapters</b></a></td>
    <td>Cross-platform adapter discovery via native Windows IP Helper, Linux sysfs, and BSD sockets.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0008-routing-table-and-gateway-inspection.md"><b>Routing Table and Default Gateway Discovery</b></a></td>
    <td>Kernel routing table inspection and active gateway discovery without shell execution.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0009-listening-services-inspection.md"><b>Local Listening Sockets and Port Inventory</b></a></td>
    <td>Active TCP/UDP listener discovery and non-root port exposure auditing.</td>
  </tr>
</table>

<br/>
</details>

<details>
<summary><b>📂 Network Transport Diagnostics & Probe Engines</b></summary>
<br/>

<table>
  <tr>
    <th width="45%"><b>Architecture Decision</b></th>
    <th width="55%"><b>Key Technical Rationale & Scope</b></th>
  </tr>
  <tr>
    <td><a href="docs/decisions/0010-probe-engine-scheduling-deadlines-and-cancellation.md"><b>Probe Engine Scheduling, Deadlines, and Cancellation</b></a></td>
    <td>Cooperative cancellation tokens, deadline bounds, and worker concurrency controls.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0011-normalized-timing-errors-and-operation-metadata.md"><b>Normalized Timing, Errors, and Operation Metadata</b></a></td>
    <td>High-resolution nanosecond timers and unified structured error classification.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0012-dns-resolution-and-failure-classification.md"><b>DNS Wire Protocol Parser and Failure Classification</b></a></td>
    <td>RFC 1035 wire parser, record decoding, and deterministic failure category mapping.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0013-dns-troubleshooting-and-resolver-comparison.md"><b>Resolver Disagreement Analysis and Troubleshooting</b></a></td>
    <td>Direct recursive query vs OS resolver arbitration with contextual guidance.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0014-tcp-connectivity-probes.md"><b>TCP Connectivity Probes and Lifecycle States</b></a></td>
    <td>Non-blocking socket state machine with immediate RST vs timeout differentiation.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0015-tcp-repeated-measurements-and-statistics.md"><b>Repeated Measurement Sampling and Latency Analysis</b></a></td>
    <td>Batched socket probing, jitter calculation (RFC 3550), and percentile statistics.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0016-actionable-connectivity-troubleshooting.md"><b>Actionable Network Connectivity Troubleshooting</b></a></td>
    <td>Rule-based diagnostic reasoning engine generating deterministic remediation advice.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0017-tls-certificate-and-hostname-validation.md"><b>TLS Certificate-Chain and Hostname Validation</b></a></td>
    <td>Pure Zig TLS handshakes, Subject Alternative Name (SAN) matching, and expiration checks.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0018-https-timing-and-bounded-response-handling.md"><b>HTTPS Connection Timing and Bounded Response Streaming</b></a></td>
    <td>Multi-stage connection phase measurements and bounded HTTP payload handling.</td>
  </tr>
</table>

<br/>
</details>

<details>
<summary><b>📂 Defensive Auditing, Exposure Analysis & Policy Governance</b></summary>
<br/>

<table>
  <tr>
    <th width="45%"><b>Architecture Decision</b></th>
    <th width="55%"><b>Key Technical Rationale & Scope</b></th>
  </tr>
  <tr>
    <td><a href="docs/decisions/0019-scope-validation-and-plan-preview.md"><b>Scope Boundary Enforcement and Dry-Run Planning</b></a></td>
    <td>Deterministic assessment plan preview and operator authorization boundary verification.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0020-bounded-host-discovery.md"><b>Bounded Target Discovery and Reachability States</b></a></td>
    <td>Target discovery restricted to explicit, bounded operator-configured targets.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0021-tcp-port-checks-and-conservative-service-identification.md"><b>Non-Invasive Port Checks and Service Identification</b></a></td>
    <td>Safe banner capture without invasive payloads, brute-force, or active fuzzing.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0022-asset-and-exposure-inventory.md"><b>Discovered Asset and Exposure Inventory</b></a></td>
    <td>Normalized structural inventory of verified addresses, ports, and listening daemons.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0023-http-security-configuration-auditor.md"><b>Defensive HTTP Security Header Auditing</b></a></td>
    <td>Evaluation of HSTS, CSP, Framing, and cookie attributes against security standards.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0024-local-exposure-auditor.md"><b>Defensive Host Exposure and Service Hardening</b></a></td>
    <td>Audit non-loopback bindings, plaintext transport, and privilege boundaries.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0025-versioned-local-rules-engine.md"><b>Declarative Local Security Rules Engine</b></a></td>
    <td>Structured, offline security rules schema with severity and confidence metrics.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0026-multi-module-assessment-orchestrator.md"><b>Multi-Module Diagnostic Assessment Orchestrator</b></a></td>
    <td>Coordinated diagnostic task execution with resource throttling and early termination.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0027-explicit-baselines-and-deterministic-diffs.md"><b>Network State Baselines and Drift Detection</b></a></td>
    <td>Point-in-time network state snapshots with deterministic delta comparisons.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0028-normalize-findings-and-remediation-tracking.md"><b>Normalized Findings and False-Positive Caveats</b></a></td>
    <td>Finding deduplication, remediation guidance, and transparent false-positive context.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0029-offline-policy-evaluation.md"><b>Offline Policy Evaluation and Compliance Gates</b></a></td>
    <td>Zero-cloud policy evaluation for local security audits and CI/CD verification gates.</td>
  </tr>
</table>

<br/>
</details>

<details>
<summary><b>📂 Local Persistence, Integrity Provenance & Simulation Lab</b></summary>
<br/>

<table>
  <tr>
    <th width="45%"><b>Architecture Decision</b></th>
    <th width="55%"><b>Key Technical Rationale & Scope</b></th>
  </tr>
  <tr>
    <td><a href="docs/decisions/0030-versioned-local-storage.md"><b>Atomic Local Storage and Data Layout</b></a></td>
    <td>Atomic write-to-temp-then-rename persistence within standard OS user app data directories.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0031-history-queries-retention-and-recovery.md"><b>History Queries, Retention Policies, and Recovery</b></a></td>
    <td>Query historical records, filter by tag/date, and prune aged assessments safely.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0032-report-integrity-manifests.md"><b>Cryptographic Artifact Provenance and Manifests</b></a></td>
    <td>SHA-256 cryptographic digests for report artifact provenance and tamper detection.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0033-versioned-json-reports.md"><b>Structured Machine-Readable JSON Reporting</b></a></td>
    <td>Strict JSON Schema Draft 7 reporting contracts for programmatic integration.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0034-markdown-and-terminal-reports.md"><b>Human-Readable Terminal and Markdown Reports</b></a></td>
    <td>Rich terminal formatting and GitHub-flavored markdown export generators.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0035-cli-automation-and-scripting-contracts.md"><b>CLI Automation, Piping, and Scripting Safety</b></a></td>
    <td>Pipe safety, non-interactive flags, deterministic formats, and machine exit codes.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0036-lab-lifecycle-and-isolation.md"><b>Practice Lab Lifecycle and Environment Isolation</b></a></td>
    <td>Isolated loopback daemon lifecycles with guaranteed resource cleanup.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0037-initial-diagnostic-and-defensive-exercises.md"><b>Defensive Practice Exercises and Scenarios</b></a></td>
    <td>Built-in drills for DNS failure, TCP refusal, unexpected listener, and HTTP violation.</td>
  </tr>
</table>

<br/>
</details>

<details>
<summary><b>📂 System Hardening, Verification & Delivery Pipeline</b></summary>
<br/>

<table>
  <tr>
    <th width="45%"><b>Architecture Decision</b></th>
    <th width="55%"><b>Key Technical Rationale & Scope</b></th>
  </tr>
  <tr>
    <td><a href="docs/decisions/0038-security-hardening-and-residual-risks.md"><b>System Hardening and Residual Risk Registry</b></a></td>
    <td>Fuzz testing engines, scope-escape defenses, and transparent residual risk documentation.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0039-platform-support-matrix-and-performance-validation.md"><b>Cross-Platform Compatibility and Performance Standards</b></a></td>
    <td>Cross-platform validation across Windows, Linux, and macOS environments.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0040-documentation-license-and-release-candidate.md"><b>Comprehensive Documentation and Release Packaging</b></a></td>
    <td>Release specifications, MIT licensing, and distribution packaging.</td>
  </tr>
  <tr>
    <td><a href="docs/decisions/0041-github-actions-ci-cd-and-v1.0-release-audit.md"><b>Automated CI/CD Workflows and Release Audit</b></a></td>
    <td>Multi-platform continuous integration, release artifact automation, and audit.</td>
  </tr>
</table>

<br/>
</details>

<a id="code-of-conduct"></a>
## 🤝 Code of Conduct

WireScope is dedicated to providing a welcoming, harassment-free community. We adhere to the **Contributor Covenant Code of Conduct v2.1**. Please review [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for standards, reporting, and enforcement details.

<br>

<a id="license"></a>
## 📜 License & Governance

- **License:** Licensed under the [MIT License](LICENSE).
- **Security Disclosures:** Review [SECURITY.md](SECURITY.md) for our coordinated vulnerability disclosure policy.
- **Contributing:** Review [CONTRIBUTING.md](CONTRIBUTING.md) for build, testing, and formatting guidelines.
- **Changelog:** Review [CHANGELOG.md](CHANGELOG.md) for complete version release notes.

<br>

<div align="center">
  <sub>Built with ⚡ in pure <b>Zig 0.13.0</b> · Zero Telemetry · Evidence-Driven · Deterministic Outcomes</sub>
</div>
