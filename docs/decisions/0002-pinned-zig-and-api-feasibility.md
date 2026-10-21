# Architecture Decision Record (ADR) 0002: Pinned Zig Version and API Feasibility Validation

## Status
Accepted

## Context
Phase 0.2 of Milestone 0 requires:
1. Pinning a stable release of the Zig compiler.
2. Validating uncertain standard library and OS APIs via small proof-of-concept programs.
3. Confirming API behavior and naming for the selected compiler version.
4. Defining which capabilities are directly implemented, which require platform adapters, and which utilize bounded subprocess fallbacks.
5. Establishing capability assumptions across Windows, Linux, and macOS.

## Decision

### 1. Pinned Compiler Version
- **Selected Version:** Zig `0.13.0` (Official Stable Release).
- **Target Architecture:** `x86_64-windows` (primary host development), with first-class cross-compilation targets for `x86_64-linux`, `aarch64-linux`, `x86_64-macos`, and `aarch64-macos`.
- **Installation & Provisioning:**
  - Archive: `https://ziglang.org/download/0.13.0/zig-windows-x86_64-0.13.0.zip`
  - Host Location: `D:\tools\zig-windows-x86_64-0.13.0`
  - PATH Configuration: Added to User PATH and shimmed in `.cargo/bin/zig.cmd` for direct shell execution.
  - Verification: `zig version` outputs `0.13.0`.

### 2. Standard Library & OS API Feasibility Results
All proof-of-concept programs were created under `poc/` and verified with `zig test` and `zig run`:

| API Domain | Zig Standard Library / OS Mechanism | Feasibility Status | Implementation Strategy |
| :--- | :--- | :--- | :--- |
| **Monotonic Timing** | `std.time.Timer`, `std.time.Instant`, `nanoTimestamp` | Verified | Direct Zig standard library. Uses Windows `QueryPerformanceCounter`, Linux `CLOCK_MONOTONIC`, and macOS `mach_absolute_time`. |
| **DNS Resolution** | `std.net.getAddressList` | Verified | Direct Zig standard library. Classifies `error.UnknownHostName` as NXDOMAIN. Multiple answers will be sorted deterministically. |
| **TCP Connectivity** | `std.net.Address.parseIp`, `std.net.tcpConnectToAddress` | Verified | Direct Zig standard library. Successfully distinguishes `connected`, `error.ConnectionRefused`, and timeouts on loopback fixtures. |
| **TLS & HTTPS** | `std.crypto.tls.Client`, `std.crypto.Certificate.Bundle` | Verified | Direct Zig standard library. System certificates loaded via `Certificate.Bundle.rescan()`. Test certificates managed locally. |
| **Network Interfaces** | Win32 `GetAdaptersAddresses` (`iphlpapi.dll`) | Verified | Platform adapter via Zig's native C ABI calling convention (`extern fn callconv(WINAPI)`), avoiding any external C wrapper library. Linux adapter to read Netlink/sysfs, macOS to use `getifaddrs`. |
| **Listener Inspection** | Win32 `GetExtendedTcpTable` + Bounded Subprocess Fallback (`netstat.exe -ano -p tcp`) | Verified | Platform adapter using native Win32 API with bounded child process execution (`std.process.Child`) as fallback. |
| **Cross-Compilation** | Zig built-in multi-target backend | Verified | Verified cross-compilation to `x86_64-linux` and `aarch64-macos` without external toolchains. |

### 3. Dependency Policy
- **Zero External Dependencies:** No external third-party libraries (no OpenSSL, no libcurl, no SQLite C libraries).
- All networking, cryptographic hashes, TLS parsing, and platform APIs will use Zig 0.13.0 standard library and native OS bindings.

### 4. Cross-Platform Capability Matrix & Assumptions

| Capability | Windows (Host) | Linux (Target) | macOS (Target) |
| :--- | :--- | :--- | :--- |
| **TCP / DNS Probes** | Native (`std.net`) | Native (`std.net`) | Native (`std.net`) |
| **TLS Diagnostics** | Native (`std.crypto.tls`) | Native (`std.crypto.tls`) | Native (`std.crypto.tls`) |
| **Interface Enumeration** | Native Win32 `iphlpapi` | Native Netlink / `/proc/net/dev` | Native `getifaddrs` |
| **Route Inspection** | Win32 `GetIpForwardTable2` | Netlink `RTM_GETROUTE` / `/proc/net/route` | Native `sysctl` / `netstat` fallback |
| **Listener Inspection** | Win32 `GetExtendedTcpTable` / `netstat` | `/proc/net/tcp` / `ss` fallback | `lsof` / `netstat` fallback |
| **Privilege Requirements** | Non-elevated for standard diagnostics | Non-root for standard diagnostics | Non-root for standard diagnostics |

## Consequences
- Pinned Zig 0.13.0 eliminates compiler API drift.
- Technical feasibility confirmed for all required Milestone 3–7 capabilities.
- Development proceeds to Milestone 1 (Project Skeleton and Core Contracts).
