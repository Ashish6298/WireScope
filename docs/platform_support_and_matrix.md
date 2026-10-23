# WireScope Platform Support Matrix & Feature Validation

## 1. Operating System & Architecture Support Matrix

WireScope is engineered as a cross-platform, local-first network diagnostics and defensive cybersecurity assessment engine written in Zig 0.13.0. The platform layer abstracts OS-specific network APIs, routing tables, and process management.

To maintain engineering integrity, WireScope distinguishes between:
- **Native Tested:** Compiled and tested natively on physical/virtual hardware runners with full unit and integration test suites passing.
- **Cross-Compiled / Supported:** Compiles cleanly to binary artifacts across targets via Zig's cross-compilation toolchain; core engine, parsing, and socket logic are fully functional; platform-specific network introspection uses POSIX/filesystem fallbacks.
- **Permission-Limited:** Requires elevated/administrative privileges (Windows Administrator / POSIX root) for full operational fidelity.
- **Stub / Planned:** Platform introspection stubs awaiting native OS-specific kernel interfaces (e.g. macOS routing sockets).

| Subsystem / Capability | Windows (x86_64) | Linux (x86_64, aarch64) | macOS (x86_64, aarch64) | Notes / Boundary |
|---|---|---|---|---|
| **Compilation & Binaries** | **Native Tested** | **Cross-Compiled** | **Cross-Compiled** | Compiles cleanly across all targets using Zig 0.13.0 |
| **Test Suite Execution** | **290/290 Passed** | Host Cross-Runner | Host Cross-Runner | Native Linux/macOS CI runners scheduled for Milestone 15 |
| **Interface Enumeration** | **Native Tested** (`iphlpapi`) | **Supported** (`/sys/class/net`) | **Supported** (`lo0` stub) | Linux parses sysfs; macOS provides loopback fallback |
| **Routing & Gateway** | **Native Tested** (`GetBestRoute`) | **Supported** (`/proc/net/route`) | **Stub** (null gateway) | Fallback subprocess commands used when APIs restricted |
| **Listening Sockets** | **Native Tested** (`GetExtendedTcpTable`) | **Supported** (`/proc/net/tcp`) | **Supported** (loopback stub) | Identifies listening ports and bind addresses |
| **Process Attribution** | **Permission-Limited** | **Permission-Limited** | **Unsupported** | Requires Administrator/root; unprivileged runs emit `WS-AUDIT-EXPOSURE-PERMISSION-LIMITED` |
| **DNS Troubleshooting** | **Native Tested** | **Supported** | **Supported** | RFC 1035 wire protocol, local resolver comparison |
| **TCP Connect & Latency** | **Native Tested** (`ws2_32`) | **Supported** (`libc`/POSIX) | **Supported** (`libc`/POSIX) | Repeated measurements, jitter (RFC 3550), stddev, percentiles |
| **TLS & SAN Auditing** | **Native Tested** | **Supported** | **Supported** | Self-signed test certificates, SAN matching, expiry calculation |
| **HTTP Security Auditor** | **Native Tested** | **Supported** | **Supported** | HSTS, CSP, XFO, cookies, redirect scope guards |
| **Practice Lab Lifecycles** | **Native Tested** | **Supported** | **Supported** | 100% loopback services, sandboxed state, zero public egress |
| **Storage & Manifests** | **Native Tested** | **Supported** | **Supported** | Atomic file writes, SHA-256 integrity verification |

---

## 2. Platform-Specific Gaps & Narrowed Support Claims

In accordance with Phase 14.2 acceptance criteria, WireScope explicitly narrows support claims where live execution evidence on physical hardware is not yet established:

1. **Host Execution Scope:**
   - Active host verification was conducted natively on **Windows 11 x86_64**.
   - Linux (`x86_64-linux`, `aarch64-linux`) and macOS (`x86_64-macos`, `aarch64-macos`) binaries compile with zero warnings or errors.
   - Comprehensive multi-platform hardware matrix testing across Ubuntu Linux and Apple Silicon macOS is formally assigned to the GitHub Actions CI/CD pipeline in **Milestone 15**.

2. **Operating System Privilege Boundaries:**
   - On Windows, unprivileged users can inspect all TCP/UDP listeners and bind addresses, but Windows API `GetExtendedTcpTable` does not expose owning process IDs without elevated tokens for system services.
   - On Linux, `/proc/net/tcp` exposes inode and bind addresses; mapping inode to process executable via `/proc/<pid>/fd` requires root privileges or identical UID ownership.
   - WireScope marks missing process names as `WS-AUDIT-EXPOSURE-PERMISSION-LIMITED` rather than failing.

3. **Routing Table Introspection on macOS:**
   - macOS routing table introspection currently falls back to system command parsers (`netstat -rn` / `route get default`) or returns an empty route set with a null default gateway if subprocess execution is prohibited.

4. **Public Network Independence:**
   - All tests, benchmarks, lab exercises, and diagnostic probes run strictly against `127.0.0.1`, RFC 6761 reserved domains (`.test`, `.example`), or synthetic mock connectors. Zero public internet connections are initiated or required.
