# Architecture Decision Record (ADR) 0009: Local Listening Services Inspection

## Status
Accepted

## Context
Phase 3.3 of Milestone 3 requires discovering local TCP listening services where OS APIs and permissions permit.
Requirements include:
1. Identifying local listening sockets (transport, local address, local port, binding classification, owning PID).
2. Classifying bindings into loopback-only (`127.0.0.0/8`, `::1`), wildcard (`0.0.0.0`, `::`), and specific interface bindings (`192.168.x.x`, `10.x.x.x`, etc.).
3. Distinguishing "No listeners found" from "unable to inspect" or permission-limited states.
4. Ensuring zero host configuration changes (read-only telemetry).
5. Implementing both native OS API access and safe, bounded subprocess fallbacks.
6. Supporting both clean, machine-readable JSON and formatted terminal table presentation.

## Decision

### 1. Data Model (`src/platform/listeners.zig`)
- `BindingType`: Enum with `.loopback_only`, `.wildcard`, `.specific_interface`.
  - `classify(addr)` helper evaluates IP strings against loopback, wildcard, and specific IP patterns.
- `ListenerEntry`: Holds transport protocol ("tcp"), allocated IP string, port number, `BindingType`, optional owning PID (`?u32`), and optional process name (`?[]const u8`). Full allocator-based ownership and deterministic `deinit()`.
- `ListenerInspectionResult`: Encapsulates an array of `ListenerEntry` and an `is_permission_limited: bool` flag.
  - `toJson()` serializes strict JSON: `{"permission_limited":false,"listeners":[...]}`.
  - `toTerminal()` formats a structured, human-readable console table with Proto, Local Address, Port, Binding Type, and PID.

### 2. Windows Implementation (`src/platform/windows.zig`)
- **Primary Native API**: Uses Win32 `GetExtendedTcpTable` from `iphlpapi.dll`.
  - Uses `TCP_TABLE_OWNER_PID_LISTENER` (constant value `3` from Win32 `TCP_TABLE_CLASS` enum).
  - Retrieves `MIB_TCPTABLE_OWNER_PID` containing `MIB_TCPROW_OWNER_PID` entries.
  - Extracts IPv4 addresses, network-byte-order port numbers (converted via `std.mem.bigToNative`), and owning process IDs.
  - Memory-safe double-call pattern: calls `GetExtendedTcpTable` with NULL buffer to obtain required buffer size, allocates with page alignment, and fills table.
- **Subprocess Fallback**:
  - Spawns `netstat.exe -ano -p tcp` via `std.process.Child` with argv list (no shell interpolation).
  - Enforces a strict 64 KB stdout read boundary.
  - Parses listening entries matching status `LISTENING`, tokenizing IP address, port, and PID.

### 3. Linux Implementation (`src/platform/linux.zig`)
- Reads `/proc/net/tcp` and `/proc/net/tcp6` directly without spawning external binaries.
- Parses hex IP addresses and ports, filtering for state `0A` (`TCP_LISTEN`).
- Converts hex addresses to human-readable dotted-decimal notation.
- Classifies binding types accordingly.

### 4. macOS Implementation (`src/platform/macos.zig`)
- Executes bounded fallback via `lsof -nP -iTCP -sTCP:LISTEN` or `netstat -an -p tcp`.
- Parses listening sockets and owning PIDs.

### 5. CLI Integration (`src/cli/args.zig`, `src/cli/root.zig`)
- Added `listeners` subcommand to the WireScope CLI.
- Integrated into `wirescope audit local` suite alongside interface enumeration (`interfaces`) and route inspection (`routes`).
- Supports `--format text` and `--format json`.

## Consequences
- WireScope can now audit all active TCP network listeners on Windows and Linux without modifying system state.
- Loopback-only vs. externally-exposed services (wildcard/specific IP) are immediately discernible, allowing security posture assessment.
- Pure read-only operation with zero privilege elevation required for standard socket discovery.
