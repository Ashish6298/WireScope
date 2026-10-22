# Architecture Decision Record (ADR) 0008: Routing Table and Default Gateway Inspection

## Status
Accepted

## Context
Phase 3.2 of Milestone 3 requires inspecting local routing tables and identifying default gateways using documented OS APIs where practical, complemented by an isolated, bounded subprocess fallback. The design must:
1. Return real route telemetry without fabricating default routes or gateways.
2. Isolate fallback subprocess execution, using fixed argument arrays, avoiding shell interpolation, and enforcing strict buffer boundaries (64 KB).
3. Report platform limitations and missing privileges distinctly.
4. Provide both machine-readable JSON and human-readable terminal output.

## Decision

### 1. Routing Model
Defined in `src/platform/routes.zig`:
- `RouteEntry`: Destination prefix (CIDR notation), Next Hop (IP address or "On-link"), interface index, metric, `is_default_gateway` flag, and routing protocol (`local`, `netmgmt`, `kernel`, etc.).
- `RouteInspectionResult`: Holds an array of `RouteEntry` and an optional `default_gateway` IP string. Includes `toJson()` and `toTerminal()` formatting methods.

### 2. Windows Native Implementation (`src/platform/windows.zig`)
- Uses `iphlpapi.dll`'s `GetIpForwardTable` API via native Zig C ABI declarations.
- Maps `MIB_IPFORWARDTABLE` and `MIB_IPFORWARDROW`:
  - `dwForwardDest` and `dwForwardMask` are converted to CIDR notation using `@popCount(dwForwardMask)`.
  - Next hop is resolved to an IPv4 string or marked as `"On-link"`.
  - Protocol is decoded from `dwForwardProto` (e.g. `netmgmt`, `local`, `icmp`).
  - Default gateway is extracted strictly when destination is `0.0.0.0/0` and next hop is an active gateway IP.
- Bounded Subprocess Fallback (`inspectRoutesSubprocessFallback`):
  - Spawns `route.exe print -4` directly via `std.process.Child` with no shell interpolation.
  - Enforces a 64 KB maximum buffer cap on stdout.
  - Parses default gateway from route output safely.

### 3. Linux Implementation (`src/platform/linux.zig`)
- Reads `/proc/net/route` directly without spawning child processes.
- Parses destination, gateway, mask, metric, and flags.

### 4. Non-Fabrication Policy
- If no default route is observed in the routing table, `default_gateway` remains `null`.
- Inconclusive or empty routing tables are never populated with fabricated dummy gateways.

## Consequences
- Accurate discovery of host default gateway and routing topology.
- Resilient dual-path architecture on Windows (native Win32 API primary + bounded subprocess fallback).
- Zero elevated privileges required.
