# Architecture Decision Record (ADR) 0007: Network Interface Enumeration and Platform Adapters

## Status
Accepted

## Context
Phase 3.1 of Milestone 3 requires implementing platform adapters to enumerate actual network interfaces and available metadata (interface name/ID, operational status, IPv4/IPv6 addresses, MAC addresses, loopback identification). The implementation must:
1. Return real data on supported operating systems without fabricating records or mock data.
2. Distinguish missing/empty results from permission errors and API failures.
3. Support both human-readable terminal output and machine-readable JSON.
4. Require zero elevated/root privileges for standard interface inspection.

## Decision

### 1. Platform Adapter Architecture
Structured under `src/platform/`:
- `types.zig`: Common data contracts (`NetworkInterface`, `InterfaceStatus`, `InterfaceEnumerationResult`, and formatting methods `toJson()`, `toTerminal()`).
- `windows.zig`: Win32 adapter calling `GetAdaptersAddresses` from `iphlpapi.dll` using native Zig C ABI declarations (`callconv(std.os.windows.WINAPI)`).
- `linux.zig`: Linux adapter iterating `/sys/class/net/` and inspecting `operstate`.
- `macos.zig`: macOS adapter structure and fallback.
- `root.zig`: Top-level platform dispatcher routing `enumerateInterfaces(allocator)` based on `@import("builtin").os.tag`.

### 2. Windows Native Implementation
- Invokes `GetAdaptersAddresses` with `AF_UNSPEC` and skips multicast/DNS server lists for optimal performance.
- Handles buffer sizing dynamically (`ERROR_BUFFER_OVERFLOW` triggers automatic buffer reallocation).
- Unpacks `IP_ADAPTER_ADDRESSES` and `IP_ADAPTER_UNICAST_ADDRESS` linked lists:
  - IPv4 addresses extracted from `sockaddr_in`.
  - IPv6 addresses extracted from `sockaddr_in6`.
  - Converts wide string (`PWCHAR`) Friendly Name and Description to UTF-8 using `std.unicode.utf16LeToUtf8Alloc`.
  - Detects software loopback via `IfType == IF_TYPE_SOFTWARE_LOOPBACK` (24).
  - Formats physical MAC addresses (`PhysicalAddress[0..6]`) for non-loopback adapters.

### 3. Error Disambiguation
- `ERROR_NO_DATA`: Returns an empty interface list (clean empty result).
- `ERROR_ACCESS_DENIED`: Returns `error.AccessDenied` (distinguishable from empty data).
- General failures: Return `error.ApiFailure`.
- Unsupported platforms: Return `error.UnsupportedPlatformApi`.

## Consequences
- Real interface telemetry gathered directly from the operating system with zero external C wrapper libraries.
- Accurate distinction between physical, virtual (e.g., Hyper-V/WSL), and loopback adapters.
- Deterministic, leak-free memory reclamation verified via `testing.allocator`.
