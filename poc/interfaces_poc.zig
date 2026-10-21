const std = @import("std");
const testing = std.testing;
const windows = std.os.windows;

// Win32 IP Helper API definitions for GetAdaptersAddresses
const ULONG = windows.ULONG;
const DWORD = windows.DWORD;
const PVOID = windows.PVOID;
const WINAPI = windows.WINAPI;

pub const AF_UNSPEC: ULONG = 0;
pub const GAA_FLAG_INCLUDE_PREFIX: ULONG = 0x0010;
pub const ERROR_SUCCESS: ULONG = 0;
pub const ERROR_BUFFER_OVERFLOW: ULONG = 111;

pub const IP_ADAPTER_ADDRESSES = extern struct {
    Length: ULONG,
    IfIndex: DWORD,
    Next: ?*IP_ADAPTER_ADDRESSES,
    AdapterName: [*:0]u8,
    // Additional fields omitted for basic enumeration test
};

pub extern "iphlpapi" fn GetAdaptersAddresses(
    Family: ULONG,
    Flags: ULONG,
    Reserved: ?PVOID,
    AdapterAddresses: ?*IP_ADAPTER_ADDRESSES,
    SizePointer: *ULONG,
) callconv(WINAPI) ULONG;

test "Win32 GetAdaptersAddresses API can be called safely" {
    if (@import("builtin").os.tag != .windows) return;

    var size_needed: ULONG = 0;
    const res = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, null, null, &size_needed);
    // Buffer overflow (111) is expected when querying size
    try testing.expect(res == ERROR_BUFFER_OVERFLOW or res == ERROR_SUCCESS or size_needed > 0);
}

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    if (@import("builtin").os.tag != .windows) {
        try stdout.print("Interfaces PoC: Non-Windows platform\n", .{});
        return;
    }

    var size_needed: ULONG = 0;
    const res = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, null, null, &size_needed);
    try stdout.print("Interfaces PoC: GetAdaptersAddresses returned {d}, required size: {d} bytes -> Native Win32 OK\n", .{ res, size_needed });
}
