const std = @import("std");
const testing = std.testing;
const windows = std.os.windows;

const ULONG = windows.ULONG;
const DWORD = windows.DWORD;
const BOOL = windows.BOOL;
const WINAPI = windows.WINAPI;

pub const MIB_IPFORWARDROW = extern struct {
    dwForwardDest: DWORD,
    dwForwardMask: DWORD,
    dwForwardPolicy: DWORD,
    dwForwardNextHop: DWORD,
    dwForwardIfIndex: DWORD,
    dwForwardType: DWORD,
    dwForwardProto: DWORD,
    dwForwardAge: DWORD,
    dwForwardNextHopAS: DWORD,
    dwForwardMetric1: DWORD,
    dwForwardMetric2: DWORD,
    dwForwardMetric3: DWORD,
    dwForwardMetric4: DWORD,
    dwForwardMetric5: DWORD,
};

pub const MIB_IPFORWARDTABLE = extern struct {
    dwNumEntries: DWORD,
    table: [1]MIB_IPFORWARDROW,
};

pub extern "iphlpapi" fn GetIpForwardTable(
    pIpForwardTable: ?*MIB_IPFORWARDTABLE,
    pdwSize: *ULONG,
    bOrder: BOOL,
) callconv(WINAPI) DWORD;

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    if (@import("builtin").os.tag != .windows) {
        try stdout.print("Routes PoC: Non-Windows\n", .{});
        return;
    }

    var size: ULONG = 0;
    _ = GetIpForwardTable(null, &size, 0);

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const buffer = try allocator.alloc(u8, size);
    defer allocator.free(buffer);

    const table: *MIB_IPFORWARDTABLE = @ptrCast(@alignCast(buffer.ptr));
    const ret = GetIpForwardTable(table, &size, 0);

    try stdout.print("Routes PoC: GetIpForwardTable ret={d}, size={d}, entries={d}\n", .{
        ret, size, table.dwNumEntries,
    });
}
