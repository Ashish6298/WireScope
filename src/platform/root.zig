const std = @import("std");
const testing = std.testing;

pub const OsTag = @import("builtin").os.tag;

pub const types = @import("types.zig");
pub const NetworkInterface = types.NetworkInterface;
pub const InterfaceStatus = types.InterfaceStatus;
pub const InterfaceEnumerationResult = types.InterfaceEnumerationResult;

pub const windows = @import("windows.zig");
pub const linux = @import("linux.zig");
pub const macos = @import("macos.zig");

pub const PlatformInfo = struct {
    os_name: []const u8,
    is_supported: bool,
};

pub fn getPlatformInfo() PlatformInfo {
    return switch (OsTag) {
        .windows => .{ .os_name = "windows", .is_supported = true },
        .linux => .{ .os_name = "linux", .is_supported = true },
        .macos => .{ .os_name = "macos", .is_supported = true },
        else => .{ .os_name = "unknown", .is_supported = false },
    };
}

/// Enumerates network interfaces on the current host operating system
pub fn enumerateInterfaces(allocator: std.mem.Allocator) !InterfaceEnumerationResult {
    return switch (OsTag) {
        .windows => windows.enumerateInterfacesWindows(allocator),
        .linux => linux.enumerateInterfacesLinux(allocator),
        .macos => macos.enumerateInterfacesMacos(allocator),
        else => error.UnsupportedPlatformApi,
    };
}

test "platform adapter detects valid OS" {
    const info = getPlatformInfo();
    try testing.expect(info.is_supported);
}

test "real interface enumeration on current OS" {
    _ = types;
    _ = windows;
    _ = linux;
    _ = macos;

    var result = try enumerateInterfaces(testing.allocator);
    defer result.deinit(testing.allocator);

    // Host must report at least 1 interface (loopback or physical)
    try testing.expect(result.interfaces.len > 0);

    var has_loopback = false;
    for (result.interfaces) |iface| {
        try testing.expect(iface.name.len > 0);
        if (iface.is_loopback) {
            has_loopback = true;
        }
    }
    try testing.expect(has_loopback);

    // Test JSON and Terminal rendering
    var json_buf: [4096]u8 = undefined;
    var json_fbs = std.io.fixedBufferStream(&json_buf);
    try result.toJson(json_fbs.writer());
    try testing.expect(json_fbs.getWritten().len > 0);
    try testing.expect(std.mem.startsWith(u8, json_fbs.getWritten(), "{\"interfaces\":["));

    var term_buf: [4096]u8 = undefined;
    var term_fbs = std.io.fixedBufferStream(&term_buf);
    try result.toTerminal(term_fbs.writer());
    try testing.expect(term_fbs.getWritten().len > 0);
    try testing.expect(std.mem.startsWith(u8, term_fbs.getWritten(), "Network Interfaces"));
}
