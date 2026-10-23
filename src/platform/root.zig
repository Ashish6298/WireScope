const std = @import("std");
const testing = std.testing;

pub const OsTag = @import("builtin").os.tag;

pub const types = @import("types.zig");
pub const NetworkInterface = types.NetworkInterface;
pub const InterfaceStatus = types.InterfaceStatus;
pub const InterfaceEnumerationResult = types.InterfaceEnumerationResult;

pub const routes = @import("routes.zig");
pub const RouteEntry = routes.RouteEntry;
pub const RouteInspectionResult = routes.RouteInspectionResult;

pub const listeners = @import("listeners.zig");
pub const BindingType = listeners.BindingType;
pub const ListenerEntry = listeners.ListenerEntry;
pub const ListenerInspectionResult = listeners.ListenerInspectionResult;

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

/// Inspects routing table and default gateway on the current host operating system
pub fn inspectRoutes(allocator: std.mem.Allocator) !RouteInspectionResult {
    return switch (OsTag) {
        .windows => windows.inspectRoutesWindows(allocator),
        .linux => linux.inspectRoutesLinux(allocator),
        .macos => macos.inspectRoutesMacos(allocator),
        else => error.UnsupportedPlatformApi,
    };
}

/// Inspects local listening TCP sockets and classifies binding types
pub fn inspectListeners(allocator: std.mem.Allocator) !ListenerInspectionResult {
    return switch (OsTag) {
        .windows => windows.inspectListenersWindows(allocator),
        .linux => linux.inspectListenersLinux(allocator),
        .macos => macos.inspectListenersMacos(allocator),
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

    var result = enumerateInterfaces(testing.allocator) catch return error.SkipZigTest;
    defer result.deinit(testing.allocator);

    if (result.interfaces.len == 0) {
        return error.SkipZigTest;
    }

    var has_loopback = false;
    for (result.interfaces) |iface| {
        try testing.expect(iface.name.len > 0);
        if (iface.is_loopback) {
            has_loopback = true;
        }
    }
    if (!has_loopback) {
        return error.SkipZigTest;
    }

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

test "real route inspection on current OS" {
    _ = routes;

    var result = inspectRoutes(testing.allocator) catch return error.SkipZigTest;
    defer result.deinit(testing.allocator);

    if (result.routes.len == 0) {
        return error.SkipZigTest;
    }

    var json_buf: [8192]u8 = undefined;
    var json_fbs = std.io.fixedBufferStream(&json_buf);
    try result.toJson(json_fbs.writer());
    try testing.expect(json_fbs.getWritten().len > 0);
    try testing.expect(std.mem.startsWith(u8, json_fbs.getWritten(), "{\"default_gateway\":"));

    var term_buf: [8192]u8 = undefined;
    var term_fbs = std.io.fixedBufferStream(&term_buf);
    try result.toTerminal(term_fbs.writer());
    try testing.expect(term_fbs.getWritten().len > 0);
    try testing.expect(std.mem.startsWith(u8, term_fbs.getWritten(), "Routing Table"));
}

test "real listener inspection on current OS" {
    _ = listeners;

    const loopback = std.net.Address.parseIp("127.0.0.1", 0) catch return error.SkipZigTest;
    var server = loopback.listen(.{ .reuse_address = true }) catch return error.SkipZigTest;
    defer server.deinit();

    const actual_port = server.listen_address.getPort();

    var result = inspectListeners(testing.allocator) catch return error.SkipZigTest;
    defer result.deinit(testing.allocator);

    if (result.listeners.len == 0) {
        return error.SkipZigTest;
    }

    var found_our_port = false;
    for (result.listeners) |l| {
        if (l.local_port == actual_port) {
            found_our_port = true;
            try testing.expectEqual(BindingType.loopback_only, l.binding_type);
            break;
        }
    }

    if (!found_our_port) {
        return error.SkipZigTest;
    }

    var json_out = std.ArrayList(u8).init(testing.allocator);
    defer json_out.deinit();
    try result.toJson(json_out.writer());
    try testing.expect(json_out.items.len > 0);
    try testing.expect(std.mem.startsWith(u8, json_out.items, "{\"permission_limited\":"));

    var term_out = std.ArrayList(u8).init(testing.allocator);
    defer term_out.deinit();
    try result.toTerminal(term_out.writer());
    try testing.expect(term_out.items.len > 0);
    try testing.expect(std.mem.startsWith(u8, term_out.items, "Local Listening Services"));
}
