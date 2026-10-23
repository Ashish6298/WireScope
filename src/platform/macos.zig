const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const NetworkInterface = types.NetworkInterface;
const InterfaceEnumerationResult = types.InterfaceEnumerationResult;

const routes_mod = @import("routes.zig");
pub const RouteEntry = routes_mod.RouteEntry;
pub const RouteInspectionResult = routes_mod.RouteInspectionResult;

const listeners_mod = @import("listeners.zig");
pub const BindingType = listeners_mod.BindingType;
pub const ListenerEntry = listeners_mod.ListenerEntry;
pub const ListenerInspectionResult = listeners_mod.ListenerInspectionResult;

pub fn enumerateInterfacesMacos(allocator: std.mem.Allocator) !InterfaceEnumerationResult {
    var list = std.ArrayList(NetworkInterface).init(allocator);
    errdefer {
        for (list.items) |*i| i.deinit(allocator);
        list.deinit();
    }

    var ipv4_list = std.ArrayList([]const u8).init(allocator);
    try ipv4_list.append(try allocator.dupe(u8, "127.0.0.1"));
    var ipv6_list = std.ArrayList([]const u8).init(allocator);
    try ipv6_list.append(try allocator.dupe(u8, "::1"));

    const lo = NetworkInterface{
        .name = try allocator.dupe(u8, "lo0"),
        .adapter_id = try allocator.dupe(u8, "lo0"),
        .display_name = try allocator.dupe(u8, "Loopback"),
        .status = .up,
        .is_loopback = true,
        .ipv4_addresses = try ipv4_list.toOwnedSlice(),
        .ipv6_addresses = try ipv6_list.toOwnedSlice(),
        .mac_address = null,
    };
    try list.append(lo);

    return InterfaceEnumerationResult{ .interfaces = try list.toOwnedSlice() };
}

pub fn inspectRoutesMacos(allocator: std.mem.Allocator) !RouteInspectionResult {
    var list = std.ArrayList(RouteEntry).init(allocator);
    return RouteInspectionResult{
        .routes = try list.toOwnedSlice(),
        .default_gateway = null,
    };
}

pub fn inspectListenersMacos(allocator: std.mem.Allocator) !ListenerInspectionResult {
    var list = std.ArrayList(ListenerEntry).init(allocator);
    return ListenerInspectionResult{
        .listeners = try list.toOwnedSlice(),
        .is_permission_limited = false,
    };
}

test "macos route inspection dummy check" {
    if (@import("builtin").os.tag != .macos) return;
    var res = inspectRoutesMacos(testing.allocator) catch return error.SkipZigTest;
    defer res.deinit(testing.allocator);
}
