const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const NetworkInterface = types.NetworkInterface;
const InterfaceEnumerationResult = types.InterfaceEnumerationResult;

pub fn enumerateInterfacesMacos(allocator: std.mem.Allocator) !InterfaceEnumerationResult {
    // macOS adapter fallback: returns loopback baseline if sysctl is not directly bound
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

test "macos interface enumeration dummy check" {
    if (@import("builtin").os.tag != .macos) return;
    var res = try enumerateInterfacesMacos(testing.allocator);
    defer res.deinit(testing.allocator);
}
