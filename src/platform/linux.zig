const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const NetworkInterface = types.NetworkInterface;
const InterfaceStatus = types.InterfaceStatus;
const InterfaceEnumerationResult = types.InterfaceEnumerationResult;

pub fn enumerateInterfacesLinux(allocator: std.mem.Allocator) !InterfaceEnumerationResult {
    var dir = std.fs.openDirAbsolute("/sys/class/net", .{ .iterate = true }) catch {
        // Fallback or permission limitation
        var list = std.ArrayList(NetworkInterface).init(allocator);
        return InterfaceEnumerationResult{ .interfaces = try list.toOwnedSlice() };
    };
    defer dir.close();

    var list = std.ArrayList(NetworkInterface).init(allocator);
    errdefer {
        for (list.items) |*i| i.deinit(allocator);
        list.deinit();
    }

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .sym_link and entry.kind != .directory) continue;

        const iface_name = try allocator.dupe(u8, entry.name);
        errdefer allocator.free(iface_name);

        const is_lo = std.mem.eql(u8, entry.name, "lo");

        // Read operstate if present
        var status: InterfaceStatus = .unknown;
        var operstate_file = dir.openFile(try std.fmt.allocPrint(allocator, "{s}/operstate", .{entry.name}), .{}) catch null;
        if (operstate_file) |*f| {
            defer f.close();
            var state_buf: [32]u8 = undefined;
            const len = f.readAll(&state_buf) catch 0;
            const state_str = std.mem.trim(u8, state_buf[0..len], " \r\n");
            if (std.mem.eql(u8, state_str, "up")) {
                status = .up;
            } else if (std.mem.eql(u8, state_str, "down")) {
                status = .down;
            }
        }

        var ipv4_list = std.ArrayList([]const u8).init(allocator);
        var ipv6_list = std.ArrayList([]const u8).init(allocator);

        if (is_lo) {
            try ipv4_list.append(try allocator.dupe(u8, "127.0.0.1"));
            try ipv6_list.append(try allocator.dupe(u8, "::1"));
            status = .up;
        }

        const iface = NetworkInterface{
            .name = iface_name,
            .adapter_id = try allocator.dupe(u8, iface_name),
            .display_name = try allocator.dupe(u8, iface_name),
            .status = status,
            .is_loopback = is_lo,
            .ipv4_addresses = try ipv4_list.toOwnedSlice(),
            .ipv6_addresses = try ipv6_list.toOwnedSlice(),
            .mac_address = null,
        };

        try list.append(iface);
    }

    return InterfaceEnumerationResult{ .interfaces = try list.toOwnedSlice() };
}

test "linux interface enumeration dummy check" {
    if (@import("builtin").os.tag != .linux) return;
    var res = try enumerateInterfacesLinux(testing.allocator);
    defer res.deinit(testing.allocator);
}
