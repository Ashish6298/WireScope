const std = @import("std");
const testing = std.testing;

pub const PlatformError = error{
    AccessDenied,
    PermissionDenied,
    SystemResources,
    UnsupportedPlatformApi,
    OutOfMemory,
};

pub const InterfaceStatus = enum {
    up,
    down,
    testing,
    unknown,
    dormant,
    not_present,
    lower_layer_down,

    pub fn toSlice(self: InterfaceStatus) []const u8 {
        return @tagName(self);
    }
};

pub const NetworkInterface = struct {
    name: []const u8,
    adapter_id: []const u8,
    display_name: []const u8,
    status: InterfaceStatus,
    is_loopback: bool,
    ipv4_addresses: [][]const u8,
    ipv6_addresses: [][]const u8,
    mac_address: ?[]const u8 = null,

    pub fn deinit(self: *NetworkInterface, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.adapter_id);
        allocator.free(self.display_name);
        for (self.ipv4_addresses) |addr| allocator.free(addr);
        allocator.free(self.ipv4_addresses);
        for (self.ipv6_addresses) |addr| allocator.free(addr);
        allocator.free(self.ipv6_addresses);
        if (self.mac_address) |mac| allocator.free(mac);
    }
};

pub const InterfaceEnumerationResult = struct {
    interfaces: []NetworkInterface,

    pub fn deinit(self: *InterfaceEnumerationResult, allocator: std.mem.Allocator) void {
        for (self.interfaces) |*iface| {
            iface.deinit(allocator);
        }
        allocator.free(self.interfaces);
    }

    pub fn toJson(self: *const InterfaceEnumerationResult, writer: anytype) !void {
        try writer.writeAll("{\"interfaces\":[");
        for (self.interfaces, 0..) |iface, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.print(
                \\{{"name":"{s}","adapter_id":"{s}","display_name":"{s}","status":"{s}","is_loopback":{s},"ipv4":[
            , .{
                iface.name,
                iface.adapter_id,
                iface.display_name,
                iface.status.toSlice(),
                if (iface.is_loopback) "true" else "false",
            });
            for (iface.ipv4_addresses, 0..) |addr, j| {
                if (j > 0) try writer.writeAll(",");
                try writer.print("\"{s}\"", .{addr});
            }
            try writer.writeAll("],\"ipv6\":[");
            for (iface.ipv6_addresses, 0..) |addr, j| {
                if (j > 0) try writer.writeAll(",");
                try writer.print("\"{s}\"", .{addr});
            }
            try writer.writeAll("],\"mac\":");
            if (iface.mac_address) |mac| {
                try writer.print("\"{s}\"", .{mac});
            } else {
                try writer.writeAll("null");
            }
            try writer.writeAll("}");
        }
        try writer.writeAll("]}\n");
    }

    pub fn toTerminal(self: *const InterfaceEnumerationResult, writer: anytype) !void {
        try writer.print("Network Interfaces ({d} detected):\n", .{self.interfaces.len});
        try writer.writeAll("--------------------------------------------------------------------------------\n");
        for (self.interfaces) |iface| {
            try writer.print("  Interface:    {s} ({s})\n", .{ iface.display_name, iface.name });
            try writer.print("    Status:     {s} | Loopback: {s}\n", .{
                iface.status.toSlice(),
                if (iface.is_loopback) "yes" else "no",
            });
            if (iface.mac_address) |mac| {
                try writer.print("    MAC:        {s}\n", .{mac});
            }
            if (iface.ipv4_addresses.len > 0) {
                try writer.writeAll("    IPv4:       ");
                for (iface.ipv4_addresses, 0..) |addr, idx| {
                    if (idx > 0) try writer.writeAll(", ");
                    try writer.writeAll(addr);
                }
                try writer.writeAll("\n");
            }
            if (iface.ipv6_addresses.len > 0) {
                try writer.writeAll("    IPv6:       ");
                for (iface.ipv6_addresses, 0..) |addr, idx| {
                    if (idx > 0) try writer.writeAll(", ");
                    try writer.writeAll(addr);
                }
                try writer.writeAll("\n");
            }
            try writer.writeAll("\n");
        }
    }
};

test "interface types and JSON rendering" {
    const allocator = testing.allocator;

    var ipv4 = try allocator.alloc([]const u8, 1);
    ipv4[0] = try allocator.dupe(u8, "127.0.0.1");

    var ipv6 = try allocator.alloc([]const u8, 1);
    ipv6[0] = try allocator.dupe(u8, "::1");

    var ifaces = try allocator.alloc(NetworkInterface, 1);
    ifaces[0] = .{
        .name = try allocator.dupe(u8, "lo0"),
        .adapter_id = try allocator.dupe(u8, "loopback_1"),
        .display_name = try allocator.dupe(u8, "Loopback Interface"),
        .status = .up,
        .is_loopback = true,
        .ipv4_addresses = ipv4,
        .ipv6_addresses = ipv6,
        .mac_address = try allocator.dupe(u8, "00:00:00:00:00:00"),
    };

    var res = InterfaceEnumerationResult{ .interfaces = ifaces };
    defer res.deinit(allocator);

    var buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try res.toJson(fbs.writer());
    const json_str = fbs.getWritten();
    try testing.expect(std.mem.startsWith(u8, json_str, "{\"interfaces\":["));
    try testing.expect(std.mem.indexOf(u8, json_str, "127.0.0.1") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "::1") != null);
}
