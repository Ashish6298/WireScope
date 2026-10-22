const std = @import("std");
const testing = std.testing;

pub const RouteEntry = struct {
    destination: []const u8,
    next_hop: []const u8,
    interface_index: u32,
    metric: u32,
    is_default_gateway: bool,
    protocol: []const u8,

    pub fn deinit(self: *RouteEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.destination);
        allocator.free(self.next_hop);
        allocator.free(self.protocol);
    }
};

pub const RouteInspectionResult = struct {
    routes: []RouteEntry,
    default_gateway: ?[]const u8 = null,

    pub fn deinit(self: *RouteInspectionResult, allocator: std.mem.Allocator) void {
        for (self.routes) |*r| {
            r.deinit(allocator);
        }
        allocator.free(self.routes);
        if (self.default_gateway) |gw| allocator.free(gw);
    }

    pub fn toJson(self: *const RouteInspectionResult, writer: anytype) !void {
        try writer.writeAll("{\"default_gateway\":");
        if (self.default_gateway) |gw| {
            try writer.print("\"{s}\"", .{gw});
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(",\"routes\":[");

        for (self.routes, 0..) |r, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.print(
                \\{{"destination":"{s}","next_hop":"{s}","interface_index":{d},"metric":{d},"is_default_gateway":{s},"protocol":"{s}"}}
            , .{
                r.destination,
                r.next_hop,
                r.interface_index,
                r.metric,
                if (r.is_default_gateway) "true" else "false",
                r.protocol,
            });
        }
        try writer.writeAll("]}\n");
    }

    pub fn toTerminal(self: *const RouteInspectionResult, writer: anytype) !void {
        try writer.print("Routing Table ({d} routes detected):\n", .{self.routes.len});
        try writer.writeAll("--------------------------------------------------------------------------------\n");
        if (self.default_gateway) |gw| {
            try writer.print("  Default Gateway:  {s}\n\n", .{gw});
        } else {
            try writer.writeAll("  Default Gateway:  None detected\n\n");
        }

        try writer.print("  {s:<22} {s:<20} {s:<10} {s:<8} {s:<8}\n", .{
            "Destination", "Next Hop", "Interface", "Metric", "Default",
        });
        try writer.writeAll("  ----------------------------------------------------------------------------\n");

        for (self.routes) |r| {
            try writer.print("  {s:<22} {s:<20} {d:<10} {d:<8} {s:<8}\n", .{
                r.destination,
                r.next_hop,
                r.interface_index,
                r.metric,
                if (r.is_default_gateway) "yes" else "no",
            });
        }
        try writer.writeAll("\n");
    }
};

test "route types and JSON rendering" {
    const allocator = testing.allocator;

    var routes = try allocator.alloc(RouteEntry, 2);
    routes[0] = .{
        .destination = try allocator.dupe(u8, "0.0.0.0/0"),
        .next_hop = try allocator.dupe(u8, "192.168.1.1"),
        .interface_index = 10,
        .metric = 25,
        .is_default_gateway = true,
        .protocol = try allocator.dupe(u8, "netmgmt"),
    };
    routes[1] = .{
        .destination = try allocator.dupe(u8, "127.0.0.1/32"),
        .next_hop = try allocator.dupe(u8, "On-link"),
        .interface_index = 1,
        .metric = 256,
        .is_default_gateway = false,
        .protocol = try allocator.dupe(u8, "local"),
    };

    var res = RouteInspectionResult{
        .routes = routes,
        .default_gateway = try allocator.dupe(u8, "192.168.1.1"),
    };
    defer res.deinit(allocator);

    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try res.toJson(fbs.writer());
    const json_str = fbs.getWritten();
    try testing.expect(std.mem.startsWith(u8, json_str, "{\"default_gateway\":\"192.168.1.1\",\"routes\":["));
    try testing.expect(std.mem.indexOf(u8, json_str, "0.0.0.0/0") != null);
}
