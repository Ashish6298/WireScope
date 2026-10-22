const std = @import("std");
const testing = std.testing;

pub const BindingType = enum {
    loopback_only,
    wildcard,
    specific_interface,

    pub fn toSlice(self: BindingType) []const u8 {
        return @tagName(self);
    }

    pub fn classify(addr: []const u8) BindingType {
        if (std.mem.startsWith(u8, addr, "127.") or
            std.mem.eql(u8, addr, "::1") or
            std.mem.eql(u8, addr, "localhost"))
        {
            return .loopback_only;
        }
        if (std.mem.eql(u8, addr, "0.0.0.0") or
            std.mem.eql(u8, addr, "::") or
            std.mem.eql(u8, addr, "0:0:0:0:0:0:0:0") or
            std.mem.eql(u8, addr, "*"))
        {
            return .wildcard;
        }
        return .specific_interface;
    }
};

pub const ListenerEntry = struct {
    transport: []const u8,
    local_address: []const u8,
    local_port: u16,
    binding_type: BindingType,
    pid: ?u32 = null,
    process_name: ?[]const u8 = null,

    pub fn clone(self: *const ListenerEntry, allocator: std.mem.Allocator) !ListenerEntry {
        return ListenerEntry{
            .transport = try allocator.dupe(u8, self.transport),
            .local_address = try allocator.dupe(u8, self.local_address),
            .local_port = self.local_port,
            .binding_type = self.binding_type,
            .pid = self.pid,
            .process_name = if (self.process_name) |p| try allocator.dupe(u8, p) else null,
        };
    }

    pub fn deinit(self: *ListenerEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.transport);
        allocator.free(self.local_address);
        if (self.process_name) |p| allocator.free(p);
    }
};

pub const ListenerInspectionResult = struct {
    listeners: []ListenerEntry,
    is_permission_limited: bool = false,

    pub fn deinit(self: *ListenerInspectionResult, allocator: std.mem.Allocator) void {
        for (self.listeners) |*l| {
            l.deinit(allocator);
        }
        allocator.free(self.listeners);
    }

    pub fn toJson(self: *const ListenerInspectionResult, writer: anytype) !void {
        try writer.print("{{\"permission_limited\":{s},\"listeners\":[", .{
            if (self.is_permission_limited) "true" else "false",
        });

        for (self.listeners, 0..) |l, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.print(
                \\{{"transport":"{s}","local_address":"{s}","local_port":{d},"binding_type":"{s}","pid":
            , .{
                l.transport,
                l.local_address,
                l.local_port,
                l.binding_type.toSlice(),
            });
            if (l.pid) |p| {
                try writer.print("{d}", .{p});
            } else {
                try writer.writeAll("null");
            }
            try writer.writeAll(",\"process_name\":");
            if (l.process_name) |pn| {
                try writer.print("\"{s}\"", .{pn});
            } else {
                try writer.writeAll("null");
            }
            try writer.writeAll("}");
        }
        try writer.writeAll("]}\n");
    }

    pub fn toTerminal(self: *const ListenerInspectionResult, writer: anytype) !void {
        try writer.print("Local Listening Services ({d} listeners detected):\n", .{self.listeners.len});
        try writer.writeAll("--------------------------------------------------------------------------------\n");
        if (self.is_permission_limited) {
            try writer.writeAll("  Notice: Some process metadata was restricted by OS permission limitations.\n\n");
        }

        try writer.print("  {s:<7} {s:<20} {s:<8} {s:<20} {s:<8}\n", .{
            "Proto", "Local Address", "Port", "Binding Type", "PID",
        });
        try writer.writeAll("  ----------------------------------------------------------------------------\n");

        for (self.listeners) |l| {
            var pid_buf: [16]u8 = undefined;
            const pid_str = if (l.pid) |p|
                std.fmt.bufPrint(&pid_buf, "{d}", .{p}) catch "-"
            else
                "-";

            try writer.print("  {s:<7} {s:<20} {d:<8} {s:<20} {s:<8}\n", .{
                l.transport,
                l.local_address,
                l.local_port,
                l.binding_type.toSlice(),
                pid_str,
            });
        }
        try writer.writeAll("\n");
    }
};

test "listener types and JSON rendering" {
    const allocator = testing.allocator;

    var listeners = try allocator.alloc(ListenerEntry, 3);
    listeners[0] = .{
        .transport = try allocator.dupe(u8, "tcp"),
        .local_address = try allocator.dupe(u8, "127.0.0.1"),
        .local_port = 8080,
        .binding_type = .loopback_only,
        .pid = 1234,
        .process_name = null,
    };
    listeners[1] = .{
        .transport = try allocator.dupe(u8, "tcp"),
        .local_address = try allocator.dupe(u8, "0.0.0.0"),
        .local_port = 80,
        .binding_type = .wildcard,
        .pid = 4,
        .process_name = null,
    };
    listeners[2] = .{
        .transport = try allocator.dupe(u8, "tcp"),
        .local_address = try allocator.dupe(u8, "192.168.1.50"),
        .local_port = 22,
        .binding_type = .specific_interface,
        .pid = 999,
        .process_name = null,
    };

    var res = ListenerInspectionResult{
        .listeners = listeners,
        .is_permission_limited = false,
    };
    defer res.deinit(allocator);

    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try res.toJson(fbs.writer());
    const json_str = fbs.getWritten();

    try testing.expect(std.mem.startsWith(u8, json_str, "{\"permission_limited\":false,\"listeners\":["));
    try testing.expect(std.mem.indexOf(u8, json_str, "loopback_only") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "wildcard") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "specific_interface") != null);
}

test "binding type classification" {
    // Wildcard bindings
    try testing.expectEqual(BindingType.wildcard, BindingType.classify("0.0.0.0"));
    try testing.expectEqual(BindingType.wildcard, BindingType.classify("::"));
    try testing.expectEqual(BindingType.wildcard, BindingType.classify("0:0:0:0:0:0:0:0"));
    try testing.expectEqual(BindingType.wildcard, BindingType.classify("*"));

    // Loopback bindings
    try testing.expectEqual(BindingType.loopback_only, BindingType.classify("127.0.0.1"));
    try testing.expectEqual(BindingType.loopback_only, BindingType.classify("127.0.0.2"));
    try testing.expectEqual(BindingType.loopback_only, BindingType.classify("::1"));
    try testing.expectEqual(BindingType.loopback_only, BindingType.classify("localhost"));

    // Specific interface bindings
    try testing.expectEqual(BindingType.specific_interface, BindingType.classify("192.168.1.100"));
    try testing.expectEqual(BindingType.specific_interface, BindingType.classify("10.0.0.1"));
    try testing.expectEqual(BindingType.specific_interface, BindingType.classify("fe80::1"));
}

test "empty listeners distinct from unable to inspect" {
    const allocator = testing.allocator;

    var empty_res = ListenerInspectionResult{
        .listeners = try allocator.alloc(ListenerEntry, 0),
        .is_permission_limited = false,
    };
    defer empty_res.deinit(allocator);

    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try empty_res.toJson(fbs.writer());
    try testing.expectEqualStrings("{\"permission_limited\":false,\"listeners\":[]}\n", fbs.getWritten());

    var term_buf: [512]u8 = undefined;
    var term_fbs = std.io.fixedBufferStream(&term_buf);
    try empty_res.toTerminal(term_fbs.writer());
    try testing.expect(std.mem.indexOf(u8, term_fbs.getWritten(), "0 listeners detected") != null);
    try testing.expect(std.mem.indexOf(u8, term_fbs.getWritten(), "Notice: Some process metadata was restricted") == null);

    // Permission limited case
    var limited_res = ListenerInspectionResult{
        .listeners = try allocator.alloc(ListenerEntry, 0),
        .is_permission_limited = true,
    };
    defer limited_res.deinit(allocator);

    var buf2: [256]u8 = undefined;
    var fbs2 = std.io.fixedBufferStream(&buf2);
    try limited_res.toJson(fbs2.writer());
    try testing.expectEqualStrings("{\"permission_limited\":true,\"listeners\":[]}\n", fbs2.getWritten());

    var term_buf2: [512]u8 = undefined;
    var term_fbs2 = std.io.fixedBufferStream(&term_buf2);
    try limited_res.toTerminal(term_fbs2.writer());
    try testing.expect(std.mem.indexOf(u8, term_fbs2.getWritten(), "Notice: Some process metadata was restricted") != null);
}
