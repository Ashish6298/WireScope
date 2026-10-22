const std = @import("std");
const testing = std.testing;

/// Granular probe-specific timing stages preserved distinctly from total elapsed duration
pub const TimingStages = struct {
    dns_lookup_ns: ?u64 = null,
    tcp_connect_ns: ?u64 = null,
    tls_handshake_ns: ?u64 = null,
    http_ttfb_ns: ?u64 = null,
    http_transfer_ns: ?u64 = null,
    total_elapsed_ns: u64 = 0,

    /// Deterministic serialization adhering to strictly fixed key ordering
    pub fn toJson(self: TimingStages, writer: anytype) !void {
        try writer.writeAll("{");
        var first = true;

        if (self.dns_lookup_ns) |dns| {
            if (!first) try writer.writeAll(",");
            first = false;
            try writer.print("\"dns_lookup_ns\":{d}", .{dns});
        }
        if (self.tcp_connect_ns) |tcp| {
            if (!first) try writer.writeAll(",");
            first = false;
            try writer.print("\"tcp_connect_ns\":{d}", .{tcp});
        }
        if (self.tls_handshake_ns) |tls| {
            if (!first) try writer.writeAll(",");
            first = false;
            try writer.print("\"tls_handshake_ns\":{d}", .{tls});
        }
        if (self.http_ttfb_ns) |ttfb| {
            if (!first) try writer.writeAll(",");
            first = false;
            try writer.print("\"http_ttfb_ns\":{d}", .{ttfb});
        }
        if (self.http_transfer_ns) |transfer| {
            if (!first) try writer.writeAll(",");
            first = false;
            try writer.print("\"http_transfer_ns\":{d}", .{transfer});
        }
        if (!first) try writer.writeAll(",");
        try writer.print("\"total_elapsed_ns\":{d}}}", .{self.total_elapsed_ns});
    }
};

/// Monotonic ID generator for traceable operation correlation
pub const OperationIdGenerator = struct {
    counter: std.atomic.Value(u64) = std.atomic.Value(u64).init(1),

    pub fn generate(self: *OperationIdGenerator, allocator: std.mem.Allocator, prefix: []const u8) ![]u8 {
        const id_num = self.counter.fetchAdd(1, .seq_cst);
        return std.fmt.allocPrint(allocator, "op_{s}_{d:0>6}", .{ prefix, id_num });
    }
};

test "timing stages deterministic serialization" {
    const stages = TimingStages{
        .dns_lookup_ns = 2500000,
        .tcp_connect_ns = 1800000,
        .tls_handshake_ns = 5400000,
        .http_ttfb_ns = 3200000,
        .http_transfer_ns = 1100000,
        .total_elapsed_ns = 14000000,
    };

    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try stages.toJson(fbs.writer());

    const expected = "{\"dns_lookup_ns\":2500000,\"tcp_connect_ns\":1800000,\"tls_handshake_ns\":5400000,\"http_ttfb_ns\":3200000,\"http_transfer_ns\":1100000,\"total_elapsed_ns\":14000000}";
    try testing.expectEqualStrings(expected, fbs.getWritten());
}

test "timing stages with partial stages serialization" {
    const stages = TimingStages{
        .tcp_connect_ns = 1200000,
        .total_elapsed_ns = 1200000,
    };

    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try stages.toJson(fbs.writer());

    const expected = "{\"tcp_connect_ns\":1200000,\"total_elapsed_ns\":1200000}";
    try testing.expectEqualStrings(expected, fbs.getWritten());
}

test "operation id generator sequencing" {
    var gen = OperationIdGenerator{};
    const id1 = try gen.generate(testing.allocator, "dns");
    defer testing.allocator.free(id1);
    const id2 = try gen.generate(testing.allocator, "tcp");
    defer testing.allocator.free(id2);

    try testing.expectEqualStrings("op_dns_000001", id1);
    try testing.expectEqualStrings("op_tcp_000002", id2);
}
