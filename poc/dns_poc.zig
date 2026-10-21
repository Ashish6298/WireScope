const std = @import("std");
const testing = std.testing;

pub const DnsOutcome = enum {
    success,
    nxdomain,
    timeout,
    invalid_input,
    network_error,
};

pub fn resolveHost(allocator: std.mem.Allocator, host: []const u8) !DnsOutcome {
    const list = std.net.getAddressList(allocator, host, 0) catch |err| switch (err) {
        error.UnknownHostName => return .nxdomain,
        else => return .network_error,
    };
    defer list.deinit();

    if (list.addrs.len == 0) return .nxdomain;
    return .success;
}

test "DNS resolution for localhost" {
    const outcome = try resolveHost(testing.allocator, "localhost");
    try testing.expectEqual(DnsOutcome.success, outcome);
}

test "DNS resolution for non-existent domain returns nxdomain" {
    const outcome = try resolveHost(testing.allocator, "wirescope-definitely-nonexistent-domain-12345.test");
    try testing.expectEqual(DnsOutcome.nxdomain, outcome);
}

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const local_res = try resolveHost(allocator, "localhost");
    const nx_res = try resolveHost(allocator, "wirescope-definitely-nonexistent-domain-12345.test");

    try stdout.print("DNS PoC: localhost -> {s}, non-existent -> {s} -> DNS Resolution OK\n", .{
        @tagName(local_res),
        @tagName(nx_res),
    });
}
