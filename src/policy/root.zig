const std = @import("std");
const testing = std.testing;

pub const PolicyOutcome = enum {
    pass,
    fail,
    inconclusive,
    not_applicable,
};

pub const Rule = struct {
    id: []const u8,
    version: u32,
    title: []const u8,
    description: []const u8,
};

test "policy definitions compile" {
    const outcome = PolicyOutcome.pass;
    try testing.expectEqual(PolicyOutcome.pass, outcome);
}
