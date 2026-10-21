const std = @import("std");
const testing = std.testing;

pub const AssessmentStatus = enum {
    not_started,
    in_progress,
    completed,
    partial,
    cancelled,
    failed,
};

pub const TargetScope = struct {
    hosts: []const []const u8,
    ports: []const u16,
    max_operations: usize = 100,
};

test "assessment definitions compile" {
    const status = AssessmentStatus.not_started;
    try testing.expectEqual(AssessmentStatus.not_started, status);
}
