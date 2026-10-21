const std = @import("std");
const testing = std.testing;
const core = @import("../core/root.zig");

pub const ProbeType = enum {
    dns,
    tcp,
    tls,
    http,
};

pub const ProbeConfig = struct {
    timeout_ms: u32 = 5000,
    max_retries: u8 = 1,
};

test "probes definitions compile" {
    const config = ProbeConfig{};
    try testing.expectEqual(@as(u32, 5000), config.timeout_ms);
}
