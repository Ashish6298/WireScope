const std = @import("std");
const testing = std.testing;
const core = @import("../core/root.zig");

pub const types = @import("types.zig");
pub const engine = @import("engine.zig");

pub const ProbeEngine = engine.ProbeEngine;
pub const EngineConfig = types.EngineConfig;
pub const EngineMetrics = types.EngineMetrics;
pub const CancellationToken = types.CancellationToken;
pub const WorkStatus = types.WorkStatus;
pub const TaskDescriptor = types.TaskDescriptor;
pub const TaskRecord = types.TaskRecord;
pub const TaskFn = types.TaskFn;

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

test "probes root exports engine and types" {
    _ = types;
    _ = engine;
    const config = ProbeConfig{};
    try testing.expectEqual(@as(u32, 5000), config.timeout_ms);
}
