const std = @import("std");
const testing = std.testing;

/// Injectable clock interface enabling deterministic test seams for timing and deadlines
pub const Clock = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        nowMs: *const fn (ctx: *anyopaque) i64,
        monotonicNs: *const fn (ctx: *anyopaque) u64,
    };

    pub fn nowMs(self: Clock) i64 {
        return self.vtable.nowMs(self.ptr);
    }

    pub fn monotonicNs(self: Clock) u64 {
        return self.vtable.monotonicNs(self.ptr);
    }
};

/// Default system clock backed by standard OS time APIs
pub const SystemClock = struct {
    fn nowMs(_: *anyopaque) i64 {
        return std.time.milliTimestamp();
    }

    fn monotonicNs(_: *anyopaque) u64 {
        return @as(u64, @intCast(@max(0, std.time.nanoTimestamp())));
    }

    const default_vtable: Clock.VTable = .{
        .nowMs = nowMs,
        .monotonicNs = monotonicNs,
    };

    pub fn clock() Clock {
        return .{
            .ptr = undefined,
            .vtable = &default_vtable,
        };
    }
};

/// Mock clock for deterministic unit and regression testing
pub const MockClock = struct {
    current_ms: i64 = 1700000000000,
    current_ns: u64 = 10000000,

    fn nowMs(ctx: *anyopaque) i64 {
        const self: *MockClock = @ptrCast(@alignCast(ctx));
        return self.current_ms;
    }

    fn monotonicNs(ctx: *anyopaque) u64 {
        const self: *MockClock = @ptrCast(@alignCast(ctx));
        return self.current_ns;
    }

    const mock_vtable: Clock.VTable = .{
        .nowMs = nowMs,
        .monotonicNs = monotonicNs,
    };

    pub fn clock(self: *MockClock) Clock {
        return .{
            .ptr = self,
            .vtable = &mock_vtable,
        };
    }

    pub fn advanceMs(self: *MockClock, delta_ms: i64) void {
        self.current_ms += delta_ms;
        self.current_ns += @as(u64, @intCast(delta_ms)) * std.time.ns_per_ms;
    }

    pub fn advanceNs(self: *MockClock, delta_ns: u64) void {
        self.current_ns += delta_ns;
        self.current_ms += @as(i64, @intCast(delta_ns / std.time.ns_per_ms));
    }
};

test "system clock returns non-zero values" {
    const clk = SystemClock.clock();
    try testing.expect(clk.nowMs() > 0);
    try testing.expect(clk.monotonicNs() > 0);
}

test "mock clock provides deterministic stepped time" {
    var mock = MockClock{
        .current_ms = 1600000000000,
        .current_ns = 5000000,
    };
    const clk = mock.clock();

    try testing.expectEqual(@as(i64, 1600000000000), clk.nowMs());
    try testing.expectEqual(@as(u64, 5000000), clk.monotonicNs());

    mock.advanceMs(150);
    try testing.expectEqual(@as(i64, 1600000000150), clk.nowMs());
    try testing.expectEqual(@as(u64, 5000000 + 150 * std.time.ns_per_ms), clk.monotonicNs());
}
