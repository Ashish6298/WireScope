const std = @import("std");
const testing = std.testing;
const OutcomeCategory = @import("../core/outcome.zig").OutcomeCategory;

pub const HARD_MAX_CONCURRENCY: usize = 64;
pub const DEFAULT_MAX_CONCURRENCY: usize = 10;
pub const DEFAULT_MAX_QUEUE_SIZE: usize = 1000;
pub const DEFAULT_TIMEOUT_MS: u32 = 5000;
pub const HARD_MAX_RETRIES: u8 = 5;

/// State of a probe task throughout its lifecycle
pub const WorkStatus = enum {
    queued,
    running,
    completed,
    failed,
    timed_out,
    cancelled,

    pub fn toSlice(self: WorkStatus) []const u8 {
        return @tagName(self);
    }
};

/// Configuration governing execution concurrency, queue capacity, and deadlines
pub const EngineConfig = struct {
    max_concurrency: usize = DEFAULT_MAX_CONCURRENCY,
    max_queue_size: usize = DEFAULT_MAX_QUEUE_SIZE,
    default_timeout_ms: u32 = DEFAULT_TIMEOUT_MS,
    overall_deadline_ms: ?u32 = null,
    max_retries: u8 = 2,

    pub fn validate(self: EngineConfig) !EngineConfig {
        if (self.max_concurrency == 0 or self.max_concurrency > HARD_MAX_CONCURRENCY) {
            return error.InvalidConcurrency;
        }
        if (self.max_queue_size == 0) {
            return error.InvalidQueueSize;
        }
        if (self.default_timeout_ms == 0) {
            return error.InvalidTimeout;
        }
        if (self.max_retries > HARD_MAX_RETRIES) {
            return error.ExcessiveRetries;
        }
        return self;
    }
};

/// Thread-safe cancellation token shared across worker tasks
pub const CancellationToken = struct {
    cancelled: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    cancel_time_ns: std.atomic.Value(i128) = std.atomic.Value(i128).init(0),

    pub fn init() CancellationToken {
        return .{};
    }

    pub fn cancel(self: *CancellationToken) void {
        const was_cancelled = self.cancelled.swap(true, .seq_cst);
        if (!was_cancelled) {
            self.cancel_time_ns.store(std.time.nanoTimestamp(), .seq_cst);
        }
    }

    pub fn isCancelled(self: *const CancellationToken) bool {
        return self.cancelled.load(.seq_cst);
    }

    pub fn reset(self: *CancellationToken) void {
        self.cancelled.store(false, .seq_cst);
        self.cancel_time_ns.store(0, .seq_cst);
    }
};

/// Real-time engine telemetry and operational counters
pub const EngineMetrics = struct {
    total_enqueued: usize = 0,
    queued: usize = 0,
    running: usize = 0,
    completed: usize = 0,
    failed: usize = 0,
    timed_out: usize = 0,
    cancelled: usize = 0,
    peak_concurrency: usize = 0,
    retries_attempted: usize = 0,

    pub fn isIdle(self: EngineMetrics) bool {
        return self.queued == 0 and self.running == 0;
    }

    pub fn totalProcessed(self: EngineMetrics) usize {
        return self.completed + self.failed + self.timed_out + self.cancelled;
    }
};

/// Function signature for executable probe tasks
pub const TaskFn = *const fn (ctx: ?*anyopaque, cancel: *const CancellationToken) anyerror!OutcomeCategory;

/// Descriptor submitted when scheduling work on the engine
pub const TaskDescriptor = struct {
    id: u64,
    name: []const u8 = "",
    timeout_ms: u32 = DEFAULT_TIMEOUT_MS,
    is_retryable: bool = false,
    max_retries: u8 = 0,
    context: ?*anyopaque = null,
    run_fn: TaskFn,
};

/// Preserved record of a completed or aborted task execution
pub const TaskRecord = struct {
    id: u64,
    name: []const u8,
    status: WorkStatus,
    outcome: OutcomeCategory,
    retries_done: u8,
    elapsed_ns: u64,
};

test "engine config validation" {
    var valid = EngineConfig{
        .max_concurrency = 16,
        .max_queue_size = 500,
        .default_timeout_ms = 3000,
        .max_retries = 3,
    };
    _ = try valid.validate();

    var zero_concurrency = EngineConfig{ .max_concurrency = 0 };
    try testing.expectError(error.InvalidConcurrency, zero_concurrency.validate());

    var excessive_concurrency = EngineConfig{ .max_concurrency = 128 };
    try testing.expectError(error.InvalidConcurrency, excessive_concurrency.validate());

    var excessive_retries = EngineConfig{ .max_retries = 10 };
    try testing.expectError(error.ExcessiveRetries, excessive_retries.validate());
}

test "cancellation token semantics" {
    var token = CancellationToken.init();
    try testing.expect(!token.isCancelled());

    token.cancel();
    try testing.expect(token.isCancelled());

    token.reset();
    try testing.expect(!token.isCancelled());
}

test "metrics calculations" {
    var metrics = EngineMetrics{
        .total_enqueued = 10,
        .queued = 2,
        .running = 1,
        .completed = 5,
        .failed = 1,
        .timed_out = 1,
        .cancelled = 0,
    };

    try testing.expect(!metrics.isIdle());
    try testing.expectEqual(@as(usize, 7), metrics.totalProcessed());

    metrics.queued = 0;
    metrics.running = 0;
    try testing.expect(metrics.isIdle());
}
