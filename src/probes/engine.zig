const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const OutcomeCategory = @import("../core/outcome.zig").OutcomeCategory;

pub const EngineConfig = types.EngineConfig;
pub const EngineMetrics = types.EngineMetrics;
pub const CancellationToken = types.CancellationToken;
pub const WorkStatus = types.WorkStatus;
pub const TaskDescriptor = types.TaskDescriptor;
pub const TaskRecord = types.TaskRecord;
pub const TaskFn = types.TaskFn;

const TaskItem = struct {
    desc: TaskDescriptor,
    retries_done: u8,
};

/// Shared concurrent probe execution engine with bounded scheduling, deadlines, and cancellation
pub const ProbeEngine = struct {
    allocator: std.mem.Allocator,
    config: EngineConfig,
    cancel_token: CancellationToken,
    metrics: EngineMetrics,
    state_mutex: std.Thread.Mutex,
    work_cond: std.Thread.Condition,
    idle_cond: std.Thread.Condition,
    workers: []std.Thread,
    queue: std.ArrayList(TaskItem),
    records: std.ArrayList(TaskRecord),
    is_shutting_down: bool,
    overall_deadline_ns: ?i128,

    pub fn init(allocator: std.mem.Allocator, config: EngineConfig) !*ProbeEngine {
        const validated_config = try config.validate();

        const self = try allocator.create(ProbeEngine);
        errdefer allocator.destroy(self);

        const deadline = if (validated_config.overall_deadline_ms) |ms|
            std.time.nanoTimestamp() + (@as(i128, ms) * std.time.ns_per_ms)
        else
            null;

        self.* = .{
            .allocator = allocator,
            .config = validated_config,
            .cancel_token = CancellationToken.init(),
            .metrics = .{},
            .state_mutex = .{},
            .work_cond = .{},
            .idle_cond = .{},
            .workers = undefined,
            .queue = std.ArrayList(TaskItem).init(allocator),
            .records = std.ArrayList(TaskRecord).init(allocator),
            .is_shutting_down = false,
            .overall_deadline_ns = deadline,
        };

        const workers = try allocator.alloc(std.Thread, validated_config.max_concurrency);
        var spawned_count: usize = 0;
        errdefer {
            self.is_shutting_down = true;
            self.work_cond.broadcast();
            for (0..spawned_count) |i| {
                workers[i].join();
            }
            allocator.free(workers);
            self.queue.deinit();
            self.records.deinit();
        }

        for (0..validated_config.max_concurrency) |i| {
            workers[i] = try std.Thread.spawn(.{}, workerEntry, .{self});
            spawned_count += 1;
        }

        self.workers = workers;
        return self;
    }

    pub fn deinit(self: *ProbeEngine) void {
        {
            self.state_mutex.lock();
            self.is_shutting_down = true;
            self.cancel_token.cancel();
            self.work_cond.broadcast();
            self.idle_cond.broadcast();
            self.state_mutex.unlock();
        }

        for (self.workers) |w| {
            w.join();
        }

        self.allocator.free(self.workers);
        self.queue.deinit();
        self.records.deinit();
        self.allocator.destroy(self);
    }

    fn workerEntry(self: *ProbeEngine) void {
        self.workerLoop();
    }

    fn workerLoop(self: *ProbeEngine) void {
        while (true) {
            var task_opt: ?TaskItem = null;
            {
                self.state_mutex.lock();
                defer self.state_mutex.unlock();

                while (true) {
                    if (self.is_shutting_down) {
                        return;
                    }

                    // If cancelled, immediately purge queued tasks with .cancelled
                    if (self.cancel_token.isCancelled()) {
                        while (self.queue.items.len > 0) {
                            const queued_task = self.queue.orderedRemove(0);
                            self.metrics.queued -= 1;
                            self.metrics.cancelled += 1;
                            self.records.append(.{
                                .id = queued_task.desc.id,
                                .name = queued_task.desc.name,
                                .status = .cancelled,
                                .outcome = .cancelled,
                                .is_partial = true,
                                .retries_done = queued_task.retries_done,
                                .elapsed_ns = 0,
                                .timing_stages = .{ .total_elapsed_ns = 0 },
                            }) catch {};
                        }
                        if (self.metrics.queued == 0 and self.metrics.running == 0) {
                            self.idle_cond.broadcast();
                        }
                        self.work_cond.wait(&self.state_mutex);
                        continue;
                    }

                    // Check overall assessment deadline
                    if (self.overall_deadline_ns) |deadline| {
                        if (std.time.nanoTimestamp() >= deadline) {
                            while (self.queue.items.len > 0) {
                                const queued_task = self.queue.orderedRemove(0);
                                self.metrics.queued -= 1;
                                self.metrics.timed_out += 1;
                                self.records.append(.{
                                    .id = queued_task.desc.id,
                                    .name = queued_task.desc.name,
                                    .status = .timed_out,
                                    .outcome = .timeout,
                                    .is_partial = true,
                                    .retries_done = queued_task.retries_done,
                                    .elapsed_ns = 0,
                                    .timing_stages = .{ .total_elapsed_ns = 0 },
                                }) catch {};
                            }
                            if (self.metrics.queued == 0 and self.metrics.running == 0) {
                                self.idle_cond.broadcast();
                            }
                            self.work_cond.wait(&self.state_mutex);
                            continue;
                        }
                    }

                    if (self.queue.items.len > 0) {
                        task_opt = self.queue.orderedRemove(0);
                        self.metrics.queued -= 1;
                        self.metrics.running += 1;
                        if (self.metrics.running > self.metrics.peak_concurrency) {
                            self.metrics.peak_concurrency = self.metrics.running;
                        }
                        break;
                    }

                    if (self.metrics.queued == 0 and self.metrics.running == 0) {
                        self.idle_cond.broadcast();
                    }

                    self.work_cond.wait(&self.state_mutex);
                }
            }

            if (task_opt) |task| {
                self.executeTask(task);
            }
        }
    }

    fn executeTask(self: *ProbeEngine, task: TaskItem) void {
        const task_start = std.time.nanoTimestamp();
        var outcome: OutcomeCategory = .success;
        var final_status: WorkStatus = .completed;

        // Verify pre-execution conditions
        if (self.cancel_token.isCancelled()) {
            outcome = .cancelled;
            final_status = .cancelled;
        } else if (self.overall_deadline_ns != null and std.time.nanoTimestamp() >= self.overall_deadline_ns.?) {
            outcome = .timeout;
            final_status = .timed_out;
        } else {
            // Execute operation with cancellation token
            const result = task.desc.run_fn(task.desc.context, &self.cancel_token);
            const task_elapsed_ms = @as(u32, @intCast(@max(0, @divTrunc(std.time.nanoTimestamp() - task_start, std.time.ns_per_ms))));

            if (result) |cat| {
                outcome = cat;
                if (task_elapsed_ms > task.desc.timeout_ms or outcome == .timeout) {
                    outcome = .timeout;
                    final_status = .timed_out;
                } else if (outcome == .cancelled or self.cancel_token.isCancelled()) {
                    outcome = .cancelled;
                    final_status = .cancelled;
                } else if (outcome.isFailure()) {
                    final_status = .failed;
                } else {
                    final_status = .completed;
                }
            } else |_| {
                outcome = .operational_failure;
                final_status = .failed;
            }
        }

        const elapsed = @as(u64, @intCast(@max(0, std.time.nanoTimestamp() - task_start)));

        // Check finite retry eligibility:
        // Retries must be enabled only for operations where retrying is meaningful and bounded
        var should_retry = false;
        if (!self.cancel_token.isCancelled() and
            task.desc.is_retryable and
            task.retries_done < task.desc.max_retries and
            task.retries_done < self.config.max_retries and
            (outcome == .timeout or outcome == .operational_failure or outcome == .refusal))
        {
            should_retry = true;
        }

        {
            self.state_mutex.lock();
            defer self.state_mutex.unlock();

            self.metrics.running -= 1;

            if (should_retry) {
                self.metrics.retries_attempted += 1;
                var retry_item = task;
                retry_item.retries_done += 1;

                if (self.queue.items.len < self.config.max_queue_size) {
                    self.queue.append(retry_item) catch {
                        // Re-enqueue failed due to memory, record failure
                        self.metrics.failed += 1;
                        self.records.append(.{
                            .id = task.desc.id,
                            .name = task.desc.name,
                            .status = .failed,
                            .outcome = outcome,
                            .retries_done = task.retries_done,
                            .elapsed_ns = elapsed,
                        }) catch {};
                        return;
                    };
                    self.metrics.queued += 1;
                    self.work_cond.signal();
                    return;
                }
            }

            // Record terminal outcome
            switch (final_status) {
                .completed => self.metrics.completed += 1,
                .failed => self.metrics.failed += 1,
                .timed_out => self.metrics.timed_out += 1,
                .cancelled => self.metrics.cancelled += 1,
                else => self.metrics.completed += 1,
            }

            const is_partial = (final_status == .cancelled or final_status == .timed_out);
            self.records.append(.{
                .id = task.desc.id,
                .name = task.desc.name,
                .status = final_status,
                .outcome = outcome,
                .is_partial = is_partial,
                .retries_done = task.retries_done,
                .elapsed_ns = elapsed,
                .timing_stages = .{ .total_elapsed_ns = elapsed },
            }) catch {};

            if (self.metrics.queued == 0 and self.metrics.running == 0) {
                self.idle_cond.broadcast();
            }
        }
    }

    /// Submits a task to the engine queue.
    /// Fails immediately if cancelled or if queue capacity has been reached.
    pub fn enqueue(self: *ProbeEngine, desc: TaskDescriptor) !void {
        self.state_mutex.lock();
        defer self.state_mutex.unlock();

        if (self.cancel_token.isCancelled()) {
            return error.EngineCancelled;
        }

        if (self.queue.items.len >= self.config.max_queue_size) {
            return error.QueueFull;
        }

        try self.queue.append(.{
            .desc = desc,
            .retries_done = 0,
        });

        self.metrics.total_enqueued += 1;
        self.metrics.queued += 1;
        self.work_cond.signal();
    }

    /// Signals cancellation: stops scheduling new work and cancels pending queued tasks.
    pub fn cancel(self: *ProbeEngine) void {
        self.state_mutex.lock();
        defer self.state_mutex.unlock();

        self.cancel_token.cancel();

        // Drain pending queue
        while (self.queue.items.len > 0) {
            const queued_task = self.queue.orderedRemove(0);
            self.metrics.queued -= 1;
            self.metrics.cancelled += 1;
            self.records.append(.{
                .id = queued_task.desc.id,
                .name = queued_task.desc.name,
                .status = .cancelled,
                .outcome = .cancelled,
                .is_partial = true,
                .retries_done = queued_task.retries_done,
                .elapsed_ns = 0,
                .timing_stages = .{ .total_elapsed_ns = 0 },
            }) catch {};
        }

        self.work_cond.broadcast();
        if (self.metrics.queued == 0 and self.metrics.running == 0) {
            self.idle_cond.broadcast();
        }
    }

    /// Blocks until all queued and active work has completed, timed out, or cancelled.
    pub fn wait(self: *ProbeEngine) void {
        self.state_mutex.lock();
        defer self.state_mutex.unlock();

        while (self.metrics.queued > 0 or self.metrics.running > 0) {
            self.idle_cond.wait(&self.state_mutex);
        }
    }

    /// Returns a point-in-time snapshot of engine operational metrics.
    pub fn getMetrics(self: *ProbeEngine) EngineMetrics {
        self.state_mutex.lock();
        defer self.state_mutex.unlock();
        return self.metrics;
    }

    /// Returns a copy of execution records for completed tasks.
    pub fn getRecords(self: *ProbeEngine, allocator: std.mem.Allocator) ![]TaskRecord {
        self.state_mutex.lock();
        defer self.state_mutex.unlock();
        return allocator.dupe(TaskRecord, self.records.items);
    }
};

// -----------------------------------------------------------------------------
// TESTS & ACCEPTANCE VERIFICATION
// -----------------------------------------------------------------------------

test "stress test proves active work never exceeds max_concurrency" {
    const allocator = testing.allocator;

    const max_concurrent: usize = 4;
    const task_count: usize = 20;

    const engine = try ProbeEngine.init(allocator, .{
        .max_concurrency = max_concurrent,
        .max_queue_size = 100,
        .default_timeout_ms = 5000,
    });
    defer engine.deinit();

    const Context = struct {
        active_counter: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
        max_seen: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
        limit: usize,

        fn run(ctx_ptr: ?*anyopaque, _: *const CancellationToken) anyerror!OutcomeCategory {
            const ctx: *@This() = @ptrCast(@alignCast(ctx_ptr.?));
            const current = ctx.active_counter.fetchAdd(1, .seq_cst) + 1;

            var old_max = ctx.max_seen.load(.seq_cst);
            while (current > old_max) {
                if (ctx.max_seen.cmpxchgWeak(old_max, current, .seq_cst, .seq_cst)) |new_old| {
                    old_max = new_old;
                } else break;
            }

            // Simulate small work
            std.time.sleep(10 * std.time.ns_per_ms);

            _ = ctx.active_counter.fetchSub(1, .seq_cst);
            return .success;
        }
    };

    var shared_ctx = Context{ .limit = max_concurrent };

    for (0..task_count) |i| {
        try engine.enqueue(.{
            .id = i,
            .name = "stress_task",
            .context = &shared_ctx,
            .run_fn = Context.run,
        });
    }

    engine.wait();

    const metrics = engine.getMetrics();
    try testing.expectEqual(task_count, metrics.completed);
    try testing.expectEqual(@as(usize, 0), metrics.failed);
    try testing.expectEqual(@as(usize, 0), metrics.running);
    try testing.expectEqual(@as(usize, 0), metrics.queued);

    // Strict acceptance criteria: active work never exceeded configured limit
    try testing.expect(metrics.peak_concurrency <= max_concurrent);
    try testing.expect(shared_ctx.max_seen.load(.seq_cst) <= max_concurrent);
}

test "queue growth is bounded by max_queue_size" {
    const allocator = testing.allocator;

    const engine = try ProbeEngine.init(allocator, .{
        .max_concurrency = 1,
        .max_queue_size = 3,
        .default_timeout_ms = 5000,
    });
    defer engine.deinit();

    const Dummy = struct {
        fn run(_: ?*anyopaque, cancel: *const CancellationToken) anyerror!OutcomeCategory {
            // Block until cancelled or sleep
            while (!cancel.isCancelled()) {
                std.time.sleep(10 * std.time.ns_per_ms);
            }
            return .cancelled;
        }
    };

    // First task starts running on worker thread immediately
    try engine.enqueue(.{ .id = 1, .run_fn = Dummy.run });

    // Allow worker to pick up task 1
    std.time.sleep(10 * std.time.ns_per_ms);

    // Now fill the 3 queue slots
    try engine.enqueue(.{ .id = 2, .run_fn = Dummy.run });
    try engine.enqueue(.{ .id = 3, .run_fn = Dummy.run });
    try engine.enqueue(.{ .id = 4, .run_fn = Dummy.run });

    // 4th enqueue to a full queue MUST fail with error.QueueFull
    try testing.expectError(error.QueueFull, engine.enqueue(.{ .id = 5, .run_fn = Dummy.run }));

    engine.cancel();
    engine.wait();
}

test "cancellation stops new work and releases active resources" {
    const allocator = testing.allocator;

    const engine = try ProbeEngine.init(allocator, .{
        .max_concurrency = 2,
        .max_queue_size = 50,
    });
    defer engine.deinit();

    const CancelCtx = struct {
        cancelled_observed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

        fn run(ctx_ptr: ?*anyopaque, cancel: *const CancellationToken) anyerror!OutcomeCategory {
            const ctx: *@This() = @ptrCast(@alignCast(ctx_ptr.?));
            while (!cancel.isCancelled()) {
                std.time.sleep(5 * std.time.ns_per_ms);
            }
            ctx.cancelled_observed.store(true, .seq_cst);
            return .cancelled;
        }
    };

    var ctx = CancelCtx{};

    // Enqueue 10 tasks
    for (0..10) |i| {
        try engine.enqueue(.{
            .id = i,
            .context = &ctx,
            .run_fn = CancelCtx.run,
        });
    }

    // Wait slightly so workers start running
    std.time.sleep(10 * std.time.ns_per_ms);

    // Cancel engine
    engine.cancel();

    // Enqueuing after cancel MUST fail
    try testing.expectError(error.EngineCancelled, engine.enqueue(.{
        .id = 99,
        .run_fn = CancelCtx.run,
    }));

    engine.wait();

    const metrics = engine.getMetrics();
    try testing.expect(metrics.cancelled > 0);
    try testing.expect(ctx.cancelled_observed.load(.seq_cst));
    try testing.expectEqual(@as(usize, 0), metrics.running);
    try testing.expectEqual(@as(usize, 0), metrics.queued);
}

test "retries are bounded and enabled only when retryable" {
    const allocator = testing.allocator;

    const engine = try ProbeEngine.init(allocator, .{
        .max_concurrency = 2,
        .max_retries = 2,
    });
    defer engine.deinit();

    const RetryState = struct {
        attempts: std.atomic.Value(u8) = std.atomic.Value(u8).init(0),

        fn failingRetryable(ctx_ptr: ?*anyopaque, _: *const CancellationToken) anyerror!OutcomeCategory {
            const state: *@This() = @ptrCast(@alignCast(ctx_ptr.?));
            _ = state.attempts.fetchAdd(1, .seq_cst);
            // Return retryable failure
            return .operational_failure;
        }

        fn failingNonRetryable(ctx_ptr: ?*anyopaque, _: *const CancellationToken) anyerror!OutcomeCategory {
            const state: *@This() = @ptrCast(@alignCast(ctx_ptr.?));
            _ = state.attempts.fetchAdd(1, .seq_cst);
            return .operational_failure;
        }
    };

    var retryable_state = RetryState{};
    try engine.enqueue(.{
        .id = 1,
        .name = "retryable_task",
        .is_retryable = true,
        .max_retries = 2,
        .context = &retryable_state,
        .run_fn = RetryState.failingRetryable,
    });

    var non_retryable_state = RetryState{};
    try engine.enqueue(.{
        .id = 2,
        .name = "non_retryable_task",
        .is_retryable = false,
        .max_retries = 2,
        .context = &non_retryable_state,
        .run_fn = RetryState.failingNonRetryable,
    });

    engine.wait();

    const metrics = engine.getMetrics();
    try testing.expectEqual(@as(usize, 2), metrics.failed);

    // Initial attempt + 2 retries = 3 attempts total for retryable
    try testing.expectEqual(@as(u8, 3), retryable_state.attempts.load(.seq_cst));

    // Non-retryable task executed exactly 1 time
    try testing.expectEqual(@as(u8, 1), non_retryable_state.attempts.load(.seq_cst));

    // Exactly 2 retry attempts were recorded
    try testing.expectEqual(@as(usize, 2), metrics.retries_attempted);
}

test "overall assessment deadline marks remaining work timed out" {
    const allocator = testing.allocator;

    // Overall deadline of 50ms
    const engine = try ProbeEngine.init(allocator, .{
        .max_concurrency = 1,
        .overall_deadline_ms = 50,
    });
    defer engine.deinit();

    const SlowTask = struct {
        fn run(_: ?*anyopaque, _: *const CancellationToken) anyerror!OutcomeCategory {
            std.time.sleep(70 * std.time.ns_per_ms);
            return .success;
        }
    };

    try engine.enqueue(.{ .id = 1, .run_fn = SlowTask.run });
    try engine.enqueue(.{ .id = 2, .run_fn = SlowTask.run });

    engine.wait();

    const metrics = engine.getMetrics();
    try testing.expect(metrics.timed_out >= 1);
    try testing.expectEqual(@as(usize, 0), metrics.running);
    try testing.expectEqual(@as(usize, 0), metrics.queued);
}

test "per-operation deadline marks long operation as timed out" {
    const allocator = testing.allocator;

    const engine = try ProbeEngine.init(allocator, .{
        .max_concurrency = 2,
    });
    defer engine.deinit();

    const OvertimeTask = struct {
        fn run(_: ?*anyopaque, _: *const CancellationToken) anyerror!OutcomeCategory {
            std.time.sleep(60 * std.time.ns_per_ms);
            return .success;
        }
    };

    // Task specifies a 15ms timeout, but sleeps for 60ms
    try engine.enqueue(.{
        .id = 42,
        .name = "overtime_task",
        .timeout_ms = 15,
        .run_fn = OvertimeTask.run,
    });

    engine.wait();

    const metrics = engine.getMetrics();
    try testing.expectEqual(@as(usize, 1), metrics.timed_out);
    try testing.expectEqual(@as(usize, 0), metrics.completed);

    const records = try engine.getRecords(allocator);
    defer allocator.free(records);

    try testing.expectEqual(@as(usize, 1), records.len);
    try testing.expectEqual(@as(u64, 42), records[0].id);
    try testing.expectEqual(WorkStatus.timed_out, records[0].status);
    try testing.expectEqual(OutcomeCategory.timeout, records[0].outcome);
}

test "resource allocation and deterministic cleanup under task execution" {
    const allocator = testing.allocator;

    const engine = try ProbeEngine.init(allocator, .{
        .max_concurrency = 2,
    });
    defer engine.deinit();

    const ResourceContext = struct {
        allocator: std.mem.Allocator,
        allocated_buffer: []u8,
        freed: bool = false,

        fn run(ctx_ptr: ?*anyopaque, _: *const CancellationToken) anyerror!OutcomeCategory {
            const ctx: *@This() = @ptrCast(@alignCast(ctx_ptr.?));
            // Simulate buffer manipulation
            @memset(ctx.allocated_buffer, 0xAA);
            return .success;
        }

        fn deinit(self: *@This()) void {
            self.allocator.free(self.allocated_buffer);
            self.freed = true;
        }
    };

    const buf = try allocator.alloc(u8, 1024);
    var ctx = ResourceContext{
        .allocator = allocator,
        .allocated_buffer = buf,
    };
    defer ctx.deinit();

    try engine.enqueue(.{
        .id = 100,
        .name = "resource_task",
        .context = &ctx,
        .run_fn = ResourceContext.run,
    });

    engine.wait();

    const metrics = engine.getMetrics();
    try testing.expectEqual(@as(usize, 1), metrics.completed);
    try testing.expectEqual(@as(u8, 0xAA), ctx.allocated_buffer[0]);
}
