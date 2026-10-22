# Architecture Decision Record (ADR) 0010: Shared Probe Engine Scheduling, Deadlines, and Cancellation

## Status
Accepted

## Context
Phase 4.1 of Milestone 4 requires implementing a shared execution engine for network probes.
Specific requirements:
1. Configurable concurrency bounded within safe limits (1 to 64 workers).
2. Per-operation deadlines and overall assessment-level deadlines.
3. Bounded queue capacity to prevent unbounded memory growth.
4. Immediate cooperative cancellation that halts scheduling new work, signals active workers, drains pending items with `.cancelled`, and releases resources.
5. Finite, bounded retries enabled only for operations where retrying is technically meaningful (e.g., transient network errors, timeouts).
6. Real-time telemetry tracking `queued`, `running`, `completed`, `failed`, `timed_out`, `cancelled`, `peak_concurrency`, and `retries_attempted`.
7. Zero console I/O inside the engine (no printing directly to the terminal).

## Decision

### 1. Types and Contracts (`src/probes/types.zig`)
- **`EngineConfig`**: Validates configuration parameters.
  - `max_concurrency`: Enforced strictly between 1 and `HARD_MAX_CONCURRENCY` (64).
  - `max_queue_size`: Hard ceiling on queued pending tasks (default: 1,000).
  - `default_timeout_ms`: Fallback operation timeout (default: 5,000 ms).
  - `overall_deadline_ms`: Optional global deadline for assessment batches.
  - `max_retries`: Finite retry cap (default: 2, hard max: 5).
- **`CancellationToken`**: Thread-safe atomic cancellation flag (`std.atomic.Value(bool)`) paired with high-resolution cancellation timestamp. Passed into probe task executions to permit cooperative abort.
- **`EngineMetrics`**: Thread-safe telemetry snapshot recording:
  - `total_enqueued`, `queued`, `running`, `completed`, `failed`, `timed_out`, `cancelled`, `peak_concurrency`, and `retries_attempted`.
- **`TaskDescriptor` & `TaskRecord`**: Structured work input and immutable preserved execution outcomes.

### 2. Concurrency and Worker Threading (`src/probes/engine.zig`)
- **Dedicated Worker Pool Architecture**:
  - The engine spawns exactly `config.max_concurrency` worker threads.
  - Active work can physically never exceed `config.max_concurrency`, preventing socket starvation and host overload.
  - Synchronized using `std.Thread.Mutex`, `std.Thread.Condition` (`work_cond` and `idle_cond`).
- **Bounded Queue**:
  - Protected by state mutex.
  - Calling `enqueue()` when queue length reaches `max_queue_size` immediately returns `error.QueueFull`.
- **Deadlines**:
  - Overall deadline: Checked upon dequeue. If the monotonic timestamp exceeds `overall_deadline_ns`, remaining queued work is drained with status `.timed_out`.
  - Per-operation deadline: Monitored via high-resolution monotonic elapsed time. If a task exceeds its configured `timeout_ms`, it is classified as `.timed_out`.
- **Cooperative Cancellation**:
  - `engine.cancel()` sets `CancellationToken` atomically, broadcasts across all workers, and drains queued tasks directly into `.cancelled` records.
  - Enqueuing work after cancellation returns `error.EngineCancelled`.
- **Bounded Finite Retries**:
  - Retries only trigger when `task.is_retryable` is true AND the outcome is a transient failure (`.timeout`, `.operational_failure`, `.refusal`) AND `retries_done < task.max_retries` AND `retries_done < config.max_retries`.
  - Non-retryable tasks are never retried.

### 3. Clean Terminal Separation
- The engine produces zero direct standard output (`stdout` or `stderr`).
- All state transitions and results are recorded in memory structures (`TaskRecord`, `EngineMetrics`) and retrieved programmatically by the caller or reporting layer.

## Consequences
- Rock-solid execution backbone for subsequent DNS, TCP, TLS, and HTTP diagnostic probes.
- Guarantees strict resource safety and concurrency bounds under arbitrary stress.
- Deterministic cleanup and complete audit trail for all partial and cancelled runs.
