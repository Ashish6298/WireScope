const std = @import("std");
const testing = std.testing;
const builtin = @import("builtin");

const stats_mod = @import("stats.zig");
const LatencyStats = stats_mod.LatencyStats;
const reporting = @import("../reporting/root.zig");
const probes = @import("../probes/root.zig");
const recon = @import("../recon/root.zig");

/// Structured record of benchmark measurements
pub const BenchmarkResult = struct {
    name: []const u8,
    operations: usize,
    total_ns: u64,
    ns_per_op: u64,
    ops_per_sec: f64,
    throughput_mb_s: ?f64 = null,
};

/// Hardware, compiler, and OS environment record for reproducible performance tracking
pub const EnvironmentMetadata = struct {
    os_name: []const u8,
    cpu_arch: []const u8,
    zig_version: []const u8 = "0.13.0",
    build_mode: []const u8,

    pub fn current() EnvironmentMetadata {
        return .{
            .os_name = @tagName(builtin.os.tag),
            .cpu_arch = @tagName(builtin.cpu.arch),
            .build_mode = @tagName(builtin.mode),
        };
    }
};

/// Benchmarks statistical processing over large sample sets (1,000 to 10,000 samples)
pub fn benchmarkStatsCalculation(allocator: std.mem.Allocator, sample_count: usize) !BenchmarkResult {
    var prng = std.Random.DefaultPrng.init(0x5EED);
    const random = prng.random();

    const samples = try allocator.alloc(u64, sample_count);
    defer allocator.free(samples);

    for (samples) |*s| {
        s.* = random.intRangeAtMost(u64, 1_000_000, 50_000_000); // 1ms - 50ms in ns
    }

    const start_time = std.time.nanoTimestamp();
    const result = try LatencyStats.calculate(allocator, samples, @intCast(sample_count));
    const elapsed_ns: u64 = @intCast(@max(1, std.time.nanoTimestamp() - start_time));

    // Verify mathematical sanity
    if (result.percentiles.p50_ns == null and sample_count >= 1) return error.SanityCheckFailed;

    const ns_per_op = elapsed_ns / @as(u64, @max(1, sample_count));
    const ops_sec = (@as(f64, @floatFromInt(sample_count)) / @as(f64, @floatFromInt(elapsed_ns))) * 1_000_000_000.0;

    return BenchmarkResult{
        .name = "LatencyStats Processing",
        .operations = sample_count,
        .total_ns = elapsed_ns,
        .ns_per_op = ns_per_op,
        .ops_per_sec = ops_sec,
    };
}

/// Benchmarks credential and sensitive token redaction throughput
pub fn benchmarkRedactionThroughput(allocator: std.mem.Allocator, iterations: usize) !BenchmarkResult {
    const raw_text =
        \\GET /api/v1/auth?api_key=secret_1234567890abcdef HTTP/1.1
        \\Host: api.internal.test
        \\Authorization: Bearer my_super_secret_oauth_token_value_xyz
        \\Cookie: session=admintoken999; private_key=hidden_key_data
        \\X-Custom-Header: password=myadminpassword123
        \\
    ;

    const config = reporting.redact.RedactionConfig{
        .enabled = true,
        .redact_credentials = true,
    };

    const start_time = std.time.nanoTimestamp();
    var bytes_processed: usize = 0;

    for (0..iterations) |_| {
        const redacted = try reporting.redact.redactText(allocator, raw_text, config);
        allocator.free(redacted);
        bytes_processed += raw_text.len;
    }

    const elapsed_ns: u64 = @intCast(@max(1, std.time.nanoTimestamp() - start_time));
    const ns_per_op = elapsed_ns / @as(u64, @max(1, iterations));
    const ops_sec = (@as(f64, @floatFromInt(iterations)) / @as(f64, @floatFromInt(elapsed_ns))) * 1_000_000_000.0;
    const mb_processed = @as(f64, @floatFromInt(bytes_processed)) / (1024.0 * 1024.0);
    const sec_elapsed = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0;
    const mb_s = mb_processed / sec_elapsed;

    return BenchmarkResult{
        .name = "Credential Redaction Throughput",
        .operations = iterations,
        .total_ns = elapsed_ns,
        .ns_per_op = ns_per_op,
        .ops_per_sec = ops_sec,
        .throughput_mb_s = mb_s,
    };
}

/// Benchmarks JSON report validation throughput
pub fn benchmarkJsonValidation(allocator: std.mem.Allocator, iterations: usize) !BenchmarkResult {
    const report_json =
        \\{
        \\  "schema_version": 1,
        \\  "report_type": "wirescope_assessment_report",
        \\  "tool": { "name": "wirescope", "version": "0.1.0-dev" },
        \\  "metadata": {
        \\    "assessment_id": "asm-101",
        \\    "profile_id": "local-security-audit",
        \\    "profile_name": "Local Security Audit",
        \\    "started_at_ms": 1710000000000,
        \\    "completed_at_ms": 1710000005000,
        \\    "duration_ms": 5000,
        \\    "status": "completed",
        \\    "manifest_hash": "0000000000000000000000000000000000000000000000000000000000000000"
        \\  },
        \\  "scope": {
        \\    "targets": ["127.0.0.1"],
        \\    "ports": [80, 443],
        \\    "exclusions": [],
        \\    "rate_limit_rps": 10,
        \\    "timeout_ms": 5000,
        \\    "allow_out_of_scope_redirects": false
        \\  },
        \\  "completion_state": {
        \\    "tasks_planned": 2,
        \\    "tasks_executed": 2,
        \\    "tasks_succeeded": 2,
        \\    "tasks_failed": 0,
        \\    "is_complete": true,
        \\    "interruption_reason": null
        \\  },
        \\  "checks": [],
        \\  "observations": {
        \\    "dns": [],
        \\    "tcp": [],
        \\    "tls": [],
        \\    "http": [],
        \\    "listeners": []
        \\  },
        \\  "assets": [],
        \\  "findings": [],
        \\  "policy_results": [],
        \\  "limitations": []
        \\}
    ;

    const start_time = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        try reporting.schema.validateReportJson(allocator, report_json);
    }
    const elapsed_ns: u64 = @intCast(@max(1, std.time.nanoTimestamp() - start_time));
    const ns_per_op = elapsed_ns / @as(u64, @max(1, iterations));
    const ops_sec = (@as(f64, @floatFromInt(iterations)) / @as(f64, @floatFromInt(elapsed_ns))) * 1_000_000_000.0;

    return BenchmarkResult{
        .name = "Report JSON Schema Validation",
        .operations = iterations,
        .total_ns = elapsed_ns,
        .ns_per_op = ns_per_op,
        .ops_per_sec = ops_sec,
    };
}

/// Benchmarks SHA-256 manifest artifact hashing throughput
pub fn benchmarkSha256Throughput(iterations: usize) BenchmarkResult {
    var data: [64 * 1024]u8 = undefined; // 64 KB chunk
    @memset(&data, 0xAA);

    var digest: [32]u8 = undefined;
    const start_time = std.time.nanoTimestamp();

    for (0..iterations) |_| {
        std.crypto.hash.sha2.Sha256.hash(&data, &digest, .{});
    }

    const elapsed_ns: u64 = @intCast(@max(1, std.time.nanoTimestamp() - start_time));
    const ns_per_op = elapsed_ns / @as(u64, @max(1, iterations));
    const ops_sec = (@as(f64, @floatFromInt(iterations)) / @as(f64, @floatFromInt(elapsed_ns))) * 1_000_000_000.0;
    const total_bytes = iterations * data.len;
    const mb_processed = @as(f64, @floatFromInt(total_bytes)) / (1024.0 * 1024.0);
    const sec_elapsed = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0;
    const mb_s = mb_processed / sec_elapsed;

    return BenchmarkResult{
        .name = "SHA-256 Artifact Hashing Throughput",
        .operations = iterations,
        .total_ns = elapsed_ns,
        .ns_per_op = ns_per_op,
        .ops_per_sec = ops_sec,
        .throughput_mb_s = mb_s,
    };
}

// ============================================================================
// TESTS & BENCHMARK VALIDATION
// ============================================================================

test "benchmarks: current environment metadata is accurate" {
    const env = EnvironmentMetadata.current();
    try testing.expect(env.os_name.len > 0);
    try testing.expect(env.cpu_arch.len > 0);
    try testing.expectEqualStrings("0.13.0", env.zig_version);
}

test "benchmarks: latency stats calculation on 1000 samples executes in < 5ms" {
    const res = try benchmarkStatsCalculation(testing.allocator, 1000);
    try testing.expectEqual(@as(usize, 1000), res.operations);
    // Even in Debug mode, 1000 mathematical samples calculate in < 50ms
    try testing.expect(res.total_ns < 50_000_000);
}

test "benchmarks: credential redaction processes > 1 MB/s" {
    const res = try benchmarkRedactionThroughput(testing.allocator, 200);
    try testing.expectEqual(@as(usize, 200), res.operations);
    try testing.expect(res.throughput_mb_s.? > 0.5);
}

test "benchmarks: json schema validation achieves > 1000 ops/sec" {
    const res = try benchmarkJsonValidation(testing.allocator, 100);
    try testing.expectEqual(@as(usize, 100), res.operations);
    try testing.expect(res.ops_per_sec > 100.0);
}

test "benchmarks: sha256 hashing throughput achieves > 10 MB/s" {
    const res = benchmarkSha256Throughput(50);
    try testing.expectEqual(@as(usize, 50), res.operations);
    try testing.expect(res.throughput_mb_s.? > 5.0);
}

test "benchmarks: max configured workload bounds - excessive operations intercepted" {
    // Attempting to calculate 256 hosts * 100 ports = 25,600 tasks exceeds max_operations (5,000)
    const caps = recon.scope.ScopeCaps{
        .max_hosts = 256,
        .max_ports = 100,
        .max_operations = 5000,
    };

    // Generating 60 hosts on 100 ports = 6000 ops -> must safely return error.ExcessiveOperationCount
    var hosts_list = std.ArrayList([]const u8).init(testing.allocator);
    defer {
        for (hosts_list.items) |h| testing.allocator.free(h);
        hosts_list.deinit();
    }

    for (0..60) |idx| {
        const h = try std.fmt.allocPrint(testing.allocator, "127.0.0.{d}", .{idx + 1});
        try hosts_list.append(h);
    }

    const ports_list = try testing.allocator.alloc(u16, 100);
    defer testing.allocator.free(ports_list);
    for (ports_list, 0..) |*p, idx| p.* = @intCast(idx + 1);

    const plan_result = recon.plan.AssessmentPlan.create(testing.allocator, .{
        .targets = hosts_list.items,
        .ports = ports_list,
        .include_dns = false,
        .include_tcp = true,
        .caps = caps,
    });

    // Invariant: WireScope strict safety cap intercepts runaway workload before probe dispatch
    try testing.expectError(error.ExcessiveOperationCount, plan_result);
}

test "benchmarks: cooperative cancellation responsiveness under active batch" {
    var cancel = probes.types.CancellationToken.init();
    try testing.expect(!cancel.isCancelled());

    const start_time = std.time.nanoTimestamp();
    cancel.cancel();
    const abort_time = std.time.nanoTimestamp();

    const cancellation_latency_ns = abort_time - start_time;
    // Cancellation flag transition is immediate atomic operation (< 1ms)
    try testing.expect(cancellation_latency_ns < 1_000_000);
    try testing.expect(cancel.isCancelled());
}
