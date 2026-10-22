const std = @import("std");
const testing = std.testing;

/// Minimum sample count thresholds required for percentiles to be mathematically meaningful.
/// Percentiles are omitted or null if sample size is insufficient.
pub const PercentileThresholds = struct {
    pub const p50_min_samples: usize = 1;
    pub const p75_min_samples: usize = 4;
    pub const p90_min_samples: usize = 10;
    pub const p95_min_samples: usize = 20;
    pub const p99_min_samples: usize = 100;
};

/// High-resolution percentile container with null values for insufficient sample sizes.
pub const PercentileSummary = struct {
    p50_ns: ?u64 = null,
    p75_ns: ?u64 = null,
    p90_ns: ?u64 = null,
    p95_ns: ?u64 = null,
    p99_ns: ?u64 = null,

    pub fn toJson(self: PercentileSummary, writer: anytype) !void {
        try writer.writeAll("{");
        var first = true;

        if (self.p50_ns) |v| {
            if (!first) try writer.writeAll(",");
            first = false;
            try writer.print("\"p50_ns\":{d}", .{v});
        }
        if (self.p75_ns) |v| {
            if (!first) try writer.writeAll(",");
            first = false;
            try writer.print("\"p75_ns\":{d}", .{v});
        }
        if (self.p90_ns) |v| {
            if (!first) try writer.writeAll(",");
            first = false;
            try writer.print("\"p90_ns\":{d}", .{v});
        }
        if (self.p95_ns) |v| {
            if (!first) try writer.writeAll(",");
            first = false;
            try writer.print("\"p95_ns\":{d}", .{v});
        }
        if (self.p99_ns) |v| {
            if (!first) try writer.writeAll(",");
            first = false;
            try writer.print("\"p99_ns\":{d}", .{v});
        }

        try writer.writeAll("}");
    }
};

/// Statistical summary computed exclusively from successful, comparable timing measurements.
///
/// Formulas & Semantics:
///   1. Exclusivity of Successes: Failed samples (refusals, timeouts, network drops)
///      do NOT have a complete handshake duration. Including artificial timeout cutoffs
///      would distort transport statistics. Failures are reported separately under
///      failed_samples and loss_percent.
///   2. Jitter (RFC 3550 / RFC 4689 Mean Successive Absolute Difference):
///      Calculated from consecutive successful measurements in chronological order:
///        J = (1 / (k - 1)) * sum_{i=1}^{k-1} |x_{i+1} - x_i|   (for k >= 2)
///      Where k is the count of successful samples. If k < 2, jitter is null.
///   3. Sample Standard Deviation:
///        s = sqrt( (1 / (k - 1)) * sum_{i=1}^k (x_i - mean)^2 )   (for k >= 2)
///      If k < 2, stddev is null.
///   4. Percentiles (Nearest-Rank Method):
///      For sorted array of length k:
///        rank = ceil((P / 100) * k)
///        index = min(rank - 1, k - 1)
///      Reported only when k >= minimum threshold (p75 >= 4, p90 >= 10, p95 >= 20, p99 >= 100).
pub const LatencyStats = struct {
    total_samples: u32 = 0,
    successful_samples: u32 = 0,
    failed_samples: u32 = 0,
    loss_percent: f64 = 0.0,

    min_ns: ?u64 = null,
    max_ns: ?u64 = null,
    mean_ns: ?u64 = null,
    median_ns: ?u64 = null,
    stddev_ns: ?u64 = null,
    jitter_rfc3550_ns: ?u64 = null,
    percentiles: PercentileSummary = .{},

    /// Computes latency statistics from chronological successful samples and total attempted samples.
    pub fn calculate(allocator: std.mem.Allocator, chronological_samples: []const u64, total_attempted: u32) !LatencyStats {
        var stats = LatencyStats{
            .total_samples = total_attempted,
            .successful_samples = @intCast(chronological_samples.len),
            .failed_samples = if (total_attempted >= chronological_samples.len)
                total_attempted - @as(u32, @intCast(chronological_samples.len))
            else
                0,
        };

        if (total_attempted > 0) {
            stats.loss_percent = (@as(f64, @floatFromInt(stats.failed_samples)) / @as(f64, @floatFromInt(total_attempted))) * 100.0;
        }

        const k = chronological_samples.len;
        if (k == 0) {
            return stats;
        }

        // Single sample case
        if (k == 1) {
            const single_val = chronological_samples[0];
            stats.min_ns = single_val;
            stats.max_ns = single_val;
            stats.mean_ns = single_val;
            stats.median_ns = single_val;
            stats.percentiles.p50_ns = single_val;
            // stddev, jitter, and higher percentiles remain null for k = 1
            return stats;
        }

        // Many samples: allocate a working copy to sort for order statistics
        const sorted = try allocator.alloc(u64, k);
        defer allocator.free(sorted);
        @memcpy(sorted, chronological_samples);
        std.mem.sort(u64, sorted, {}, comptime std.sort.asc(u64));

        stats.min_ns = sorted[0];
        stats.max_ns = sorted[k - 1];

        // Sum and Mean
        var sum: u128 = 0;
        for (sorted) |val| {
            sum += val;
        }
        const mean_u128 = sum / k;
        stats.mean_ns = @intCast(mean_u128);

        // Median (p50)
        if (k % 2 == 1) {
            stats.median_ns = sorted[k / 2];
        } else {
            const m1 = sorted[(k / 2) - 1];
            const m2 = sorted[k / 2];
            stats.median_ns = (m1 + m2) / 2;
        }
        stats.percentiles.p50_ns = stats.median_ns;

        // Sample Standard Deviation: s = sqrt( (1 / (k - 1)) * sum (x_i - mean)^2 )
        const mean_f: f64 = @floatFromInt(stats.mean_ns.?);
        var sum_sq_diff: f64 = 0.0;
        for (sorted) |val| {
            const val_f: f64 = @floatFromInt(val);
            const diff = val_f - mean_f;
            sum_sq_diff += diff * diff;
        }
        const variance = sum_sq_diff / @as(f64, @floatFromInt(k - 1));
        const stddev_f = @sqrt(variance);
        stats.stddev_ns = @intFromFloat(@round(stddev_f));

        // RFC 3550 / RFC 4689 Interarrival Jitter (Mean Absolute Successive Difference)
        var sum_jitter: u128 = 0;
        var i: usize = 0;
        while (i < k - 1) : (i += 1) {
            const a = chronological_samples[i];
            const b = chronological_samples[i + 1];
            const diff = if (b >= a) b - a else a - b;
            sum_jitter += diff;
        }
        stats.jitter_rfc3550_ns = @intCast(sum_jitter / (k - 1));

        // Percentiles with strict sample size significance thresholds
        if (k >= PercentileThresholds.p75_min_samples) {
            stats.percentiles.p75_ns = computeNearestRankPercentile(sorted, 75.0);
        }
        if (k >= PercentileThresholds.p90_min_samples) {
            stats.percentiles.p90_ns = computeNearestRankPercentile(sorted, 90.0);
        }
        if (k >= PercentileThresholds.p95_min_samples) {
            stats.percentiles.p95_ns = computeNearestRankPercentile(sorted, 95.0);
        }
        if (k >= PercentileThresholds.p99_min_samples) {
            stats.percentiles.p99_ns = computeNearestRankPercentile(sorted, 99.0);
        }

        return stats;
    }

    /// Nearest-rank percentile computation on pre-sorted array
    fn computeNearestRankPercentile(sorted: []const u64, percentile: f64) u64 {
        std.debug.assert(sorted.len > 0);
        const rank_f = @ceil((percentile / 100.0) * @as(f64, @floatFromInt(sorted.len)));
        const rank = @as(usize, @intFromFloat(rank_f));
        const idx = if (rank > 0) rank - 1 else 0;
        return sorted[@min(idx, sorted.len - 1)];
    }

    /// Serializes statistical summary to JSON
    pub fn toJson(self: LatencyStats, writer: anytype) !void {
        try writer.print(
            \\{{"total_samples":{d},"successful_samples":{d},"failed_samples":{d},"loss_percent":{d:.2},
        , .{ self.total_samples, self.successful_samples, self.failed_samples, self.loss_percent });

        if (self.min_ns) |v| {
            try writer.print("\"min_ns\":{d},", .{v});
        } else {
            try writer.writeAll("\"min_ns\":null,");
        }

        if (self.max_ns) |v| {
            try writer.print("\"max_ns\":{d},", .{v});
        } else {
            try writer.writeAll("\"max_ns\":null,");
        }

        if (self.mean_ns) |v| {
            try writer.print("\"mean_ns\":{d},", .{v});
        } else {
            try writer.writeAll("\"mean_ns\":null,");
        }

        if (self.median_ns) |v| {
            try writer.print("\"median_ns\":{d},", .{v});
        } else {
            try writer.writeAll("\"median_ns\":null,");
        }

        if (self.stddev_ns) |v| {
            try writer.print("\"stddev_ns\":{d},", .{v});
        } else {
            try writer.writeAll("\"stddev_ns\":null,");
        }

        if (self.jitter_rfc3550_ns) |v| {
            try writer.print("\"jitter_rfc3550_ns\":{d},", .{v});
        } else {
            try writer.writeAll("\"jitter_rfc3550_ns\":null,");
        }

        try writer.writeAll("\"percentiles\":");
        try self.percentiles.toJson(writer);
        try writer.writeAll("}");
    }
};

// ============================================================================
// Unit Tests (Acceptance Criteria: Zero, One, and Many Samples, Formulas)
// ============================================================================

test "zero samples latency statistics" {
    const empty = [_]u64{};
    const stats = try LatencyStats.calculate(testing.allocator, &empty, 0);

    try testing.expectEqual(@as(u32, 0), stats.total_samples);
    try testing.expectEqual(@as(u32, 0), stats.successful_samples);
    try testing.expectEqual(@as(u32, 0), stats.failed_samples);
    try testing.expectEqual(@as(f64, 0.0), stats.loss_percent);
    try testing.expect(stats.min_ns == null);
    try testing.expect(stats.max_ns == null);
    try testing.expect(stats.mean_ns == null);
    try testing.expect(stats.median_ns == null);
    try testing.expect(stats.stddev_ns == null);
    try testing.expect(stats.jitter_rfc3550_ns == null);
    try testing.expect(stats.percentiles.p50_ns == null);
    try testing.expect(stats.percentiles.p75_ns == null);
    try testing.expect(stats.percentiles.p90_ns == null);
    try testing.expect(stats.percentiles.p95_ns == null);
    try testing.expect(stats.percentiles.p99_ns == null);
}

test "all failed samples statistics" {
    const empty = [_]u64{};
    const stats = try LatencyStats.calculate(testing.allocator, &empty, 5);

    try testing.expectEqual(@as(u32, 5), stats.total_samples);
    try testing.expectEqual(@as(u32, 0), stats.successful_samples);
    try testing.expectEqual(@as(u32, 5), stats.failed_samples);
    try testing.expectEqual(@as(f64, 100.0), stats.loss_percent);
    try testing.expect(stats.min_ns == null);
    try testing.expect(stats.max_ns == null);
}

test "single sample latency statistics" {
    const samples = [_]u64{15_000_000}; // 15 ms
    const stats = try LatencyStats.calculate(testing.allocator, &samples, 1);

    try testing.expectEqual(@as(u32, 1), stats.total_samples);
    try testing.expectEqual(@as(u32, 1), stats.successful_samples);
    try testing.expectEqual(@as(u32, 0), stats.failed_samples);
    try testing.expectEqual(@as(f64, 0.0), stats.loss_percent);
    try testing.expectEqual(@as(?u64, 15_000_000), stats.min_ns);
    try testing.expectEqual(@as(?u64, 15_000_000), stats.max_ns);
    try testing.expectEqual(@as(?u64, 15_000_000), stats.mean_ns);
    try testing.expectEqual(@as(?u64, 15_000_000), stats.median_ns);
    try testing.expectEqual(@as(?u64, 15_000_000), stats.percentiles.p50_ns);

    // Standard deviation and jitter require at least 2 samples
    try testing.expect(stats.stddev_ns == null);
    try testing.expect(stats.jitter_rfc3550_ns == null);
    // Higher percentiles require larger sample counts
    try testing.expect(stats.percentiles.p75_ns == null);
    try testing.expect(stats.percentiles.p90_ns == null);
}

test "two samples latency statistics with jitter and stddev" {
    const samples = [_]u64{ 10_000_000, 20_000_000 };
    const stats = try LatencyStats.calculate(testing.allocator, &samples, 2);

    try testing.expectEqual(@as(?u64, 10_000_000), stats.min_ns);
    try testing.expectEqual(@as(?u64, 20_000_000), stats.max_ns);
    try testing.expectEqual(@as(?u64, 15_000_000), stats.mean_ns);
    try testing.expectEqual(@as(?u64, 15_000_000), stats.median_ns);

    // Jitter: |20 - 10| = 10 ms
    try testing.expectEqual(@as(?u64, 10_000_000), stats.jitter_rfc3550_ns);

    // Sample stddev for [10, 20]:
    // variance = ((10 - 15)^2 + (20 - 15)^2) / (2 - 1) = (25 + 25) / 1 = 50
    // stddev = sqrt(50) = 7.0710678 ms = 7_071_068 ns
    try testing.expect(stats.stddev_ns != null);
    try testing.expectEqual(@as(u64, 7_071_068), stats.stddev_ns.?);
}

test "many samples odd count with outliers and percentiles" {
    // 5 samples with an outlier: [10ms, 12ms, 11ms, 50ms (outlier), 13ms]
    const samples = [_]u64{
        10_000_000,
        12_000_000,
        11_000_000,
        50_000_000, // Outlier preserved, not hidden
        13_000_000,
    };
    const stats = try LatencyStats.calculate(testing.allocator, &samples, 5);

    try testing.expectEqual(@as(u32, 5), stats.total_samples);
    try testing.expectEqual(@as(u32, 5), stats.successful_samples);
    try testing.expectEqual(@as(u32, 0), stats.failed_samples);

    // Sorted: 10, 11, 12, 13, 50
    try testing.expectEqual(@as(?u64, 10_000_000), stats.min_ns);
    try testing.expectEqual(@as(?u64, 50_000_000), stats.max_ns);
    // Mean: (10 + 11 + 12 + 13 + 50) / 5 = 96 / 5 = 19.2 ms = 19_200_000 ns
    try testing.expectEqual(@as(?u64, 19_200_000), stats.mean_ns);
    // Median: 3rd element in sorted -> 12 ms
    try testing.expectEqual(@as(?u64, 12_000_000), stats.median_ns);

    // p75 is meaningful for k >= 4:
    // rank = ceil(0.75 * 5) = ceil(3.75) = 4 -> index 3 (4th element: 13 ms)
    try testing.expect(stats.percentiles.p75_ns != null);
    try testing.expectEqual(@as(u64, 13_000_000), stats.percentiles.p75_ns.?);

    // p90 requires k >= 10, so null for k = 5
    try testing.expect(stats.percentiles.p90_ns == null);

    // RFC 3550 Jitter:
    // Consecutive diffs: |12 - 10| = 2, |11 - 12| = 1, |50 - 11| = 39, |13 - 50| = 37
    // sum = 2 + 1 + 39 + 37 = 79 ms
    // mean jitter = 79 / 4 = 19.75 ms = 19_750_000 ns
    try testing.expectEqual(@as(?u64, 19_750_000), stats.jitter_rfc3550_ns);
}

test "large sample set with decile and 95th percentiles" {
    // 20 samples from 1ms to 20ms
    var samples: [20]u64 = undefined;
    for (&samples, 0..) |*s, i| {
        s.* = @as(u64, @intCast(i + 1)) * 1_000_000;
    }

    const stats = try LatencyStats.calculate(testing.allocator, &samples, 20);

    try testing.expectEqual(@as(?u64, 1_000_000), stats.min_ns);
    try testing.expectEqual(@as(?u64, 20_000_000), stats.max_ns);
    try testing.expectEqual(@as(?u64, 10_500_000), stats.median_ns);

    // p75 for 20: rank = ceil(0.75 * 20) = 15 -> index 14 -> 15ms
    try testing.expectEqual(@as(?u64, 15_000_000), stats.percentiles.p75_ns);
    // p90 for 20: rank = ceil(0.90 * 20) = 18 -> index 17 -> 18ms
    try testing.expectEqual(@as(?u64, 18_000_000), stats.percentiles.p90_ns);
    // p95 for 20: rank = ceil(0.95 * 20) = 19 -> index 18 -> 19ms
    try testing.expectEqual(@as(?u64, 19_000_000), stats.percentiles.p95_ns);
    // p99 requires 100 samples, so null for 20
    try testing.expect(stats.percentiles.p99_ns == null);
}

test "deterministic json serialization for latency stats" {
    const samples = [_]u64{ 10_000_000, 20_000_000, 30_000_000, 40_000_000 };
    const stats = try LatencyStats.calculate(testing.allocator, &samples, 5); // 1 failure out of 5

    try testing.expectEqual(@as(f64, 20.0), stats.loss_percent);

    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try stats.toJson(fbs.writer());

    const json = fbs.getWritten();
    try testing.expect(std.mem.startsWith(u8, json, "{\"total_samples\":5,\"successful_samples\":4,\"failed_samples\":1,\"loss_percent\":20.00,"));
    try testing.expect(std.mem.indexOf(u8, json, "\"min_ns\":10000000") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"max_ns\":40000000") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"p75_ns\":30000000") != null);
}
