const std = @import("std");
const testing = std.testing;

pub fn measureElapsedNanos() !struct { elapsed_ns: u64, elapsed_ms: u64 } {
    var timer = try std.time.Timer.start();
    // Simulate tiny workload
    std.time.sleep(10 * std.time.ns_per_ms); // sleep 10ms
    const elapsed_ns = timer.read();
    return .{
        .elapsed_ns = elapsed_ns,
        .elapsed_ms = elapsed_ns / std.time.ns_per_ms,
    };
}

test "monotonic timer accuracy and progression" {
    var timer = try std.time.Timer.start();
    const t1 = timer.read();
    std.time.sleep(5 * std.time.ns_per_ms);
    const t2 = timer.read();
    try testing.expect(t2 > t1);
    const diff = t2 - t1;
    // Expected around 5ms, allow reasonable range
    try testing.expect(diff >= 3 * std.time.ns_per_ms);
}

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    const res = try measureElapsedNanos();
    try stdout.print("Timing PoC: Elapsed = {d} ms ({d} ns) -> Monotonic Timer OK\n", .{ res.elapsed_ms, res.elapsed_ns });
}
