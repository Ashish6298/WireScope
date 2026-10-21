const std = @import("std");
const testing = std.testing;

pub fn add(a: i32, b: i32) i32 {
    return a + b;
}

test "minimal test suite" {
    try testing.expectEqual(@as(i32, 5), add(2, 3));
    try testing.expect(add(-1, 1) == 0);
}

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print("WireScope Minimal Zig Executable: OK (Zig {s})\n", .{@import("builtin").zig_version_string});
}
