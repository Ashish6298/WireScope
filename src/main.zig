const std = @import("std");
const wirescope = @import("wirescope");
const cli = @import("cli/root.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

    const exit_code = cli.execute(args, stdout, stderr);
    if (exit_code != cli.ExitCodes.success) {
        std.process.exit(exit_code);
    }
}

test "main CLI smoke test" {
    const testing = std.testing;
    _ = cli;
    try testing.expect(wirescope.version.len > 0);
}
