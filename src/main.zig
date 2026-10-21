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

    if (args.len < 2) {
        try cli.printHelp(stdout);
        std.process.exit(cli.ExitCodes.success);
    }

    const cmd = cli.parseCommand(args[1]);
    switch (cmd) {
        .help => {
            try cli.printHelp(stdout);
            std.process.exit(cli.ExitCodes.success);
        },
        .version => {
            try stdout.print("WireScope v{s} (Zig {s})\n", .{
                wirescope.version,
                @import("builtin").zig_version_string,
            });
            std.process.exit(cli.ExitCodes.success);
        },
        .diagnose, .audit, .lab => {
            try stdout.print("Command '{s}' recognized (skeleton milestone active).\n", .{args[1]});
            std.process.exit(cli.ExitCodes.success);
        },
        .unknown => {
            try stderr.print("Error: Unknown command '{s}'. Run 'wirescope help' for usage.\n", .{args[1]});
            std.process.exit(cli.ExitCodes.invalid_input);
        },
    }
}

test "main CLI smoke test" {
    const testing = std.testing;
    try testing.expect(wirescope.version.len > 0);
}
