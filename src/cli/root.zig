const std = @import("std");
const testing = std.testing;
const wirescope = @import("wirescope");
const core = wirescope.core;

pub const ExitCodes = struct {
    pub const success: u8 = 0;
    pub const findings_or_violations: u8 = 1;
    pub const invalid_input: u8 = 2;
    pub const operational_failure: u8 = 3;
    pub const cancelled: u8 = 4;
};

pub const CliCommand = enum {
    help,
    version,
    diagnose,
    audit,
    lab,
    unknown,
};

pub fn parseCommand(arg: []const u8) CliCommand {
    if (std.mem.eql(u8, arg, "help") or std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
        return .help;
    } else if (std.mem.eql(u8, arg, "version") or std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
        return .version;
    } else if (std.mem.eql(u8, arg, "diagnose")) {
        return .diagnose;
    } else if (std.mem.eql(u8, arg, "audit")) {
        return .audit;
    } else if (std.mem.eql(u8, arg, "lab")) {
        return .lab;
    } else {
        return .unknown;
    }
}

pub fn printHelp(writer: anytype) !void {
    try writer.print(
        \\WireScope — Local-First Network Diagnostics and Defensive Toolkit
        \\Usage: wirescope <command> [options]
        \\
        \\Commands:
        \\  diagnose    Run network diagnostics (DNS, TCP, TLS, interfaces)
        \\  audit       Run defensive configuration audits
        \\  lab         Execute local practice lab scenarios
        \\  version     Display WireScope version
        \\  help        Display this help message
        \\
    , .{});
}

test "CLI command parsing" {
    try testing.expectEqual(CliCommand.help, parseCommand("--help"));
    try testing.expectEqual(CliCommand.version, parseCommand("version"));
    try testing.expectEqual(CliCommand.diagnose, parseCommand("diagnose"));
    try testing.expectEqual(CliCommand.unknown, parseCommand("random-command"));
}
