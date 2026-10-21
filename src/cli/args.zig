const std = @import("std");
const testing = std.testing;

pub const OutputFormat = enum {
    terminal,
    json,
    markdown,

    pub fn fromString(str: []const u8) ?OutputFormat {
        if (std.mem.eql(u8, str, "terminal") or std.mem.eql(u8, str, "term")) return .terminal;
        if (std.mem.eql(u8, str, "json")) return .json;
        if (std.mem.eql(u8, str, "markdown") or std.mem.eql(u8, str, "md")) return .markdown;
        return null;
    }
};

pub const Command = enum {
    none,
    help,
    version,
    capabilities,
    diagnose,
    audit,
    discover,
    baseline,
    policy,
    history,
    report,
    lab,
    unknown,

    pub fn fromString(str: []const u8) Command {
        if (std.mem.eql(u8, str, "help")) return .help;
        if (std.mem.eql(u8, str, "version")) return .version;
        if (std.mem.eql(u8, str, "capabilities") or std.mem.eql(u8, str, "capability")) return .capabilities;
        if (std.mem.eql(u8, str, "diagnose")) return .diagnose;
        if (std.mem.eql(u8, str, "audit")) return .audit;
        if (std.mem.eql(u8, str, "discover")) return .discover;
        if (std.mem.eql(u8, str, "baseline")) return .baseline;
        if (std.mem.eql(u8, str, "policy")) return .policy;
        if (std.mem.eql(u8, str, "history")) return .history;
        if (std.mem.eql(u8, str, "report")) return .report;
        if (std.mem.eql(u8, str, "lab")) return .lab;
        return .unknown;
    }
};

pub const ParseError = error{
    MissingOptionValue,
    InvalidTimeout,
    InvalidFormat,
    UnknownOption,
};

pub const ParsedCli = struct {
    command: Command = .none,
    raw_command: ?[]const u8 = null,
    subcommand: ?[]const u8 = null,
    target: ?[]const u8 = null,
    format: OutputFormat = .terminal,
    timeout_ms: u32 = 5000,
    output_path: ?[]const u8 = null,
    non_interactive: bool = false,
    dry_run: bool = false,
    show_help: bool = false,
    show_version: bool = false,
};

pub fn parse(args: []const []const u8) ParseError!ParsedCli {
    var result = ParsedCli{};
    if (args.len <= 1) {
        result.command = .help;
        result.show_help = true;
        return result;
    }

    var i: usize = 1;
    var positional_count: usize = 0;

    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            result.show_help = true;
            if (result.command == .none) result.command = .help;
        } else if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
            result.show_version = true;
            if (result.command == .none) result.command = .version;
        } else if (std.mem.eql(u8, arg, "--non-interactive") or std.mem.eql(u8, arg, "-y")) {
            result.non_interactive = true;
        } else if (std.mem.eql(u8, arg, "--dry-run")) {
            result.dry_run = true;
        } else if (std.mem.eql(u8, arg, "--format") or std.mem.eql(u8, arg, "-f")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            const fmt_str = args[i];
            result.format = OutputFormat.fromString(fmt_str) orelse return error.InvalidFormat;
        } else if (std.mem.eql(u8, arg, "--timeout") or std.mem.eql(u8, arg, "-t")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            const t_str = args[i];
            const parsed_t = std.fmt.parseInt(u32, t_str, 10) catch return error.InvalidTimeout;
            if (parsed_t == 0 or parsed_t > 300000) return error.InvalidTimeout;
            result.timeout_ms = parsed_t;
        } else if (std.mem.eql(u8, arg, "--output") or std.mem.eql(u8, arg, "-o")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            result.output_path = args[i];
        } else if (std.mem.startsWith(u8, arg, "-")) {
            return error.UnknownOption;
        } else {
            // Positional arguments
            switch (positional_count) {
                0 => {
                    result.raw_command = arg;
                    result.command = Command.fromString(arg);
                    positional_count += 1;
                },
                1 => {
                    result.subcommand = arg;
                    positional_count += 1;
                },
                2 => {
                    result.target = arg;
                    positional_count += 1;
                },
                else => {
                    // Additional positional arguments can be target or trailing args
                    if (result.target == null) {
                        result.target = arg;
                    }
                },
            }
        }
    }

    return result;
}

test "parse empty or single arg defaults to help" {
    const args = [_][]const u8{"wirescope"};
    const parsed = try parse(&args);
    try testing.expectEqual(Command.help, parsed.command);
    try testing.expect(parsed.show_help);
}

test "parse version flag and command" {
    const args1 = [_][]const u8{ "wirescope", "--version" };
    const parsed1 = try parse(&args1);
    try testing.expect(parsed1.show_version);
    try testing.expectEqual(Command.version, parsed1.command);

    const args2 = [_][]const u8{ "wirescope", "version" };
    const parsed2 = try parse(&args2);
    try testing.expectEqual(Command.version, parsed2.command);
}

test "parse format and timeout options" {
    const args = [_][]const u8{ "wirescope", "diagnose", "tcp", "127.0.0.1:80", "--format", "json", "-t", "2500" };
    const parsed = try parse(&args);
    try testing.expectEqual(Command.diagnose, parsed.command);
    try testing.expectEqualStrings("tcp", parsed.subcommand.?);
    try testing.expectEqualStrings("127.0.0.1:80", parsed.target.?);
    try testing.expectEqual(OutputFormat.json, parsed.format);
    try testing.expectEqual(@as(u32, 2500), parsed.timeout_ms);
}

test "parse rejects invalid timeout and format" {
    const bad_t = [_][]const u8{ "wirescope", "diagnose", "--timeout", "0" };
    try testing.expectError(error.InvalidTimeout, parse(&bad_t));

    const bad_fmt = [_][]const u8{ "wirescope", "diagnose", "--format", "xml" };
    try testing.expectError(error.InvalidFormat, parse(&bad_fmt));

    const missing_val = [_][]const u8{ "wirescope", "diagnose", "--timeout" };
    try testing.expectError(error.MissingOptionValue, parse(&missing_val));

    const bad_flag = [_][]const u8{ "wirescope", "--nonexistent-flag" };
    try testing.expectError(error.UnknownOption, parse(&bad_flag));
}
