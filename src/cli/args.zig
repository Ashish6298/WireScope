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
    interfaces,
    routes,
    listeners,
    dns,
    tcp,
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
        if (std.mem.eql(u8, str, "interfaces") or std.mem.eql(u8, str, "interface")) return .interfaces;
        if (std.mem.eql(u8, str, "routes") or std.mem.eql(u8, str, "route")) return .routes;
        if (std.mem.eql(u8, str, "listeners") or std.mem.eql(u8, str, "listener") or std.mem.eql(u8, str, "ports")) return .listeners;
        if (std.mem.eql(u8, str, "dns") or std.mem.eql(u8, str, "resolve")) return .dns;
        if (std.mem.eql(u8, str, "tcp") or std.mem.eql(u8, str, "connect") or std.mem.eql(u8, str, "latency")) return .tcp;
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
    InvalidCount,
    InvalidInterval,
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
    count: u32 = 1,
    interval_ms: u32 = 1000,
    output_path: ?[]const u8 = null,
    config_path: ?[]const u8 = null,
    profile_path: ?[]const u8 = null,
    resolvers: ?[]const u8 = null,
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
        } else if (std.mem.eql(u8, arg, "--count") or std.mem.eql(u8, arg, "-c")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            const c_str = args[i];
            const parsed_c = std.fmt.parseInt(u32, c_str, 10) catch return error.InvalidCount;
            if (parsed_c == 0 or parsed_c > 100) return error.InvalidCount;
            result.count = parsed_c;
        } else if (std.mem.eql(u8, arg, "--interval") or std.mem.eql(u8, arg, "-i")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            const int_str = args[i];
            const parsed_int = std.fmt.parseInt(u32, int_str, 10) catch return error.InvalidInterval;
            if (parsed_int > 60000) return error.InvalidInterval;
            result.interval_ms = parsed_int;
        } else if (std.mem.eql(u8, arg, "--output") or std.mem.eql(u8, arg, "-o")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            result.output_path = args[i];
        } else if (std.mem.eql(u8, arg, "--config")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            result.config_path = args[i];
        } else if (std.mem.eql(u8, arg, "--profile") or std.mem.eql(u8, arg, "-p")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            result.profile_path = args[i];
        } else if (std.mem.eql(u8, arg, "--compare") or std.mem.eql(u8, arg, "--resolvers")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            result.resolvers = args[i];
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

    if (result.command == .dns and result.target == null) {
        result.target = result.subcommand;
    }
    if (result.command == .tcp and result.target == null) {
        result.target = result.subcommand;
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
    const args = [_][]const u8{ "wirescope", "diagnose", "tcp", "127.0.0.1:80", "--format", "json", "-t", "2500", "--config", "cfg.json", "--profile", "prof.json" };
    const parsed = try parse(&args);
    try testing.expectEqual(Command.diagnose, parsed.command);
    try testing.expectEqualStrings("tcp", parsed.subcommand.?);
    try testing.expectEqualStrings("127.0.0.1:80", parsed.target.?);
    try testing.expectEqual(OutputFormat.json, parsed.format);
    try testing.expectEqual(@as(u32, 2500), parsed.timeout_ms);
    try testing.expectEqualStrings("cfg.json", parsed.config_path.?);
    try testing.expectEqualStrings("prof.json", parsed.profile_path.?);

    const tcp_cmd_args = [_][]const u8{ "wirescope", "tcp", "localhost:8080" };
    const parsed_tcp = try parse(&tcp_cmd_args);
    try testing.expectEqual(Command.tcp, parsed_tcp.command);
    try testing.expectEqualStrings("localhost:8080", parsed_tcp.target.?);

    const compare_args = [_][]const u8{ "wirescope", "dns", "example.com", "--compare", "1.1.1.1,8.8.8.8" };
    const parsed_compare = try parse(&compare_args);
    try testing.expectEqual(Command.dns, parsed_compare.command);
    try testing.expectEqualStrings("example.com", parsed_compare.target.?);
    try testing.expectEqualStrings("1.1.1.1,8.8.8.8", parsed_compare.resolvers.?);
}

test "parse count and interval options" {
    const args = [_][]const u8{ "wirescope", "tcp", "127.0.0.1:80", "-c", "5", "-i", "250" };
    const parsed = try parse(&args);
    try testing.expectEqual(Command.tcp, parsed.command);
    try testing.expectEqualStrings("127.0.0.1:80", parsed.target.?);
    try testing.expectEqual(@as(u32, 5), parsed.count);
    try testing.expectEqual(@as(u32, 250), parsed.interval_ms);

    const long_args = [_][]const u8{ "wirescope", "diagnose", "latency", "127.0.0.1:80", "--count", "10", "--interval", "500" };
    const parsed_long = try parse(&long_args);
    try testing.expectEqual(@as(u32, 10), parsed_long.count);
    try testing.expectEqual(@as(u32, 500), parsed_long.interval_ms);
}

test "parse rejects invalid count and interval" {
    const zero_count = [_][]const u8{ "wirescope", "tcp", "127.0.0.1:80", "-c", "0" };
    try testing.expectError(error.InvalidCount, parse(&zero_count));

    const huge_count = [_][]const u8{ "wirescope", "tcp", "127.0.0.1:80", "-c", "101" };
    try testing.expectError(error.InvalidCount, parse(&huge_count));

    const huge_interval = [_][]const u8{ "wirescope", "tcp", "127.0.0.1:80", "-i", "70000" };
    try testing.expectError(error.InvalidInterval, parse(&huge_interval));
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
