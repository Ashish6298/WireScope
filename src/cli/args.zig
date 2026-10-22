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
    tls,
    https,
    diagnose,
    audit,
    assess,
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
        if (std.mem.eql(u8, str, "tls") or std.mem.eql(u8, str, "ssl")) return .tls;
        if (std.mem.eql(u8, str, "https") or std.mem.eql(u8, str, "http")) return .https;
        if (std.mem.eql(u8, str, "diagnose")) return .diagnose;
        if (std.mem.eql(u8, str, "audit")) return .audit;
        if (std.mem.eql(u8, str, "assess") or std.mem.eql(u8, str, "assessment")) return .assess;
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
    InvalidRedirectLimit,
    InvalidResponseSize,
    InvalidCapValue,
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
    max_redirects: u32 = 5,
    max_response_bytes: usize = 1024 * 1024,
    allow_redirect_scope_expansion: bool = false,
    output_path: ?[]const u8 = null,
    config_path: ?[]const u8 = null,
    profile_path: ?[]const u8 = null,
    resolvers: ?[]const u8 = null,
    ca_bundle_path: ?[]const u8 = null,
    insecure: bool = false,
    server_name: ?[]const u8 = null,
    non_interactive: bool = false,
    dry_run: bool = false,
    show_help: bool = false,
    show_version: bool = false,

    // Phase 8.1, 8.2, 8.3 & 8.4 reconnaissance and inventory options
    ports: ?[]const u8 = null,
    exclusions: ?[]const u8 = null,
    confirm_authorized: bool = false,
    preview: bool = false,
    max_hosts: usize = 256,
    max_ports: usize = 100,
    max_operations: usize = 5000,
    concurrency: u16 = 4,
    rate_limit_delay_ms: u32 = 5,
    inventory: bool = false,
    diff_path: ?[]const u8 = null,
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
        } else if (std.mem.eql(u8, arg, "--ca-bundle") or std.mem.eql(u8, arg, "--ca")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            result.ca_bundle_path = args[i];
        } else if (std.mem.eql(u8, arg, "--insecure") or std.mem.eql(u8, arg, "--insecure-skip-verify") or std.mem.eql(u8, arg, "-k")) {
            result.insecure = true;
        } else if (std.mem.eql(u8, arg, "--server-name") or std.mem.eql(u8, arg, "--sni")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            result.server_name = args[i];
        } else if (std.mem.eql(u8, arg, "--max-redirects") or std.mem.eql(u8, arg, "--redirects")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            const r_str = args[i];
            const parsed_r = std.fmt.parseInt(u32, r_str, 10) catch return error.InvalidRedirectLimit;
            if (parsed_r > 50) return error.InvalidRedirectLimit;
            result.max_redirects = parsed_r;
        } else if (std.mem.eql(u8, arg, "--max-response-size") or std.mem.eql(u8, arg, "--max-size")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            const s_str = args[i];
            const parsed_s = std.fmt.parseInt(usize, s_str, 10) catch return error.InvalidResponseSize;
            if (parsed_s == 0 or parsed_s > 100 * 1024 * 1024) return error.InvalidResponseSize;
            result.max_response_bytes = parsed_s;
        } else if (std.mem.eql(u8, arg, "--allow-redirect-scope-expansion") or std.mem.eql(u8, arg, "--allow-out-of-scope-redirects")) {
            result.allow_redirect_scope_expansion = true;
        } else if (std.mem.eql(u8, arg, "--ports")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            result.ports = args[i];
        } else if (std.mem.eql(u8, arg, "--exclude") or std.mem.eql(u8, arg, "--exclusions")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            result.exclusions = args[i];
        } else if (std.mem.eql(u8, arg, "--confirm-authorized")) {
            result.confirm_authorized = true;
        } else if (std.mem.eql(u8, arg, "--preview")) {
            result.preview = true;
        } else if (std.mem.eql(u8, arg, "--max-hosts")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            const h_str = args[i];
            const parsed_h = std.fmt.parseInt(usize, h_str, 10) catch return error.InvalidCapValue;
            if (parsed_h == 0) return error.InvalidCapValue;
            result.max_hosts = parsed_h;
        } else if (std.mem.eql(u8, arg, "--max-ports")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            const p_str = args[i];
            const parsed_p = std.fmt.parseInt(usize, p_str, 10) catch return error.InvalidCapValue;
            if (parsed_p == 0) return error.InvalidCapValue;
            result.max_ports = parsed_p;
        } else if (std.mem.eql(u8, arg, "--max-operations") or std.mem.eql(u8, arg, "--max-ops")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            const op_str = args[i];
            const parsed_op = std.fmt.parseInt(usize, op_str, 10) catch return error.InvalidCapValue;
            if (parsed_op == 0) return error.InvalidCapValue;
            result.max_operations = parsed_op;
        } else if (std.mem.eql(u8, arg, "--concurrency")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            const con_str = args[i];
            const parsed_con = std.fmt.parseInt(u16, con_str, 10) catch return error.InvalidCapValue;
            if (parsed_con == 0 or parsed_con > 64) return error.InvalidCapValue;
            result.concurrency = parsed_con;
        } else if (std.mem.eql(u8, arg, "--rate-limit") or std.mem.eql(u8, arg, "--rate-limit-ms")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            const rl_str = args[i];
            const parsed_rl = std.fmt.parseInt(u32, rl_str, 10) catch return error.InvalidCapValue;
            if (parsed_rl > 60000) return error.InvalidCapValue;
            result.rate_limit_delay_ms = parsed_rl;
        } else if (std.mem.eql(u8, arg, "--inventory")) {
            result.inventory = true;
        } else if (std.mem.eql(u8, arg, "--diff")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            result.diff_path = args[i];
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
    if (result.command == .tls and result.target == null) {
        result.target = result.subcommand;
    }
    if (result.command == .https and result.target == null) {
        result.target = result.subcommand;
    }
    if (result.command == .discover and result.target == null) {
        result.target = result.subcommand;
    }
    if (result.command == .audit and result.target == null) {
        if (result.subcommand) |sub| {
            if (std.mem.startsWith(u8, sub, "http://") or std.mem.startsWith(u8, sub, "https://")) {
                result.target = sub;
                result.subcommand = "http";
            }
        }
    }
    if (result.command == .assess and result.target == null) {
        result.target = result.subcommand;
    }
    if (result.dry_run) {
        result.preview = true;
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

test "parse tls command and flags" {
    const args1 = [_][]const u8{ "wirescope", "tls", "example.com:443", "--insecure", "--ca-bundle", "ca.pem", "--server-name", "sni.example.com" };
    const parsed1 = try parse(&args1);
    try testing.expectEqual(Command.tls, parsed1.command);
    try testing.expectEqualStrings("example.com:443", parsed1.target.?);
    try testing.expect(parsed1.insecure);
    try testing.expectEqualStrings("ca.pem", parsed1.ca_bundle_path.?);
    try testing.expectEqualStrings("sni.example.com", parsed1.server_name.?);

    const args2 = [_][]const u8{ "wirescope", "diagnose", "tls", "example.com" };
    const parsed2 = try parse(&args2);
    try testing.expectEqual(Command.diagnose, parsed2.command);
    try testing.expectEqualStrings("tls", parsed2.subcommand.?);
    try testing.expectEqualStrings("example.com", parsed2.target.?);
    try testing.expect(!parsed2.insecure);
}

test "parse https command and flags" {
    const args1 = [_][]const u8{ "wirescope", "https", "https://example.com/api", "--max-redirects", "3", "--max-response-size", "2048", "--allow-redirect-scope-expansion" };
    const parsed1 = try parse(&args1);
    try testing.expectEqual(Command.https, parsed1.command);
    try testing.expectEqualStrings("https://example.com/api", parsed1.target.?);
    try testing.expectEqual(@as(u32, 3), parsed1.max_redirects);
    try testing.expectEqual(@as(usize, 2048), parsed1.max_response_bytes);
    try testing.expect(parsed1.allow_redirect_scope_expansion);

    const bad_redir = [_][]const u8{ "wirescope", "https", "https://example.com", "--max-redirects", "100" };
    try testing.expectError(error.InvalidRedirectLimit, parse(&bad_redir));

    const bad_size = [_][]const u8{ "wirescope", "https", "https://example.com", "--max-response-size", "0" };
    try testing.expectError(error.InvalidResponseSize, parse(&bad_size));
}

test "parse discover command and reconnaissance flags" {
    const args1 = [_][]const u8{
        "wirescope",        "discover",
        "192.168.1.0/24",   "--ports",
        "80,443,8080-8085", "--exclude",
        "192.168.1.1",      "--confirm-authorized",
        "--preview",        "--max-hosts",
        "500",              "--max-ports",
        "50",               "--max-operations",
        "2000",
    };
    const parsed1 = try parse(&args1);
    try testing.expectEqual(Command.discover, parsed1.command);
    try testing.expectEqualStrings("192.168.1.0/24", parsed1.target.?);
    try testing.expectEqualStrings("80,443,8080-8085", parsed1.ports.?);
    try testing.expectEqualStrings("192.168.1.1", parsed1.exclusions.?);
    try testing.expect(parsed1.confirm_authorized);
    try testing.expect(parsed1.preview);
    try testing.expectEqual(@as(usize, 500), parsed1.max_hosts);
    try testing.expectEqual(@as(usize, 50), parsed1.max_ports);
    try testing.expectEqual(@as(usize, 2000), parsed1.max_operations);
}

test "parse audit http command and options" {
    const args1 = [_][]const u8{ "wirescope", "audit", "http", "https://localhost:8443/", "--format", "json", "--max-redirects", "3", "--allow-redirect-scope-expansion" };
    const parsed1 = try parse(&args1);
    try testing.expectEqual(Command.audit, parsed1.command);
    try testing.expectEqualStrings("http", parsed1.subcommand.?);
    try testing.expectEqualStrings("https://localhost:8443/", parsed1.target.?);
    try testing.expectEqual(OutputFormat.json, parsed1.format);
    try testing.expectEqual(@as(u32, 3), parsed1.max_redirects);
    try testing.expect(parsed1.allow_redirect_scope_expansion);

    const args2 = [_][]const u8{ "wirescope", "audit", "https://localhost:8443/" };
    const parsed2 = try parse(&args2);
    try testing.expectEqual(Command.audit, parsed2.command);
    try testing.expectEqualStrings("http", parsed2.subcommand.?);
    try testing.expectEqualStrings("https://localhost:8443/", parsed2.target.?);
}
