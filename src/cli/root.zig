const std = @import("std");
const testing = std.testing;
const wirescope = @import("wirescope");

pub const exit_codes = @import("exit_codes.zig");
pub const ExitCodes = exit_codes.ExitCodes;

pub const args_mod = @import("args.zig");
pub const ParsedCli = args_mod.ParsedCli;
pub const Command = args_mod.Command;
pub const OutputFormat = args_mod.OutputFormat;
pub const parseArgs = args_mod.parse;

pub const capabilities = @import("capabilities.zig");
pub const printCapabilities = capabilities.printCapabilities;

pub const help = @import("help.zig");
pub const printRootHelp = help.printRootHelp;
pub const printSubcommandHelp = help.printSubcommandHelp;

/// Main CLI execution entry point
pub fn execute(raw_args: []const []const u8, stdout: anytype, stderr: anytype) u8 {
    const parsed = parseArgs(raw_args) catch |err| {
        switch (err) {
            error.MissingOptionValue => {
                stderr.print("Error: Option requires a parameter value.\nRun 'wirescope --help' for usage.\n", .{}) catch {};
            },
            error.InvalidTimeout => {
                stderr.print("Error: Invalid timeout. Must be a positive integer between 1 and 300000 ms.\n", .{}) catch {};
            },
            error.InvalidFormat => {
                stderr.print("Error: Invalid output format. Supported formats: terminal, json, markdown.\n", .{}) catch {};
            },
            error.UnknownOption => {
                stderr.print("Error: Unrecognized option flag.\nRun 'wirescope --help' for usage.\n", .{}) catch {};
            },
        }
        return ExitCodes.invalid_input;
    };

    // 1. Help dispatch
    if (parsed.show_help or parsed.command == .help) {
        if (parsed.subcommand) |sub| {
            printSubcommandHelp(stdout, sub) catch return ExitCodes.operational_failure;
        } else if (parsed.raw_command) |raw| {
            if (!std.mem.eql(u8, raw, "help")) {
                printSubcommandHelp(stdout, raw) catch return ExitCodes.operational_failure;
            } else {
                printRootHelp(stdout) catch return ExitCodes.operational_failure;
            }
        } else {
            printRootHelp(stdout) catch return ExitCodes.operational_failure;
        }
        return ExitCodes.success;
    }

    // 2. Version dispatch
    if (parsed.show_version or parsed.command == .version) {
        if (parsed.format == .json) {
            stdout.print(
                \\{{"version":"{s}","zig_version":"{s}","schema_version":1}}
                \\
            , .{ wirescope.version, @import("builtin").zig_version_string }) catch return ExitCodes.operational_failure;
        } else {
            stdout.print("WireScope v{s} (Zig {s})\n", .{
                wirescope.version,
                @import("builtin").zig_version_string,
            }) catch return ExitCodes.operational_failure;
        }
        return ExitCodes.success;
    }

    // 3. Capabilities dispatch
    if (parsed.command == .capabilities) {
        printCapabilities(stdout, parsed.format) catch return ExitCodes.operational_failure;
        return ExitCodes.success;
    }

    // 4. Unknown command dispatch
    if (parsed.command == .unknown) {
        if (parsed.raw_command) |rc| {
            stderr.print("Error: Unknown command '{s}'. Run 'wirescope --help' for usage.\n", .{rc}) catch {};
        } else {
            stderr.print("Error: Unknown command. Run 'wirescope --help' for usage.\n", .{}) catch {};
        }
        return ExitCodes.invalid_input;
    }

    // 5. Network Interfaces dispatch
    const is_interfaces_cmd = (parsed.command == .interfaces) or
        (parsed.command == .diagnose and parsed.subcommand != null and std.mem.eql(u8, parsed.subcommand.?, "interfaces"));

    if (is_interfaces_cmd) {
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        var iface_res = wirescope.platform.enumerateInterfaces(allocator) catch |err| {
            stderr.print("Error: Failed to enumerate network interfaces: {s}\n", .{@errorName(err)}) catch {};
            return ExitCodes.operational_failure;
        };
        defer iface_res.deinit(allocator);

        switch (parsed.format) {
            .json => iface_res.toJson(stdout) catch return ExitCodes.operational_failure,
            .terminal, .markdown => iface_res.toTerminal(stdout) catch return ExitCodes.operational_failure,
        }
        return ExitCodes.success;
    }

    // 6. Routing Table dispatch
    const is_routes_cmd = (parsed.command == .routes) or
        (parsed.command == .diagnose and parsed.subcommand != null and std.mem.eql(u8, parsed.subcommand.?, "routes"));

    if (is_routes_cmd) {
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        var route_res = wirescope.platform.inspectRoutes(allocator) catch |err| {
            stderr.print("Error: Failed to inspect routing table: {s}\n", .{@errorName(err)}) catch {};
            return ExitCodes.operational_failure;
        };
        defer route_res.deinit(allocator);

        switch (parsed.format) {
            .json => route_res.toJson(stdout) catch return ExitCodes.operational_failure,
            .terminal, .markdown => route_res.toTerminal(stdout) catch return ExitCodes.operational_failure,
        }
        return ExitCodes.success;
    }

    // 7. Local Listening Services dispatch
    const is_listeners_cmd = (parsed.command == .listeners) or
        (parsed.command == .diagnose and parsed.subcommand != null and std.mem.eql(u8, parsed.subcommand.?, "listeners")) or
        (parsed.command == .audit and parsed.subcommand != null and std.mem.eql(u8, parsed.subcommand.?, "local"));

    if (is_listeners_cmd) {
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        var listener_res = wirescope.platform.inspectListeners(allocator) catch |err| {
            stderr.print("Error: Failed to inspect listening services: {s}\n", .{@errorName(err)}) catch {};
            return ExitCodes.operational_failure;
        };
        defer listener_res.deinit(allocator);

        switch (parsed.format) {
            .json => listener_res.toJson(stdout) catch return ExitCodes.operational_failure,
            .terminal, .markdown => listener_res.toTerminal(stdout) catch return ExitCodes.operational_failure,
        }
        return ExitCodes.success;
    }

    // 8. DNS Resolution dispatch
    const is_dns_cmd = (parsed.command == .dns) or
        (parsed.command == .diagnose and parsed.subcommand != null and std.mem.eql(u8, parsed.subcommand.?, "dns"));

    if (is_dns_cmd) {
        const target = parsed.target orelse {
            stderr.print("Error: Target hostname required for DNS diagnosis. Usage: wirescope dns <hostname>\n", .{}) catch {};
            return ExitCodes.invalid_input;
        };

        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        // 8a. Optional multi-resolver comparison mode
        if (parsed.resolvers) |res_list_str| {
            var resolver_list = std.ArrayList(wirescope.probes.Resolver).init(allocator);
            defer resolver_list.deinit();
            var label_list = std.ArrayList([]const u8).init(allocator);
            defer label_list.deinit();

            var udp_resolvers = std.ArrayList(wirescope.probes.CustomUdpResolver).init(allocator);
            defer udp_resolvers.deinit();

            var iter = std.mem.splitScalar(u8, res_list_str, ',');
            while (iter.next()) |raw_tok| {
                const tok = std.mem.trim(u8, raw_tok, " ");
                if (tok.len == 0) continue;

                if (std.mem.eql(u8, tok, "system") or std.mem.eql(u8, tok, "local")) {
                    resolver_list.append(wirescope.probes.SystemResolver.resolver()) catch return ExitCodes.operational_failure;
                    label_list.append("System Resolver") catch return ExitCodes.operational_failure;
                } else {
                    udp_resolvers.append(wirescope.probes.CustomUdpResolver{
                        .resolver_ip = tok,
                        .timeout_ms = parsed.timeout_ms,
                    }) catch return ExitCodes.operational_failure;
                }
            }

            for (udp_resolvers.items) |*ur| {
                resolver_list.append(ur.resolver()) catch return ExitCodes.operational_failure;
                label_list.append(ur.resolver_ip) catch return ExitCodes.operational_failure;
            }

            if (resolver_list.items.len == 0) {
                stderr.print("Error: No valid resolvers specified in --compare.\n", .{}) catch {};
                return ExitCodes.invalid_input;
            }

            var comp_res = wirescope.probes.compareResolvers(
                allocator,
                target,
                .both,
                resolver_list.items,
                label_list.items,
            ) catch |err| {
                stderr.print("Error: Resolver comparison execution failed: {s}\n", .{@errorName(err)}) catch {};
                return ExitCodes.operational_failure;
            };
            defer comp_res.deinit(allocator);

            switch (parsed.format) {
                .json => comp_res.toJson(stdout) catch return ExitCodes.operational_failure,
                .terminal, .markdown => comp_res.toTerminal(stdout) catch return ExitCodes.operational_failure,
            }

            return ExitCodes.success;
        }

        // 8b. Single resolver execution (System default)
        const resolver = wirescope.probes.SystemResolver.resolver();
        var dns_res = resolver.resolve(allocator, target, .both) catch |err| {
            stderr.print("Error: DNS resolution execution failed: {s}\n", .{@errorName(err)}) catch {};
            return ExitCodes.operational_failure;
        };
        defer dns_res.deinit(allocator);

        switch (parsed.format) {
            .json => {
                var envelope = dns_res.toEnvelope(allocator, "op_dns_cli", null) catch return ExitCodes.operational_failure;
                defer envelope.deinit(allocator);
                envelope.toJson(stdout) catch return ExitCodes.operational_failure;
            },
            .terminal, .markdown => dns_res.toTerminal(stdout) catch return ExitCodes.operational_failure,
        }

        if (dns_res.failure_category == .malformed_input) {
            return ExitCodes.invalid_input;
        } else if (dns_res.failure_category != .success) {
            return ExitCodes.findings_or_violations;
        }
        return ExitCodes.success;
    }

    // 9. Diagnostics, Audits, Reconnaissance, and Lab commands (skeleton dispatcher)
    switch (parsed.format) {
        .json => {
            stdout.print(
                \\{{"command":"{s}","subcommand":{s},"status":"ready","dry_run":{s},"timeout_ms":{d}}}
                \\
            , .{
                @tagName(parsed.command),
                if (parsed.subcommand) |s| s else "null",
                if (parsed.dry_run) "true" else "false",
                parsed.timeout_ms,
            }) catch return ExitCodes.operational_failure;
        },
        .terminal, .markdown => {
            stdout.print("Command '{s}' recognized (subcommand: {s}, dry_run: {s}, timeout: {d}ms).\n", .{
                @tagName(parsed.command),
                if (parsed.subcommand) |s| s else "none",
                if (parsed.dry_run) "true" else "false",
                parsed.timeout_ms,
            }) catch return ExitCodes.operational_failure;
        },
    }

    return ExitCodes.success;
}

test "cli module integration" {
    _ = args_mod;
    _ = capabilities;
    _ = help;
    _ = exit_codes;
}

test "execute help and version" {
    var out_buf: [4096]u8 = undefined;
    var err_buf: [1024]u8 = undefined;

    var out_fbs = std.io.fixedBufferStream(&out_buf);
    var err_fbs = std.io.fixedBufferStream(&err_buf);

    const help_args = [_][]const u8{ "wirescope", "--help" };
    const code1 = execute(&help_args, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code1);
    try testing.expect(out_fbs.getWritten().len > 0);

    out_fbs.reset();
    err_fbs.reset();

    const ver_args = [_][]const u8{ "wirescope", "version", "--format", "json" };
    const code2 = execute(&ver_args, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code2);
    try testing.expect(std.mem.startsWith(u8, out_fbs.getWritten(), "{\"version\":"));
    try testing.expectEqual(@as(usize, 0), err_fbs.getWritten().len);
}

test "execute interfaces command" {
    var out_buf: [8192]u8 = undefined;
    var err_buf: [1024]u8 = undefined;

    var out_fbs = std.io.fixedBufferStream(&out_buf);
    var err_fbs = std.io.fixedBufferStream(&err_buf);

    const iface_args = [_][]const u8{ "wirescope", "diagnose", "interfaces", "--format", "json" };
    const code = execute(&iface_args, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code);
    try testing.expect(std.mem.startsWith(u8, out_fbs.getWritten(), "{\"interfaces\":["));
    try testing.expectEqual(@as(usize, 0), err_fbs.getWritten().len);
}

test "execute routes command" {
    var out_buf: [16384]u8 = undefined;
    var err_buf: [1024]u8 = undefined;

    var out_fbs = std.io.fixedBufferStream(&out_buf);
    var err_fbs = std.io.fixedBufferStream(&err_buf);

    const route_args = [_][]const u8{ "wirescope", "diagnose", "routes", "--format", "json" };
    const code = execute(&route_args, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code);
    try testing.expect(std.mem.startsWith(u8, out_fbs.getWritten(), "{\"default_gateway\":"));
    try testing.expectEqual(@as(usize, 0), err_fbs.getWritten().len);
}

test "execute listeners command" {
    var out_buf: [32768]u8 = undefined;
    var err_buf: [1024]u8 = undefined;

    var out_fbs = std.io.fixedBufferStream(&out_buf);
    var err_fbs = std.io.fixedBufferStream(&err_buf);

    const listener_args = [_][]const u8{ "wirescope", "listeners", "--format", "json" };
    const code = execute(&listener_args, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code);
    try testing.expect(std.mem.startsWith(u8, out_fbs.getWritten(), "{\"permission_limited\":"));
    try testing.expectEqual(@as(usize, 0), err_fbs.getWritten().len);
}

test "execute invalid command returns invalid_input exit code" {
    var out_buf: [512]u8 = undefined;
    var err_buf: [512]u8 = undefined;

    var out_fbs = std.io.fixedBufferStream(&out_buf);
    var err_fbs = std.io.fixedBufferStream(&err_buf);

    const bad_args = [_][]const u8{ "wirescope", "invalid-subcmd-1234" };
    const code = execute(&bad_args, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.invalid_input, code);
    try testing.expect(err_fbs.getWritten().len > 0);
}

test "execute dns command with valid, invalid, and missing target" {
    var out_buf: [4096]u8 = undefined;
    var err_buf: [1024]u8 = undefined;

    // 1. Valid localhost resolution with JSON format
    var out_fbs = std.io.fixedBufferStream(&out_buf);
    var err_fbs = std.io.fixedBufferStream(&err_buf);
    const valid_dns = [_][]const u8{ "wirescope", "dns", "localhost", "--format", "json" };
    const code1 = execute(&valid_dns, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code1);
    try testing.expect(std.mem.startsWith(u8, out_fbs.getWritten(), "{\"operation_id\":"));
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"operation_type\":\"dns\"") != null);
    try testing.expectEqual(@as(usize, 0), err_fbs.getWritten().len);

    // 2. Malformed hostname rejected before network activity
    out_fbs.reset();
    err_fbs.reset();
    const invalid_dns = [_][]const u8{ "wirescope", "dns", "illegal_char..com" };
    const code2 = execute(&invalid_dns, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.invalid_input, code2);

    // 3. Missing target hostname returns invalid_input
    out_fbs.reset();
    err_fbs.reset();
    const missing_target = [_][]const u8{ "wirescope", "dns" };
    const code3 = execute(&missing_target, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.invalid_input, code3);
    try testing.expect(err_fbs.getWritten().len > 0);

    // 4. Resolver comparison option (--compare)
    out_fbs.reset();
    err_fbs.reset();
    const compare_args = [_][]const u8{ "wirescope", "dns", "localhost", "--compare", "system", "--format", "json" };
    const code4 = execute(&compare_args, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code4);
    try testing.expect(std.mem.startsWith(u8, out_fbs.getWritten(), "{\"host\":\"localhost\""));
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"answers_match\":true") != null);
    try testing.expectEqual(@as(usize, 0), err_fbs.getWritten().len);
}
