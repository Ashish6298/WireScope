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
            error.InvalidCount => {
                stderr.print("Error: Invalid count. Must be a positive integer between 1 and 100.\n", .{}) catch {};
            },
            error.InvalidInterval => {
                stderr.print("Error: Invalid interval. Must be an integer between 0 and 60000 ms.\n", .{}) catch {};
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

    // 9. TCP Connectivity Probe dispatch
    const is_tcp_cmd = (parsed.command == .tcp) or
        (parsed.command == .diagnose and parsed.subcommand != null and (std.mem.eql(u8, parsed.subcommand.?, "tcp") or std.mem.eql(u8, parsed.subcommand.?, "latency")));

    if (is_tcp_cmd) {
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        var raw_target_opt: ?[]const u8 = null;
        var default_port: ?u16 = null;

        if (parsed.command == .tcp) {
            if (parsed.subcommand) |sub| {
                if (parsed.target) |tgt| {
                    if (std.mem.indexOfScalar(u8, sub, ':') == null) {
                        // "wirescope tcp localhost 80"
                        raw_target_opt = sub;
                        const p_num = std.fmt.parseInt(u32, tgt, 10) catch {
                            stderr.print("Error: Invalid port '{s}'. Must be an integer between 1 and 65535.\n", .{tgt}) catch {};
                            return ExitCodes.invalid_input;
                        };
                        default_port = wirescope.probes.validatePort(p_num) catch {
                            stderr.print("Error: Port {d} out of range (1-65535).\n", .{p_num}) catch {};
                            return ExitCodes.invalid_input;
                        };
                    } else {
                        raw_target_opt = sub;
                    }
                } else {
                    raw_target_opt = sub;
                }
            } else {
                raw_target_opt = parsed.target;
            }
        } else {
            // "wirescope diagnose tcp <target>" or "wirescope diagnose latency <target>"
            raw_target_opt = parsed.target;
        }

        const raw_target = raw_target_opt orelse {
            stderr.print("Error: Target specification required for TCP probe. Usage: wirescope tcp <host:port>\n", .{}) catch {};
            return ExitCodes.invalid_input;
        };

        const spec = wirescope.probes.parseTargetAndPort(raw_target, default_port) catch |err| {
            stderr.print("Error: Invalid target specification '{s}': {s}\n", .{ raw_target, @errorName(err) }) catch {};
            return ExitCodes.invalid_input;
        };

        var profile_id_opt: ?[]const u8 = null;
        if (parsed.profile_path) |prof_path| {
            const prof = wirescope.assessment.AssessmentProfile{
                .id = prof_path,
                .name = prof_path,
                .description = "",
                .scope = .{
                    .targets = &[_][]const u8{spec.host},
                    .ports = &[_]u16{spec.port},
                },
                .authorization_acknowledged = true,
            };
            if (!prof.isScopePermitted(spec.host, spec.port)) {
                stderr.print("Error: Target {s}:{d} is not authorized in profile scope.\n", .{ spec.host, spec.port }) catch {};
                return ExitCodes.invalid_input;
            }
            profile_id_opt = prof.id;
        }

        var effective_count = parsed.count;
        if (parsed.command == .diagnose and parsed.subcommand != null and std.mem.eql(u8, parsed.subcommand.?, "latency") and parsed.count == 1) {
            effective_count = 4;
        }

        if (effective_count > 1) {
            const cancel = wirescope.probes.CancellationToken.init();
            var batch_res = wirescope.probes.executeTcpBatchProbe(
                allocator,
                wirescope.probes.RealTcpConnector.connector(),
                spec.host,
                spec.port,
                effective_count,
                parsed.interval_ms,
                parsed.timeout_ms,
                &cancel,
            ) catch |err| {
                stderr.print("Error: TCP batch probe execution failed: {s}\n", .{@errorName(err)}) catch {};
                return ExitCodes.operational_failure;
            };
            defer batch_res.deinit(allocator);

            switch (parsed.format) {
                .json => {
                    batch_res.toJson(stdout) catch return ExitCodes.operational_failure;
                    stdout.writeAll("\n") catch return ExitCodes.operational_failure;
                },
                .terminal, .markdown => batch_res.toTerminal(stdout) catch return ExitCodes.operational_failure,
            }

            if (batch_res.is_partial) {
                return ExitCodes.cancelled;
            } else if (batch_res.stats.successful_samples == 0) {
                return ExitCodes.findings_or_violations;
            }
            return ExitCodes.success;
        }

        const cancel = wirescope.probes.CancellationToken.init();
        var tcp_res = wirescope.probes.RealTcpConnector.connector().connect(
            allocator,
            spec.host,
            spec.port,
            parsed.timeout_ms,
            &cancel,
        ) catch |err| {
            stderr.print("Error: TCP probe execution failed: {s}\n", .{@errorName(err)}) catch {};
            return ExitCodes.operational_failure;
        };
        defer tcp_res.deinit(allocator);

        switch (parsed.format) {
            .json => {
                var envelope = tcp_res.toEnvelope(allocator, "op_tcp_cli", profile_id_opt) catch return ExitCodes.operational_failure;
                defer envelope.deinit(allocator);
                envelope.toJson(stdout) catch return ExitCodes.operational_failure;
            },
            .terminal, .markdown => tcp_res.toTerminal(stdout) catch return ExitCodes.operational_failure,
        }

        if (tcp_res.failure_category == .malformed_input) {
            return ExitCodes.invalid_input;
        } else if (tcp_res.failure_category == .cancelled) {
            return ExitCodes.cancelled;
        } else if (tcp_res.failure_category == .operational_failure) {
            return ExitCodes.operational_failure;
        } else if (!tcp_res.is_open) {
            return ExitCodes.findings_or_violations;
        }
        return ExitCodes.success;
    }

    // 10. TLS Connectivity & Certificate Validation Probe dispatch
    const is_tls_cmd = (parsed.command == .tls) or
        (parsed.command == .diagnose and parsed.subcommand != null and (std.mem.eql(u8, parsed.subcommand.?, "tls") or std.mem.eql(u8, parsed.subcommand.?, "ssl") or std.mem.eql(u8, parsed.subcommand.?, "cert")));

    if (is_tls_cmd) {
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        var raw_target_opt: ?[]const u8 = null;
        var default_port: ?u16 = null;

        if (parsed.command == .tls) {
            if (parsed.subcommand) |sub| {
                if (parsed.target) |tgt| {
                    if (std.mem.indexOfScalar(u8, sub, ':') == null) {
                        // "wirescope tls localhost 443"
                        raw_target_opt = sub;
                        const p_num = std.fmt.parseInt(u32, tgt, 10) catch {
                            stderr.print("Error: Invalid port '{s}'. Must be an integer between 1 and 65535.\n", .{tgt}) catch {};
                            return ExitCodes.invalid_input;
                        };
                        default_port = wirescope.probes.validatePort(p_num) catch {
                            stderr.print("Error: Port {d} out of range (1-65535).\n", .{p_num}) catch {};
                            return ExitCodes.invalid_input;
                        };
                    } else {
                        raw_target_opt = sub;
                    }
                } else {
                    raw_target_opt = sub;
                }
            } else {
                raw_target_opt = parsed.target;
            }
        } else {
            // "wirescope diagnose tls <target> [port]"
            if (parsed.target) |tgt| {
                raw_target_opt = tgt;
            }
        }

        const raw_target = raw_target_opt orelse {
            stderr.print("Error: Target specification required for TLS probe. Usage: wirescope tls <host[:port]>\n", .{}) catch {};
            return ExitCodes.invalid_input;
        };

        const config = wirescope.probes.TlsConfig{
            .timeout_ms = parsed.timeout_ms,
            .verify_certificates = !parsed.insecure,
            .insecure_skip_verify = parsed.insecure,
            .custom_ca_path = parsed.ca_bundle_path,
            .server_name = parsed.server_name,
        };

        var real_connector = wirescope.probes.RealTlsConnector{};
        const connector = real_connector.connector();
        var cancel = wirescope.probes.CancellationToken{};
        const now_sec = std.time.timestamp();

        var tls_res = wirescope.probes.executeTlsProbe(
            allocator,
            raw_target,
            default_port,
            config,
            connector,
            &cancel,
            now_sec,
        ) catch |err| {
            stderr.print("Error: TLS probe execution failed: {s}\n", .{@errorName(err)}) catch {};
            return ExitCodes.operational_failure;
        };
        defer tls_res.deinit(allocator);

        switch (parsed.format) {
            .json => {
                var envelope = tls_res.toEnvelope(allocator, "op_tls_cli", null) catch return ExitCodes.operational_failure;
                defer envelope.deinit(allocator);
                envelope.toJson(stdout) catch return ExitCodes.operational_failure;
            },
            .terminal, .markdown => tls_res.toTerminal(stdout) catch return ExitCodes.operational_failure,
        }

        if (tls_res.failure_category == .malformed_input) {
            return ExitCodes.invalid_input;
        } else if (tls_res.failure_category == .cancelled) {
            return ExitCodes.cancelled;
        } else if (tls_res.failure_category == .inability_to_verify or tls_res.failure_category == .operational_failure or tls_res.failure_category == .tcp_connection_failed) {
            return ExitCodes.operational_failure;
        } else if (tls_res.failure_category != .success) {
            return ExitCodes.findings_or_violations;
        }
        return ExitCodes.success;
    }

    // 11. Diagnostics, Audits, Reconnaissance, and Lab commands (skeleton dispatcher)
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

test "execute tcp command with valid, invalid, and missing target" {
    var out_buf: [4096]u8 = undefined;
    var err_buf: [1024]u8 = undefined;

    // 1. Missing target returns invalid_input
    var out_fbs = std.io.fixedBufferStream(&out_buf);
    var err_fbs = std.io.fixedBufferStream(&err_buf);
    const missing_target = [_][]const u8{ "wirescope", "tcp" };
    const code1 = execute(&missing_target, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.invalid_input, code1);
    try testing.expect(err_fbs.getWritten().len > 0);

    // 2. Invalid target syntax rejected pre-network
    out_fbs.reset();
    err_fbs.reset();
    const invalid_target = [_][]const u8{ "wirescope", "tcp", "localhost:99999" };
    const code2 = execute(&invalid_target, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.invalid_input, code2);
    try testing.expect(err_fbs.getWritten().len > 0);

    // 3. Valid target with JSON format against a local port (e.g. closed port returns findings code)
    out_fbs.reset();
    err_fbs.reset();
    const json_tcp = [_][]const u8{ "wirescope", "tcp", "127.0.0.1:54321", "--format", "json", "--timeout", "500" };
    const code3 = execute(&json_tcp, out_fbs.writer(), err_fbs.writer());
    // Closed port returns findings_or_violations exit code
    try testing.expect(code3 == ExitCodes.findings_or_violations or code3 == ExitCodes.success);
    try testing.expect(std.mem.startsWith(u8, out_fbs.getWritten(), "{\"operation_id\":"));
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"operation_type\":\"tcp\"") != null);
    try testing.expectEqual(@as(usize, 0), err_fbs.getWritten().len);

    // 4. Diagnose tcp subcommand dispatch
    out_fbs.reset();
    err_fbs.reset();
    const diag_tcp = [_][]const u8{ "wirescope", "diagnose", "tcp", "127.0.0.1:54321", "--format", "json", "--timeout", "500" };
    const code4 = execute(&diag_tcp, out_fbs.writer(), err_fbs.writer());
    try testing.expect(code4 == ExitCodes.findings_or_violations or code4 == ExitCodes.success);
    try testing.expect(std.mem.startsWith(u8, out_fbs.getWritten(), "{\"operation_id\":"));
}

test "execute tcp repeated measurements with count and interval" {
    var out_buf: [16384]u8 = undefined;
    var err_buf: [1024]u8 = undefined;

    // 1. Repeated TCP probes with JSON output
    var out_fbs = std.io.fixedBufferStream(&out_buf);
    var err_fbs = std.io.fixedBufferStream(&err_buf);
    const json_batch = [_][]const u8{ "wirescope", "tcp", "127.0.0.1:54321", "-c", "2", "-i", "5", "--format", "json", "--timeout", "300" };
    const code1 = execute(&json_batch, out_fbs.writer(), err_fbs.writer());
    try testing.expect(code1 == ExitCodes.findings_or_violations or code1 == ExitCodes.success);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"requested_count\":2") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"stats\":{") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"samples\":[") != null);
    try testing.expectEqual(@as(usize, 0), err_fbs.getWritten().len);

    // 2. Repeated TCP probes with terminal table output
    out_fbs.reset();
    err_fbs.reset();
    const term_batch = [_][]const u8{ "wirescope", "diagnose", "latency", "127.0.0.1:54321", "-c", "2", "-i", "5", "--timeout", "300" };
    const code2 = execute(&term_batch, out_fbs.writer(), err_fbs.writer());
    try testing.expect(code2 == ExitCodes.findings_or_violations or code2 == ExitCodes.success);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "STATISTICAL SUMMARY") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "Packets/Samples") != null);
}

test "execute tls command with missing target and invalid port" {
    var out_buf: [16384]u8 = undefined;
    var err_buf: [1024]u8 = undefined;

    // 1. Missing target
    var out_fbs = std.io.fixedBufferStream(&out_buf);
    var err_fbs = std.io.fixedBufferStream(&err_buf);
    const missing_target = [_][]const u8{ "wirescope", "tls" };
    const code1 = execute(&missing_target, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.invalid_input, code1);
    try testing.expect(err_fbs.getWritten().len > 0);

    // 2. Invalid port
    out_fbs.reset();
    err_fbs.reset();
    const invalid_port = [_][]const u8{ "wirescope", "tls", "localhost", "99999" };
    const code2 = execute(&invalid_port, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.invalid_input, code2);
    try testing.expect(err_fbs.getWritten().len > 0);

    // 3. Diagnose tls help
    out_fbs.reset();
    err_fbs.reset();
    const help_tls = [_][]const u8{ "wirescope", "help", "tls" };
    const code3 = execute(&help_tls, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code3);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "wirescope tls") != null);
}
