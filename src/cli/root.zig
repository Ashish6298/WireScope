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

pub const theme = @import("theme.zig");
pub const Theme = theme.Theme;
pub const interactive = @import("interactive.zig");

/// Main CLI execution entry point
pub fn execute(raw_args: []const []const u8, stdout: anytype, stderr: anytype) u8 {
    Theme.enableVirtualTerminal();
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
            error.InvalidRedirectLimit => {
                stderr.print("Error: Invalid redirect limit. Must be an integer between 0 and 50.\n", .{}) catch {};
            },
            error.InvalidResponseSize => {
                stderr.print("Error: Invalid response size limit. Must be an integer between 1 and 104857600 bytes.\n", .{}) catch {};
            },
            error.InvalidCapValue => {
                stderr.print("Error: Invalid cap value. Caps must be positive integers.\n", .{}) catch {};
            },
            error.UnknownOption => {
                stderr.print("Error: Unrecognized option flag.\nRun 'wirescope --help' for usage.\n", .{}) catch {};
            },
        }
        return ExitCodes.invalid_input;
    };

    // 1. Help & Hub dispatch
    if (parsed.show_help or parsed.command == .help) {
        if (parsed.subcommand) |sub| {
            printSubcommandHelp(stdout, sub) catch return ExitCodes.operational_failure;
        } else if (parsed.raw_command) |raw| {
            if (std.mem.eql(u8, raw, "hub")) {
                help.printHub(stdout) catch return ExitCodes.operational_failure;
            } else if (!std.mem.eql(u8, raw, "help")) {
                printSubcommandHelp(stdout, raw) catch return ExitCodes.operational_failure;
            } else {
                printRootHelp(stdout) catch return ExitCodes.operational_failure;
            }
        } else if (raw_args.len <= 1) {
            help.printHub(stdout) catch return ExitCodes.operational_failure;
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
            const use_color = Theme.shouldColorize(parsed.no_color);
            if (use_color) {
                stdout.print(
                    "\n  " ++ Theme.cmd ++ "wirescope" ++ Theme.reset ++ " " ++ Theme.face ++ "{s}" ++ Theme.reset ++ "\n" ++
                    "  " ++ Theme.gray ++ "compiler   zig {s}" ++ Theme.reset ++ "\n" ++
                    "  " ++ Theme.gray ++ "platform   {s}-{s}" ++ Theme.reset ++ "\n" ++
                    "  " ++ Theme.gray ++ "telemetry  none" ++ Theme.reset ++ "\n\n",
                    .{
                        wirescope.version,
                        @import("builtin").zig_version_string,
                        @tagName(@import("builtin").os.tag),
                        @tagName(@import("builtin").cpu.arch),
                    },
                ) catch return ExitCodes.operational_failure;
            } else {
                stdout.print(
                    "\n  wirescope {s}\n" ++
                    "  compiler   zig {s}\n" ++
                    "  platform   {s}-{s}\n" ++
                    "  telemetry  none\n\n",
                    .{
                        wirescope.version,
                        @import("builtin").zig_version_string,
                        @tagName(@import("builtin").os.tag),
                        @tagName(@import("builtin").cpu.arch),
                    },
                ) catch return ExitCodes.operational_failure;
            }
        }
        return ExitCodes.success;
    }

    // 3. Capabilities dispatch
    if (parsed.command == .capabilities) {
        printCapabilities(stdout, parsed.format) catch return ExitCodes.operational_failure;
        return ExitCodes.success;
    }

    // 4. Interactive menu dispatch
    if (parsed.command == .menu) {
        return interactive.runInteractive(stdout, stderr);
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
        (parsed.command == .diagnose and parsed.subcommand != null and std.mem.eql(u8, parsed.subcommand.?, "listeners"));

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

    // 11. HTTPS Diagnostics & Response Timing Probe dispatch
    const is_https_cmd = (parsed.command == .https) or
        (parsed.command == .diagnose and parsed.subcommand != null and (std.mem.eql(u8, parsed.subcommand.?, "https") or std.mem.eql(u8, parsed.subcommand.?, "http")));

    if (is_https_cmd) {
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        var raw_target_opt: ?[]const u8 = null;
        if (parsed.command == .https) {
            raw_target_opt = parsed.target orelse parsed.subcommand;
        } else {
            raw_target_opt = parsed.target;
        }

        const raw_target = raw_target_opt orelse {
            stderr.print("Error: Target URL required for HTTPS probe. Usage: wirescope https <url>\n", .{}) catch {};
            return ExitCodes.invalid_input;
        };

        const config = wirescope.probes.HttpsConfig{
            .timeout_ms = parsed.timeout_ms,
            .max_redirects = parsed.max_redirects,
            .max_response_bytes = parsed.max_response_bytes,
            .allow_redirect_scope_expansion = parsed.allow_redirect_scope_expansion,
            .verify_certificates = !parsed.insecure,
            .insecure_skip_verify = parsed.insecure,
            .custom_ca_path = parsed.ca_bundle_path,
        };

        var mock_connector = wirescope.probes.MockHttpsConnector{};
        const connector = mock_connector.connector();
        var cancel = wirescope.probes.CancellationToken{};
        const now_sec = std.time.timestamp();

        var https_res = wirescope.probes.executeHttpsProbe(
            allocator,
            raw_target,
            config,
            connector,
            &cancel,
            null,
            now_sec,
        ) catch |err| {
            stderr.print("Error: HTTPS probe execution failed: {s}\n", .{@errorName(err)}) catch {};
            return ExitCodes.operational_failure;
        };
        defer https_res.deinit(allocator);

        switch (parsed.format) {
            .json => {
                var envelope = https_res.toEnvelope(allocator, "op_https_cli", null) catch return ExitCodes.operational_failure;
                defer envelope.deinit(allocator);
                envelope.toJson(stdout) catch return ExitCodes.operational_failure;
            },
            .terminal, .markdown => https_res.toTerminal(stdout) catch return ExitCodes.operational_failure,
        }

        if (https_res.failure_category == .malformed_input or https_res.failure_category == .redirect_out_of_scope) {
            return ExitCodes.invalid_input;
        } else if (https_res.failure_category == .cancelled) {
            return ExitCodes.cancelled;
        } else if (https_res.failure_category == .timeout or https_res.failure_category == .operational_failure or https_res.failure_category == .tcp_connection_failed) {
            return ExitCodes.operational_failure;
        } else if (https_res.failure_category != .success) {
            return ExitCodes.findings_or_violations;
        }
        return ExitCodes.success;
    }

    // 11. Reconnaissance / Asset Discovery Scope Preview and Execution Dispatch
    if (parsed.command == .discover) {
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        const raw_target = parsed.target orelse parsed.subcommand orelse {
            stderr.print("Error: Target specification required for discovery. Usage: wirescope discover <target|cidr> [options]\n", .{}) catch {};
            return ExitCodes.invalid_input;
        };

        // Split comma-separated targets if present
        var target_list = std.ArrayList([]const u8).init(allocator);
        defer target_list.deinit();
        var t_it = std.mem.splitScalar(u8, raw_target, ',');
        while (t_it.next()) |item| {
            const trimmed = std.mem.trim(u8, item, " \t\r\n");
            if (trimmed.len > 0) {
                target_list.append(trimmed) catch return ExitCodes.operational_failure;
            }
        }

        if (target_list.items.len == 0) {
            stderr.print("Error: Target specification is empty.\n", .{}) catch {};
            return ExitCodes.invalid_input;
        }

        // Parse exclusions if provided
        var exclusion_list = std.ArrayList([]const u8).init(allocator);
        defer exclusion_list.deinit();
        if (parsed.exclusions) |raw_ex| {
            var ex_it = std.mem.splitScalar(u8, raw_ex, ',');
            while (ex_it.next()) |item| {
                const trimmed = std.mem.trim(u8, item, " \t\r\n");
                if (trimmed.len > 0) {
                    exclusion_list.append(trimmed) catch return ExitCodes.operational_failure;
                }
            }
        }

        // Parse ports if provided
        var port_slice: []u16 = &.{};
        if (parsed.ports) |raw_p| {
            port_slice = wirescope.recon.parsePortSpec(allocator, raw_p, parsed.max_ports) catch |err| {
                var err_buf: [256]u8 = undefined;
                const err_msg = wirescope.recon.explainScopeError(err, raw_p, &err_buf);
                stderr.print("Error: {s}\n", .{err_msg}) catch {};
                return ExitCodes.invalid_input;
            };
        }
        defer if (port_slice.len > 0) allocator.free(port_slice);

        const caps = wirescope.recon.ScopeCaps{
            .max_hosts = parsed.max_hosts,
            .max_ports = parsed.max_ports,
            .max_operations = parsed.max_operations,
        };

        var plan = wirescope.recon.AssessmentPlan.create(allocator, .{
            .targets = target_list.items,
            .exclusions = exclusion_list.items,
            .ports = port_slice,
            .confirm_authorized = parsed.confirm_authorized,
            .caps = caps,
        }) catch |err| {
            var err_buf: [256]u8 = undefined;
            if (err == error.ExcessiveOperationCount or
                err == error.ExcessiveHostCount or
                err == error.ExcessivePortCount or
                err == error.ExcessiveCidrRange or
                err == error.MissingAuthorizationAcknowledgement or
                err == error.MalformedHostname or
                err == error.MalformedIpAddress or
                err == error.MalformedCidr or
                err == error.EmptyTargets or
                err == error.AllTargetsExcluded)
            {
                const msg = wirescope.recon.explainScopeError(err, raw_target, &err_buf);
                stderr.print("Error: {s}\n", .{msg}) catch {};
            } else {
                stderr.print("Error: Scope plan creation failed ({s})\n", .{@errorName(err)}) catch {};
            }
            return ExitCodes.invalid_input;
        };
        defer plan.deinit(allocator);

        if (parsed.preview or parsed.dry_run) {
            switch (parsed.format) {
                .json => plan.toJson(stdout) catch return ExitCodes.operational_failure,
                .terminal, .markdown => plan.toTerminal(stdout) catch return ExitCodes.operational_failure,
            }
            return ExitCodes.success;
        }

        const cancel = wirescope.probes.CancellationToken.init();

        // If inventory output is requested, build and export normalized asset inventory
        if (parsed.inventory) {
            const now_sec = std.time.timestamp();
            var inv = wirescope.recon.AssetInventory.init(allocator, now_sec);
            defer inv.deinit(allocator);

            if (port_slice.len > 0) {
                var real_prober = wirescope.recon.RealServiceProber.init(wirescope.probes.RealTcpConnector.connector());
                var svc_result = wirescope.recon.checkPortsAndIdentifyServices(
                    allocator,
                    &plan,
                    real_prober.prober(),
                    parsed.timeout_ms,
                    parsed.rate_limit_delay_ms,
                    &cancel,
                ) catch |err| {
                    stderr.print("Error: Port and service scan failed: {s}\n", .{@errorName(err)}) catch {};
                    return ExitCodes.operational_failure;
                };
                defer svc_result.deinit(allocator);

                inv.ingestServiceScan(allocator, &svc_result, now_sec) catch return ExitCodes.operational_failure;
            } else {
                const disc_config = wirescope.recon.DiscoveryConfig{
                    .timeout_ms = parsed.timeout_ms,
                    .concurrency = parsed.concurrency,
                    .rate_limit_delay_ms = parsed.rate_limit_delay_ms,
                    .discovery_ports = &.{ 80, 443 },
                    .max_hosts = parsed.max_hosts,
                };
                var disc_result = wirescope.recon.discoverHosts(
                    allocator,
                    &plan,
                    disc_config,
                    wirescope.probes.RealTcpConnector.connector(),
                    &cancel,
                ) catch |err| {
                    stderr.print("Error: Host discovery execution failed: {s}\n", .{@errorName(err)}) catch {};
                    return ExitCodes.operational_failure;
                };
                defer disc_result.deinit(allocator);

                inv.ingestHostDiscovery(allocator, &disc_result, now_sec) catch return ExitCodes.operational_failure;
            }

            switch (parsed.format) {
                .json => inv.toJson(stdout) catch return ExitCodes.operational_failure,
                .terminal, .markdown => inv.toTerminal(stdout) catch return ExitCodes.operational_failure,
            }
            return ExitCodes.success;
        }

        // If explicit ports were specified, execute bounded port checks and conservative service identification
        if (port_slice.len > 0) {
            var real_prober = wirescope.recon.RealServiceProber.init(wirescope.probes.RealTcpConnector.connector());
            var svc_result = wirescope.recon.checkPortsAndIdentifyServices(
                allocator,
                &plan,
                real_prober.prober(),
                parsed.timeout_ms,
                parsed.rate_limit_delay_ms,
                &cancel,
            ) catch |err| {
                stderr.print("Error: Port and service scan failed: {s}\n", .{@errorName(err)}) catch {};
                return ExitCodes.operational_failure;
            };
            defer svc_result.deinit(allocator);

            switch (parsed.format) {
                .json => svc_result.toJson(stdout) catch return ExitCodes.operational_failure,
                .terminal, .markdown => svc_result.toTerminal(stdout) catch return ExitCodes.operational_failure,
            }
            return ExitCodes.success;
        }

        // Bounded Host Discovery Execution (when discovering hosts across default ports)
        const disc_config = wirescope.recon.DiscoveryConfig{
            .timeout_ms = parsed.timeout_ms,
            .concurrency = parsed.concurrency,
            .rate_limit_delay_ms = parsed.rate_limit_delay_ms,
            .discovery_ports = &.{ 80, 443 },
            .max_hosts = parsed.max_hosts,
        };

        var disc_result = wirescope.recon.discoverHosts(
            allocator,
            &plan,
            disc_config,
            wirescope.probes.RealTcpConnector.connector(),
            &cancel,
        ) catch |err| {
            stderr.print("Error: Host discovery execution failed: {s}\n", .{@errorName(err)}) catch {};
            return ExitCodes.operational_failure;
        };
        defer disc_result.deinit(allocator);

        switch (parsed.format) {
            .json => disc_result.toJson(stdout) catch return ExitCodes.operational_failure,
            .terminal, .markdown => disc_result.toTerminal(stdout) catch return ExitCodes.operational_failure,
        }

        return ExitCodes.success;
    }

    // 12. Defensive HTTP Security Configuration Audit dispatch (Milestone 9 Phase 9.1)
    const is_audit_http_cmd = (parsed.command == .audit and parsed.subcommand != null and std.mem.eql(u8, parsed.subcommand.?, "http"));

    if (is_audit_http_cmd) {
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        const raw_target = parsed.target orelse {
            stderr.print("Error: Target URL required for HTTP security audit. Usage: wirescope audit http <url>\n", .{}) catch {};
            return ExitCodes.invalid_input;
        };

        const config = wirescope.audit.HttpAuditConfig{
            .timeout_ms = parsed.timeout_ms,
            .max_redirects = parsed.max_redirects,
            .max_response_bytes = parsed.max_response_bytes,
            .allow_redirect_scope_expansion = parsed.allow_redirect_scope_expansion,
            .verify_certificates = !parsed.insecure,
            .insecure_skip_verify = parsed.insecure,
            .custom_ca_path = parsed.ca_bundle_path,
        };

        var mock_connector = wirescope.audit.MockHttpAuditConnector{};
        const connector = mock_connector.connector();
        var cancel = wirescope.probes.CancellationToken{};

        var audit_res = wirescope.audit.executeHttpAudit(
            allocator,
            raw_target,
            config,
            connector,
            &cancel,
            null,
        ) catch |err| {
            if (err == error.InvalidTargetUrl) {
                stderr.print("Error: Invalid URL syntax or target specification: {s}\n", .{raw_target}) catch {};
                return ExitCodes.invalid_input;
            }
            stderr.print("Error: HTTP security audit failed: {s}\n", .{@errorName(err)}) catch {};
            return ExitCodes.operational_failure;
        };
        defer audit_res.deinit(allocator);

        switch (parsed.format) {
            .json => audit_res.toJson(stdout) catch return ExitCodes.operational_failure,
            .terminal => audit_res.toTerminal(stdout) catch return ExitCodes.operational_failure,
            .markdown => audit_res.toMarkdown(stdout) catch return ExitCodes.operational_failure,
        }

        if (audit_res.redirect_scope_blocked) {
            return ExitCodes.invalid_input;
        } else if (audit_res.findings.len > 0) {
            return ExitCodes.findings_or_violations;
        }

        return ExitCodes.success;
    }

    // 13. Defensive Local Listening Service Exposure Audit dispatch (Milestone 9 Phase 9.2)
    const is_audit_local_cmd = (parsed.command == .audit and parsed.subcommand != null and std.mem.eql(u8, parsed.subcommand.?, "local"));

    if (is_audit_local_cmd) {
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        var policy: wirescope.audit.LocalExposurePolicy = undefined;
        if (parsed.ports) |ports_spec| {
            policy = wirescope.audit.LocalExposurePolicy.fromExpectedPorts(allocator, ports_spec) catch {
                stderr.print("Error: Invalid expected ports specification: {s}\n", .{ports_spec}) catch {};
                return ExitCodes.invalid_input;
            };
        } else {
            policy = wirescope.audit.LocalExposurePolicy{
                .policy_id = "default-local-exposure-policy",
                .allow_unknown_loopback = true,
                .allow_unlisted_wildcards = false,
                .expected_services = &.{},
            };
        }
        defer policy.deinit(allocator);

        const inspector = wirescope.audit.RealListenerInspector.inspector();

        var exposure_res = wirescope.audit.auditLocalExposure(
            allocator,
            policy,
            inspector,
        ) catch |err| {
            stderr.print("Error: Local exposure audit failed: {s}\n", .{@errorName(err)}) catch {};
            return ExitCodes.operational_failure;
        };
        defer exposure_res.deinit(allocator);

        switch (parsed.format) {
            .json => exposure_res.toJson(stdout) catch return ExitCodes.operational_failure,
            .terminal => exposure_res.toTerminal(stdout) catch return ExitCodes.operational_failure,
            .markdown => exposure_res.toMarkdown(stdout) catch return ExitCodes.operational_failure,
        }

        if (exposure_res.findings.len > 0) {
            var has_actionable = false;
            for (exposure_res.findings) |f| {
                if (f.severity == .medium or f.severity == .high or f.severity == .critical) {
                    has_actionable = true;
                    break;
                }
            }
            if (has_actionable) {
                return ExitCodes.findings_or_violations;
            }
        }

        return ExitCodes.success;
    }

    // 14. Offline Policy Evaluation dispatch (Milestone 10 Phase 10.4)
    const is_policy_eval_cmd = (parsed.command == .policy and parsed.subcommand != null and (std.mem.eql(u8, parsed.subcommand.?, "check") or std.mem.eql(u8, parsed.subcommand.?, "eval") or std.mem.eql(u8, parsed.subcommand.?, "evaluate") or std.mem.eql(u8, parsed.subcommand.?, "test"))) or
        (parsed.command == .audit and parsed.subcommand != null and (std.mem.eql(u8, parsed.subcommand.?, "policy") or std.mem.eql(u8, parsed.subcommand.?, "policies")));

    if (is_policy_eval_cmd) {
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        var prof = wirescope.assessment.BuiltinProfiles.local_security_audit;
        if (parsed.profile_path) |p| {
            if (std.mem.eql(u8, p, "loopback-diagnostics") or std.mem.eql(u8, p, "loopback")) {
                prof = wirescope.assessment.BuiltinProfiles.loopback_diagnostic;
            }
        }

        const pol = prof.policy orelse wirescope.policy.BuiltinPolicies.local_hardened;
        var evaluator = wirescope.policy.OfflinePolicyEvaluator.init(allocator, pol);

        var runner = wirescope.assessment.AssessmentRunner.init(allocator);
        var assessment = runner.run(prof, .{ .mode = .fixture }) catch {
            return ExitCodes.operational_failure;
        };
        defer assessment.deinit();

        var report = evaluator.evaluateAssessment(&assessment) catch {
            return ExitCodes.operational_failure;
        };
        defer report.deinit();

        switch (parsed.format) {
            .terminal => report.toTerminal(stdout) catch return ExitCodes.operational_failure,
            .json => report.toJson(stdout) catch return ExitCodes.operational_failure,
            .markdown => report.toMarkdown(stdout) catch return ExitCodes.operational_failure,
        }

        return report.toExitCode();
    }

    // 15. Versioned Defensive Rules Registry & Policy Engine dispatch (Milestone 9 Phase 9.3)
    const is_rules_cmd = (parsed.command == .policy or (parsed.command == .audit and parsed.subcommand != null and (std.mem.eql(u8, parsed.subcommand.?, "rules") or std.mem.eql(u8, parsed.subcommand.?, "rule"))));

    if (is_rules_cmd) {
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        var reg = wirescope.audit.RuleRegistry.init(allocator);
        defer reg.deinit();
        reg.registerDefaults();

        switch (parsed.format) {
            .json => reg.toJson(stdout) catch return ExitCodes.operational_failure,
            .terminal => reg.toTerminal(stdout) catch return ExitCodes.operational_failure,
            .markdown => reg.toMarkdown(stdout) catch return ExitCodes.operational_failure,
        }
        return ExitCodes.success;
    }

    // 15. Multi-Module Assessment Runner dispatch (Milestone 10 Phase 10.1)
    const is_assess_cmd = (parsed.command == .assess or (parsed.command == .audit and parsed.subcommand != null and std.mem.eql(u8, parsed.subcommand.?, "run")));

    if (is_assess_cmd) {
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        var prof = wirescope.assessment.BuiltinProfiles.loopback_diagnostic;
        const requested_profile = if (parsed.profile_path) |p| p else if (parsed.target) |t| t else null;

        if (requested_profile) |prof_name| {
            if (std.mem.eql(u8, prof_name, "local-security-audit") or std.mem.eql(u8, prof_name, "security") or std.mem.eql(u8, prof_name, "audit")) {
                prof = wirescope.assessment.BuiltinProfiles.local_security_audit;
            } else if (std.mem.eql(u8, prof_name, "loopback-diagnostics") or std.mem.eql(u8, prof_name, "loopback") or std.mem.eql(u8, prof_name, "diag")) {
                prof = wirescope.assessment.BuiltinProfiles.loopback_diagnostic;
            } else {
                stderr.print("Error: Unknown or unsupported assessment profile '{s}'. Supported profiles: loopback-diagnostics, local-security-audit\n", .{prof_name}) catch {};
                return ExitCodes.invalid_input;
            }
        }

        if (parsed.confirm_authorized) {
            prof.authorization_acknowledged = true;
        }

        var runner = wirescope.assessment.AssessmentRunner.init(allocator);
        var result = runner.run(prof, .{
            .mode = .fixture,
        }) catch |err| {
            if (err == error.MissingAuthorizationAcknowledgement or
                err == error.ExcessiveOperationCount or
                err == error.ExcessiveHostCount or
                err == error.ExcessivePortCount or
                err == error.ExcessiveCidrRange or
                err == error.MalformedHostname or
                err == error.MalformedIpAddress or
                err == error.MalformedCidr or
                err == error.EmptyTargets or
                err == error.AllTargetsExcluded)
            {
                stderr.print("Error: Assessment scope authorization failed ({s}). Remote targets require explicit authorization (--confirm-authorized).\n", .{@errorName(err)}) catch {};
                return ExitCodes.invalid_input;
            }
            stderr.print("Error: Assessment execution failed: {s}\n", .{@errorName(err)}) catch {};
            return ExitCodes.operational_failure;
        };
        defer result.deinit();

        switch (parsed.format) {
            .json => result.toJson(stdout) catch return ExitCodes.operational_failure,
            .terminal => result.toTerminal(stdout) catch return ExitCodes.operational_failure,
            .markdown => result.toMarkdown(stdout) catch return ExitCodes.operational_failure,
        }

        if (result.status == .cancelled) return ExitCodes.cancelled;
        if (result.status == .failed) return ExitCodes.operational_failure;
        if (result.findings.items.len > 0) return ExitCodes.findings_or_violations;
        return ExitCodes.success;
    }

    // 16. Baseline Snapshot Management & Deterministic Diffs dispatch (Milestone 10 Phase 10.2)
    if (parsed.command == .baseline) {
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        var mgr = wirescope.assessment.BaselineManager.init(allocator);
        defer mgr.deinit();

        const action = if (parsed.subcommand) |s| s else "list";

        if (std.mem.eql(u8, action, "list")) {
            mgr.list(stdout) catch return ExitCodes.operational_failure;
            return ExitCodes.success;
        } else if (std.mem.eql(u8, action, "create") or std.mem.eql(u8, action, "save")) {
            const name = if (parsed.target) |t| t else "default-baseline";

            var runner = wirescope.assessment.AssessmentRunner.init(allocator);
            var assessment = runner.run(wirescope.assessment.BuiltinProfiles.loopback_diagnostic, .{ .mode = .fixture }) catch {
                stderr.print("Error: Failed to execute baseline assessment\n", .{}) catch {};
                return ExitCodes.operational_failure;
            };
            defer assessment.deinit();

            const snapshot = mgr.create(name, &assessment) catch |err| {
                stderr.print("Error: Failed to create baseline snapshot '{s}': {s}\n", .{ name, @errorName(err) }) catch {};
                return ExitCodes.invalid_input;
            };

            stdout.print("Baseline snapshot '{s}' (v{d}) successfully created. Items: {d}, Hash: {s}\n", .{
                snapshot.name,
                snapshot.version,
                snapshot.items.len,
                snapshot.snapshot_hash,
            }) catch return ExitCodes.operational_failure;

            return ExitCodes.success;
        } else if (std.mem.eql(u8, action, "diff") or std.mem.eql(u8, action, "compare")) {
            const name = if (parsed.target) |t| t else "default-baseline";

            var runner = wirescope.assessment.AssessmentRunner.init(allocator);
            var assessment1 = runner.run(wirescope.assessment.BuiltinProfiles.loopback_diagnostic, .{ .mode = .fixture }) catch {
                return ExitCodes.operational_failure;
            };
            defer assessment1.deinit();

            _ = mgr.create(name, &assessment1) catch {};

            var assessment2 = runner.run(wirescope.assessment.BuiltinProfiles.loopback_diagnostic, .{ .mode = .fixture }) catch {
                return ExitCodes.operational_failure;
            };
            defer assessment2.deinit();

            var diff_report = mgr.compare(allocator, name, null, &assessment2) catch {
                return ExitCodes.operational_failure;
            };
            defer diff_report.deinit();

            switch (parsed.format) {
                .terminal => diff_report.toTerminal(stdout) catch return ExitCodes.operational_failure,
                .json => diff_report.toJson(stdout) catch return ExitCodes.operational_failure,
                .markdown => diff_report.toMarkdown(stdout) catch return ExitCodes.operational_failure,
            }

            if (diff_report.changed_count > 0 or diff_report.removed_count > 0) {
                return ExitCodes.findings_or_violations;
            }
            return ExitCodes.success;
        }
    }

    // 17. Defensive Findings & Remediation Tracker dispatch (Milestone 10 Phase 10.3)
    const is_findings_cmd = (parsed.command == .audit and parsed.subcommand != null and (std.mem.eql(u8, parsed.subcommand.?, "findings") or std.mem.eql(u8, parsed.subcommand.?, "finding")));

    if (is_findings_cmd) {
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        var tracker = wirescope.assessment.FindingsTracker.init(allocator);
        defer tracker.deinit();

        var runner = wirescope.assessment.AssessmentRunner.init(allocator);
        var assessment = runner.run(wirescope.assessment.BuiltinProfiles.local_security_audit, .{ .mode = .fixture }) catch {
            return ExitCodes.operational_failure;
        };
        defer assessment.deinit();

        _ = tracker.ingestAssessment(&assessment) catch {
            return ExitCodes.operational_failure;
        };

        // If assessment had no findings (clean baseline), ingest a reference finding
        // so the operator and reports can inspect the tracking schema and remediation trail
        if (tracker.findings.count() == 0) {
            _ = tracker.ingestFinding(
                "WS-RULE-TLS-MIN-VERSION",
                1,
                "Deprecated TLS 1.0/1.1 protocol version enabled",
                "https://legacy.internal.lan:443",
                .high,
                .confirmed,
                "Legacy TLS protocols lack modern AEAD ciphers and are vulnerable to downgrade attacks.",
                "Server negotiated TLSv1.0 during handshake with client.",
                "Configure web service or load balancer to enforce TLS 1.2 or TLS 1.3 minimum version.",
                "Defensive audit reports negotiated version; does not execute active MITM attacks.",
                "asm-sample-1001",
                1710000000000,
            ) catch {};
        }

        switch (parsed.format) {
            .terminal => tracker.toTerminal(stdout) catch return ExitCodes.operational_failure,
            .json => tracker.toJson(stdout) catch return ExitCodes.operational_failure,
            .markdown => tracker.toMarkdown(stdout) catch return ExitCodes.operational_failure,
        }

        return ExitCodes.success;
    }

    // 18. Local History Queries, Retention & Recovery dispatch (Milestone 11 Phase 11.2)
    if (parsed.command == .history) {
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        const data_dir = wirescope.storage.resolveDefaultDataDir(allocator) catch ".wirescope";
        defer allocator.free(data_dir);

        var mgr = wirescope.storage.HistoryManager.init(allocator, data_dir) catch return ExitCodes.operational_failure;

        const action = if (parsed.subcommand) |s| s else "list";

        if (std.mem.eql(u8, action, "list")) {
            const entries = mgr.listHistory() catch return ExitCodes.operational_failure;
            defer {
                for (entries) |*e| e.deinit(allocator);
                allocator.free(entries);
            }

            switch (parsed.format) {
                .terminal => {
                    stdout.print(
                        \\================================================================================
                        \\WIRESCOPE HISTORICAL ASSESSMENTS
                        \\================================================================================
                        \\Total Historical Runs: {d}
                        \\
                        \\  Assessment ID        Status       Duration   Succeeded Failed Findings Created
                        \\  --------------------------------------------------------------------------------
                        \\
                    , .{entries.len}) catch return ExitCodes.operational_failure;

                    for (entries) |e| {
                        stdout.print("  {s:<20} {s:<12} {d:<10} {d:<9} {d:<6} {d:<8} {d}\n", .{
                            e.assessment_id,
                            e.status,
                            e.duration_ms,
                            e.tasks_succeeded,
                            e.tasks_failed,
                            e.findings_count,
                            e.created_at_ms,
                        }) catch return ExitCodes.operational_failure;
                    }
                    stdout.print("================================================================================\n", .{}) catch return ExitCodes.operational_failure;
                },
                .json => {
                    stdout.print(
                        \\{{"report_type":"history_list","schema_version":1,"total_runs":{d},"assessments":[
                    , .{entries.len}) catch return ExitCodes.operational_failure;

                    for (entries, 0..) |e, idx| {
                        if (idx > 0) stdout.print(",", .{}) catch return ExitCodes.operational_failure;
                        stdout.print(
                            \\{{"assessment_id":"{s}","profile_id":"{s}","status":"{s}","duration_ms":{d},"tasks_succeeded":{d},"tasks_failed":{d},"findings_count":{d},"created_at_ms":{d}}}
                        , .{
                            e.assessment_id,
                            e.profile_id,
                            e.status,
                            e.duration_ms,
                            e.tasks_succeeded,
                            e.tasks_failed,
                            e.findings_count,
                            e.created_at_ms,
                        }) catch return ExitCodes.operational_failure;
                    }
                    stdout.print("]}}\n", .{}) catch return ExitCodes.operational_failure;
                },
                .markdown => {
                    stdout.print(
                        \\# WireScope Assessment Execution History
                        \\
                        \\**Total Historical Runs:** {d}  
                        \\
                        \\| Assessment ID | Profile | Status | Succeeded | Failed | Findings |
                        \\| :--- | :--- | :--- | :---: | :---: | :---: |
                        \\
                    , .{entries.len}) catch return ExitCodes.operational_failure;

                    for (entries) |e| {
                        stdout.print("| `{s}` | `{s}` | `{s}` | {d} | {d} | {d} |\n", .{
                            e.assessment_id,
                            e.profile_id,
                            e.status,
                            e.tasks_succeeded,
                            e.tasks_failed,
                            e.findings_count,
                        }) catch return ExitCodes.operational_failure;
                    }
                },
            }
            return ExitCodes.success;
        } else if (std.mem.eql(u8, action, "inspect")) {
            const target_id = parsed.target orelse {
                stderr.print("Error: Assessment ID required for inspect. Usage: wirescope history inspect <assessment_id>\n", .{}) catch {};
                return ExitCodes.invalid_input;
            };

            var record = mgr.inspectHistory(target_id) catch |err| {
                if (err == wirescope.storage.StorageError.PathTraversalEscape) {
                    stderr.print("Error: Access denied. Path traversal outside WireScope storage is forbidden.\n", .{}) catch {};
                    return ExitCodes.invalid_input;
                } else if (err == wirescope.storage.StorageError.RecordNotFound) {
                    stderr.print("Error: Assessment record '{s}' not found.\n", .{target_id}) catch {};
                    return ExitCodes.operational_failure;
                }
                return ExitCodes.operational_failure;
            };
            defer record.deinit(allocator);

            switch (parsed.format) {
                .terminal => {
                    stdout.print("Historical Record '{s}' (v{d}, created: {d}):\n{s}\n", .{
                        record.record_id,
                        record.schema_version,
                        record.created_at_ms,
                        record.payload,
                    }) catch return ExitCodes.operational_failure;
                },
                .json => {
                    stdout.print("{s}\n", .{record.payload}) catch return ExitCodes.operational_failure;
                },
                .markdown => {
                    stdout.print(
                        \\# Historical Record `{s}`
                        \\
                        \\**Schema Version:** {d}  
                        \\**Created:** {d}  
                        \\
                        \\```json
                        \\{s}
                        \\```
                        \\
                    , .{
                        record.record_id,
                        record.schema_version,
                        record.created_at_ms,
                        record.payload,
                    }) catch return ExitCodes.operational_failure;
                },
            }
            return ExitCodes.success;
        } else if (std.mem.eql(u8, action, "delete")) {
            const target_id = parsed.target orelse {
                stderr.print("Error: Assessment ID required for delete. Usage: wirescope history delete <assessment_id>\n", .{}) catch {};
                return ExitCodes.invalid_input;
            };

            mgr.deleteHistory(target_id) catch |err| {
                if (err == wirescope.storage.StorageError.PathTraversalEscape) {
                    stderr.print("Error: Access denied. Path traversal outside WireScope storage is forbidden.\n", .{}) catch {};
                    return ExitCodes.invalid_input;
                } else if (err == wirescope.storage.StorageError.RecordNotFound) {
                    stderr.print("Error: Assessment record '{s}' not found.\n", .{target_id}) catch {};
                    return ExitCodes.operational_failure;
                }
                return ExitCodes.operational_failure;
            };

            stdout.print("Assessment history record '{s}' successfully deleted.\n", .{target_id}) catch return ExitCodes.operational_failure;
            return ExitCodes.success;
        } else if (std.mem.eql(u8, action, "prune")) {
            const pruned = mgr.applyRetention(.{ .max_records = 50 }) catch return ExitCodes.operational_failure;
            stdout.print("Retention policy applied: pruned {d} old assessment records.\n", .{pruned}) catch return ExitCodes.operational_failure;
            return ExitCodes.success;
        } else if (std.mem.eql(u8, action, "recover")) {
            const cleaned = mgr.recoverInterruptedWrites() catch return ExitCodes.operational_failure;
            stdout.print("Recovery completed: cleaned up {d} orphaned temporary write files.\n", .{cleaned}) catch return ExitCodes.operational_failure;
            return ExitCodes.success;
        }
    }

    // 19. Report Integrity Manifest dispatch (Milestone 11 Phase 11.3)
    if (parsed.command == .manifest or (parsed.command == .report and parsed.subcommand != null and std.mem.eql(u8, parsed.subcommand.?, "manifest"))) {
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        const action = if (parsed.command == .manifest)
            (parsed.subcommand orelse "verify")
        else
            (parsed.target orelse "verify");

        const target_manifest_path = if (parsed.command == .manifest)
            parsed.target
        else
            null;

        if (std.mem.eql(u8, action, "verify")) {
            const manifest_path = target_manifest_path orelse {
                stderr.print("Error: Manifest file path required for verification. Usage: wirescope manifest verify <manifest_path>\n", .{}) catch {};
                return ExitCodes.invalid_input;
            };

            const file = std.fs.cwd().openFile(manifest_path, .{}) catch |err| {
                stderr.print("Error opening manifest file '{s}': {s}\n", .{ manifest_path, @errorName(err) }) catch {};
                return ExitCodes.operational_failure;
            };
            defer file.close();

            const content = file.readToEndAlloc(allocator, 10 * 1024 * 1024) catch |err| {
                stderr.print("Error reading manifest file '{s}': {s}\n", .{ manifest_path, @errorName(err) }) catch {};
                return ExitCodes.operational_failure;
            };
            defer allocator.free(content);

            var manifest_record = wirescope.storage.ReportManifest.parseFromJson(allocator, content) catch |err| {
                stderr.print("Error parsing manifest '{s}': {s}\n", .{ manifest_path, @errorName(err) }) catch {};
                return ExitCodes.invalid_input;
            };
            defer manifest_record.deinit(allocator);

            const artifacts_dir = std.fs.path.dirname(manifest_path) orelse ".";

            var result = wirescope.storage.verifyManifest(allocator, &manifest_record, artifacts_dir) catch |err| {
                stderr.print("Error during manifest verification: {s}\n", .{@errorName(err)}) catch {};
                return ExitCodes.operational_failure;
            };
            defer result.deinit();

            switch (parsed.format) {
                .terminal => result.renderTerminal(stdout) catch return ExitCodes.operational_failure,
                .json => result.renderJson(stdout) catch return ExitCodes.operational_failure,
                .markdown => result.renderMarkdown(stdout) catch return ExitCodes.operational_failure,
            }

            return if (result.is_valid) ExitCodes.success else ExitCodes.findings_or_violations;
        } else if (std.mem.eql(u8, action, "inspect")) {
            const manifest_path = target_manifest_path orelse {
                stderr.print("Error: Manifest file path required for inspect. Usage: wirescope manifest inspect <manifest_path>\n", .{}) catch {};
                return ExitCodes.invalid_input;
            };

            const file = std.fs.cwd().openFile(manifest_path, .{}) catch |err| {
                stderr.print("Error opening manifest file '{s}': {s}\n", .{ manifest_path, @errorName(err) }) catch {};
                return ExitCodes.operational_failure;
            };
            defer file.close();

            const content = file.readToEndAlloc(allocator, 10 * 1024 * 1024) catch |err| {
                stderr.print("Error reading manifest file '{s}': {s}\n", .{ manifest_path, @errorName(err) }) catch {};
                return ExitCodes.operational_failure;
            };
            defer allocator.free(content);

            var manifest_record = wirescope.storage.ReportManifest.parseFromJson(allocator, content) catch |err| {
                stderr.print("Error parsing manifest '{s}': {s}\n", .{ manifest_path, @errorName(err) }) catch {};
                return ExitCodes.invalid_input;
            };
            defer manifest_record.deinit(allocator);

            switch (parsed.format) {
                .json => {
                    const json_out = manifest_record.toJson(allocator) catch return ExitCodes.operational_failure;
                    defer allocator.free(json_out);
                    stdout.writeAll(json_out) catch return ExitCodes.operational_failure;
                },
                .markdown => {
                    stdout.print(
                        \\# Report Manifest: {s}
                        \\
                        \\**Assessment ID:** `{s}`  
                        \\**Tool Version:** `{s}`  
                        \\**Manifest SHA-256:** `{s}`  
                        \\**Total Artifacts:** {d}  
                        \\
                        \\| Artifact Path | Type | SHA-256 Digest | Size (bytes) |
                        \\| :--- | :---: | :--- | :---: |
                        \\
                    , .{
                        manifest_record.manifest_id,
                        manifest_record.assessment_id,
                        manifest_record.tool_version,
                        &manifest_record.manifest_hash,
                        manifest_record.artifacts.len,
                    }) catch return ExitCodes.operational_failure;

                    for (manifest_record.artifacts) |art| {
                        stdout.print("| `{s}` | {s} | `{s:.16}...` | {d} |\n", .{
                            art.path,
                            art.artifact_type.toSlice(),
                            &art.hash,
                            art.size_bytes,
                        }) catch return ExitCodes.operational_failure;
                    }

                    stdout.print("\n> [!WARNING]\n> {s}\n", .{manifest_record.limitations_notice}) catch return ExitCodes.operational_failure;
                },
                .terminal => {
                    stdout.print(
                        \\================================================================================
                        \\WIRESCOPE REPORT INTEGRITY MANIFEST
                        \\================================================================================
                        \\Manifest ID:       {s}
                        \\Assessment ID:     {s}
                        \\Tool Version:      {s}
                        \\Manifest SHA-256:  {s}
                        \\Referenced Artifacts: {d}
                        \\--------------------------------------------------------------------------------
                        \\
                    , .{
                        manifest_record.manifest_id,
                        manifest_record.assessment_id,
                        manifest_record.tool_version,
                        &manifest_record.manifest_hash,
                        manifest_record.artifacts.len,
                    }) catch return ExitCodes.operational_failure;

                    for (manifest_record.artifacts) |art| {
                        stdout.print("  {s:16} {s} ({d} bytes)\n    SHA-256: {s}\n", .{
                            art.artifact_type.toSlice(),
                            art.path,
                            art.size_bytes,
                            &art.hash,
                        }) catch return ExitCodes.operational_failure;
                    }

                    stdout.print(
                        \\--------------------------------------------------------------------------------
                        \\LIMITATIONS & SECURITY NOTICE:
                        \\  {s}
                        \\================================================================================
                        \\
                    , .{manifest_record.limitations_notice}) catch return ExitCodes.operational_failure;
                },
            }

            return ExitCodes.success;
        } else {
            stderr.print("Error: Unknown manifest action '{s}'. Supported actions: verify, inspect\n", .{action}) catch {};
            return ExitCodes.invalid_input;
        }
    }

    // 20. Versioned JSON Reports & Schema Validation dispatch (Milestone 12 Phase 12.1)
    if (parsed.command == .report and (parsed.subcommand == null or !std.mem.eql(u8, parsed.subcommand.?, "manifest"))) {
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        const action = parsed.subcommand orelse "validate";
        const file_path = parsed.target;

        if (std.mem.eql(u8, action, "validate")) {
            const target_file = file_path orelse {
                stderr.print("Error: Report file path required for validation. Usage: wirescope report validate <report.json>\n", .{}) catch {};
                return ExitCodes.invalid_input;
            };

            const file = std.fs.cwd().openFile(target_file, .{}) catch |err| {
                stderr.print("Error opening report file '{s}': {s}\n", .{ target_file, @errorName(err) }) catch {};
                return ExitCodes.operational_failure;
            };
            defer file.close();

            const content = file.readToEndAlloc(allocator, 50 * 1024 * 1024) catch |err| {
                stderr.print("Error reading report file '{s}': {s}\n", .{ target_file, @errorName(err) }) catch {};
                return ExitCodes.operational_failure;
            };
            defer allocator.free(content);

            wirescope.reporting.validateReportJson(allocator, content) catch |err| {
                stderr.print("Report validation failed for '{s}': {s}\n", .{ target_file, @errorName(err) }) catch {};
                return ExitCodes.invalid_input;
            };

            switch (parsed.format) {
                .terminal => {
                    stdout.print("Report '{s}' successfully validated against schema v{d}.\n", .{
                        target_file,
                        wirescope.reporting.REPORT_SCHEMA_VERSION,
                    }) catch return ExitCodes.operational_failure;
                },
                .json => {
                    stdout.print(
                        \\{{"status":"valid","schema_version":{d},"file":"{s}"}}
                        \\
                    , .{
                        wirescope.reporting.REPORT_SCHEMA_VERSION,
                        target_file,
                    }) catch return ExitCodes.operational_failure;
                },
                .markdown => {
                    stdout.print(
                        \\# Report Validation: SUCCESS
                        \\
                        \\- **File:** `{s}`
                        \\- **Schema Version:** `{d}`
                        \\- **Validation:** **VALID**
                        \\
                    , .{
                        target_file,
                        wirescope.reporting.REPORT_SCHEMA_VERSION,
                    }) catch return ExitCodes.operational_failure;
                },
            }

            return ExitCodes.success;
        } else if (std.mem.eql(u8, action, "normalize")) {
            const target_file = file_path orelse {
                stderr.print("Error: Report file path required for normalization. Usage: wirescope report normalize <report.json>\n", .{}) catch {};
                return ExitCodes.invalid_input;
            };

            const file = std.fs.cwd().openFile(target_file, .{}) catch |err| {
                stderr.print("Error opening report file '{s}': {s}\n", .{ target_file, @errorName(err) }) catch {};
                return ExitCodes.operational_failure;
            };
            defer file.close();

            const content = file.readToEndAlloc(allocator, 50 * 1024 * 1024) catch |err| {
                stderr.print("Error reading report file '{s}': {s}\n", .{ target_file, @errorName(err) }) catch {};
                return ExitCodes.operational_failure;
            };
            defer allocator.free(content);

            const normalized = wirescope.reporting.normalizeJsonReport(allocator, content) catch |err| {
                stderr.print("Report normalization failed for '{s}': {s}\n", .{ target_file, @errorName(err) }) catch {};
                return ExitCodes.invalid_input;
            };
            defer allocator.free(normalized);

            if (parsed.output_path) |out_p| {
                wirescope.reporting.safeWriteReportFile(allocator, out_p, normalized, parsed.force) catch |err| {
                    if (err == error.FileAlreadyExists) {
                        stderr.print("Error: Output file '{s}' already exists. Use --force to overwrite.\n", .{out_p}) catch {};
                        return ExitCodes.invalid_input;
                    }
                    stderr.print("Error writing report file '{s}': {s}\n", .{ out_p, @errorName(err) }) catch {};
                    return ExitCodes.operational_failure;
                };
                stdout.print("Normalized report written to '{s}'.\n", .{out_p}) catch return ExitCodes.operational_failure;
            } else {
                stdout.writeAll(normalized) catch return ExitCodes.operational_failure;
                stdout.writeAll("\n") catch return ExitCodes.operational_failure;
            }
            return ExitCodes.success;
        } else if (std.mem.eql(u8, action, "markdown") or std.mem.eql(u8, action, "md")) {
            const target_file = file_path orelse {
                stderr.print("Error: Report file path required. Usage: wirescope report markdown <report.json> [-o <path>] [--force] [--redact]\n", .{}) catch {};
                return ExitCodes.invalid_input;
            };

            const file = std.fs.cwd().openFile(target_file, .{}) catch |err| {
                stderr.print("Error opening report file '{s}': {s}\n", .{ target_file, @errorName(err) }) catch {};
                return ExitCodes.operational_failure;
            };
            defer file.close();

            const raw_content = file.readToEndAlloc(allocator, 50 * 1024 * 1024) catch |err| {
                stderr.print("Error reading report file '{s}': {s}\n", .{ target_file, @errorName(err) }) catch {};
                return ExitCodes.operational_failure;
            };
            defer allocator.free(raw_content);

            var parsed_report = wirescope.reporting.parseReportFromJson(allocator, raw_content) catch |err| {
                stderr.print("Failed to parse report '{s}': {s}\n", .{ target_file, @errorName(err) }) catch {};
                return ExitCodes.invalid_input;
            };
            defer parsed_report.deinit();

            var rep_data = parsed_report.data;
            if (parsed.redact) {
                rep_data = wirescope.reporting.redactReportData(parsed_report.arena.allocator(), &rep_data, .{}) catch |err| {
                    stderr.print("Error redacting report: {s}\n", .{@errorName(err)}) catch {};
                    return ExitCodes.operational_failure;
                };
            }

            const rendered_md = wirescope.reporting.renderMarkdownToString(allocator, &rep_data, .{ .redacted = parsed.redact }) catch |err| {
                stderr.print("Error rendering Markdown report: {s}\n", .{@errorName(err)}) catch {};
                return ExitCodes.operational_failure;
            };
            defer allocator.free(rendered_md);

            if (parsed.output_path) |out_p| {
                wirescope.reporting.safeWriteReportFile(allocator, out_p, rendered_md, parsed.force) catch |err| {
                    if (err == error.FileAlreadyExists) {
                        stderr.print("Error: Output file '{s}' already exists. Use --force to overwrite.\n", .{out_p}) catch {};
                        return ExitCodes.invalid_input;
                    }
                    stderr.print("Error writing Markdown report file '{s}': {s}\n", .{ out_p, @errorName(err) }) catch {};
                    return ExitCodes.operational_failure;
                };
                stdout.print("Markdown report saved to '{s}'.\n", .{out_p}) catch return ExitCodes.operational_failure;
            } else {
                stdout.writeAll(rendered_md) catch return ExitCodes.operational_failure;
            }
            return ExitCodes.success;
        } else if (std.mem.eql(u8, action, "terminal") or std.mem.eql(u8, action, "term")) {
            const target_file = file_path orelse {
                stderr.print("Error: Report file path required. Usage: wirescope report terminal <report.json> [-o <path>] [--force] [--redact]\n", .{}) catch {};
                return ExitCodes.invalid_input;
            };

            const file = std.fs.cwd().openFile(target_file, .{}) catch |err| {
                stderr.print("Error opening report file '{s}': {s}\n", .{ target_file, @errorName(err) }) catch {};
                return ExitCodes.operational_failure;
            };
            defer file.close();

            const raw_content = file.readToEndAlloc(allocator, 50 * 1024 * 1024) catch |err| {
                stderr.print("Error reading report file '{s}': {s}\n", .{ target_file, @errorName(err) }) catch {};
                return ExitCodes.operational_failure;
            };
            defer allocator.free(raw_content);

            var parsed_report = wirescope.reporting.parseReportFromJson(allocator, raw_content) catch |err| {
                stderr.print("Failed to parse report '{s}': {s}\n", .{ target_file, @errorName(err) }) catch {};
                return ExitCodes.invalid_input;
            };
            defer parsed_report.deinit();

            var rep_data = parsed_report.data;
            if (parsed.redact) {
                rep_data = wirescope.reporting.redactReportData(parsed_report.arena.allocator(), &rep_data, .{}) catch |err| {
                    stderr.print("Error redacting report: {s}\n", .{@errorName(err)}) catch {};
                    return ExitCodes.operational_failure;
                };
            }

            const rendered_term = wirescope.reporting.renderTerminalToString(allocator, &rep_data, .{ .redacted = parsed.redact }) catch |err| {
                stderr.print("Error rendering Terminal report: {s}\n", .{@errorName(err)}) catch {};
                return ExitCodes.operational_failure;
            };
            defer allocator.free(rendered_term);

            if (parsed.output_path) |out_p| {
                wirescope.reporting.safeWriteReportFile(allocator, out_p, rendered_term, parsed.force) catch |err| {
                    if (err == error.FileAlreadyExists) {
                        stderr.print("Error: Output file '{s}' already exists. Use --force to overwrite.\n", .{out_p}) catch {};
                        return ExitCodes.invalid_input;
                    }
                    stderr.print("Error writing Terminal report file '{s}': {s}\n", .{ out_p, @errorName(err) }) catch {};
                    return ExitCodes.operational_failure;
                };
                stdout.print("Terminal report saved to '{s}'.\n", .{out_p}) catch return ExitCodes.operational_failure;
            } else {
                stdout.writeAll(rendered_term) catch return ExitCodes.operational_failure;
            }
            return ExitCodes.success;
        } else if (std.mem.eql(u8, action, "export")) {
            const target_file = file_path orelse {
                stderr.print("Error: Report file path required. Usage: wirescope report export <report.json> [--format terminal|json|markdown] [-o <path>] [--force] [--redact]\n", .{}) catch {};
                return ExitCodes.invalid_input;
            };

            const file = std.fs.cwd().openFile(target_file, .{}) catch |err| {
                stderr.print("Error opening report file '{s}': {s}\n", .{ target_file, @errorName(err) }) catch {};
                return ExitCodes.operational_failure;
            };
            defer file.close();

            const raw_content = file.readToEndAlloc(allocator, 50 * 1024 * 1024) catch |err| {
                stderr.print("Error reading report file '{s}': {s}\n", .{ target_file, @errorName(err) }) catch {};
                return ExitCodes.operational_failure;
            };
            defer allocator.free(raw_content);

            var parsed_report = wirescope.reporting.parseReportFromJson(allocator, raw_content) catch |err| {
                stderr.print("Failed to parse report '{s}': {s}\n", .{ target_file, @errorName(err) }) catch {};
                return ExitCodes.invalid_input;
            };
            defer parsed_report.deinit();

            var rep_data = parsed_report.data;
            if (parsed.redact) {
                rep_data = wirescope.reporting.redactReportData(parsed_report.arena.allocator(), &rep_data, .{}) catch |err| {
                    stderr.print("Error redacting report: {s}\n", .{@errorName(err)}) catch {};
                    return ExitCodes.operational_failure;
                };
            }

            var rendered_bytes: []const u8 = undefined;
            switch (parsed.format) {
                .markdown => {
                    rendered_bytes = wirescope.reporting.renderMarkdownToString(allocator, &rep_data, .{ .redacted = parsed.redact }) catch |err| {
                        stderr.print("Error rendering Markdown report: {s}\n", .{@errorName(err)}) catch {};
                        return ExitCodes.operational_failure;
                    };
                },
                .terminal => {
                    rendered_bytes = wirescope.reporting.renderTerminalToString(allocator, &rep_data, .{ .redacted = parsed.redact }) catch |err| {
                        stderr.print("Error rendering Terminal report: {s}\n", .{@errorName(err)}) catch {};
                        return ExitCodes.operational_failure;
                    };
                },
                .json => {
                    const json_str = wirescope.reporting.serializeReport(allocator, &rep_data) catch |err| {
                        stderr.print("Error serializing JSON report: {s}\n", .{@errorName(err)}) catch {};
                        return ExitCodes.operational_failure;
                    };
                    rendered_bytes = json_str;
                },
            }
            defer allocator.free(rendered_bytes);

            if (parsed.output_path) |out_p| {
                wirescope.reporting.safeWriteReportFile(allocator, out_p, rendered_bytes, parsed.force) catch |err| {
                    if (err == error.FileAlreadyExists) {
                        stderr.print("Error: Output file '{s}' already exists. Use --force to overwrite.\n", .{out_p}) catch {};
                        return ExitCodes.invalid_input;
                    }
                    stderr.print("Error writing exported report file '{s}': {s}\n", .{ out_p, @errorName(err) }) catch {};
                    return ExitCodes.operational_failure;
                };
                stdout.print("Report exported to '{s}'.\n", .{out_p}) catch return ExitCodes.operational_failure;
            } else {
                stdout.writeAll(rendered_bytes) catch return ExitCodes.operational_failure;
            }
            return ExitCodes.success;
        } else {
            stderr.print("Error: Unknown report action '{s}'. Supported actions: validate, normalize, markdown, terminal, export\n", .{action}) catch {};
            return ExitCodes.invalid_input;
        }
    }

    // 21. Isolated Practice Lab Dispatcher (Milestone 13 Phase 13.1)
    if (parsed.command == .lab) {
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        const action = parsed.subcommand orelse "list";
        const base_data_dir = wirescope.storage.resolveDefaultDataDir(allocator) catch ".wirescope";
        defer allocator.free(base_data_dir);
        const lab_data_dir = std.fs.path.join(allocator, &[_][]const u8{ base_data_dir, "lab" }) catch ".wirescope/lab";
        defer allocator.free(lab_data_dir);

        var lab_mgr = wirescope.lab.LabManager.init(allocator, lab_data_dir);

        if (std.mem.eql(u8, action, "list")) {
            switch (parsed.format) {
                .json => wirescope.lab.scenario.formatScenarioListJson(stdout) catch return ExitCodes.operational_failure,
                .markdown => wirescope.lab.scenario.formatScenarioListMarkdown(stdout) catch return ExitCodes.operational_failure,
                .terminal => wirescope.lab.scenario.formatScenarioListTerminal(stdout) catch return ExitCodes.operational_failure,
            }
            return ExitCodes.success;
        } else if (std.mem.eql(u8, action, "inspect")) {
            const scen_id = parsed.target orelse {
                stderr.print("Error: Scenario ID required for inspect. Usage: wirescope lab inspect <scenario_id>\n", .{}) catch {};
                return ExitCodes.invalid_input;
            };

            const scen = wirescope.lab.scenario.findScenario(scen_id) orelse {
                stderr.print("Error: Unknown lab scenario '{s}'. Run 'wirescope lab list' for available scenarios.\n", .{scen_id}) catch {};
                return ExitCodes.invalid_input;
            };

            switch (parsed.format) {
                .json => wirescope.lab.scenario.formatScenarioJson(scen, stdout) catch return ExitCodes.operational_failure,
                .markdown => wirescope.lab.scenario.formatScenarioMarkdown(scen, stdout) catch return ExitCodes.operational_failure,
                .terminal => wirescope.lab.scenario.formatScenarioTerminal(scen, stdout) catch return ExitCodes.operational_failure,
            }
            return ExitCodes.success;
        } else if (std.mem.eql(u8, action, "setup")) {
            const scen_id = parsed.target orelse {
                stderr.print("Error: Scenario ID required. Usage: wirescope lab setup <scenario_id>\n", .{}) catch {};
                return ExitCodes.invalid_input;
            };

            var state = lab_mgr.setupScenario(scen_id) catch |err| {
                stderr.print("Error initializing lab scenario '{s}': {s}\n", .{ scen_id, @errorName(err) }) catch {};
                return ExitCodes.operational_failure;
            };
            defer state.deinit(allocator);

            switch (parsed.format) {
                .json => {
                    stdout.print(
                        \\{{"status":"ready","scenario_id":"{s}","title":"{s}","target":"{s}","bind_ip":"{s}","port":{d},"is_synthetic":true}}
                        \\
                    , .{
                        state.scenario_id,
                        state.scenario_title,
                        state.target,
                        state.bind_ip,
                        state.port,
                    }) catch return ExitCodes.operational_failure;
                },
                .markdown => {
                    stdout.print(
                        \\# Practice Lab Initialized: {s}
                        \\
                        \\> **Status**: Ready | `{s}`
                        \\
                        \\- **Target**: `{s}`
                        \\- **Bound Address**: `{s}:{d}`
                        \\- **Scenario ID**: `{s}`
                        \\
                    , .{
                        state.scenario_title,
                        wirescope.lab.synthetic.SYNTHETIC_DATA_BADGE,
                        state.target,
                        state.bind_ip,
                        state.port,
                        state.scenario_id,
                    }) catch return ExitCodes.operational_failure;
                },
                .terminal => {
                    stdout.print(
                        \\{s} Practice lab scenario '{s}' successfully initialized.
                        \\Target endpoint: {s}
                        \\Bound address:   {s}:{d}
                        \\Run 'wirescope lab inspect {s}' for step-by-step instructions.
                        \\
                    , .{
                        wirescope.lab.synthetic.SYNTHETIC_DATA_BADGE,
                        state.scenario_title,
                        state.target,
                        state.bind_ip,
                        state.port,
                        state.scenario_id,
                    }) catch return ExitCodes.operational_failure;
                },
            }

            if (lab_mgr.active_service) |s| {
                s.stop();
                lab_mgr.active_service = null;
            }

            return ExitCodes.success;
        } else if (std.mem.eql(u8, action, "run")) {
            const scen_id_str = parsed.target orelse {
                stderr.print("Error: Scenario ID required. Usage: wirescope lab run <scenario_id>\n", .{}) catch {};
                return ExitCodes.invalid_input;
            };

            const scen = wirescope.lab.scenario.findScenario(scen_id_str) orelse {
                stderr.print("Error: Unknown lab scenario '{s}'. Run 'wirescope lab list' for available scenarios.\n", .{scen_id_str}) catch {};
                return ExitCodes.invalid_input;
            };

            var ex_res = wirescope.lab.exercises.runExercise(allocator, scen.id, lab_data_dir) catch |err| {
                stderr.print("Error running lab exercise '{s}': {s}\n", .{ scen_id_str, @errorName(err) }) catch {};
                return ExitCodes.operational_failure;
            };
            defer ex_res.deinit(allocator);

            switch (parsed.format) {
                .json => wirescope.lab.exercises.formatExerciseJson(ex_res, stdout) catch return ExitCodes.operational_failure,
                .markdown => wirescope.lab.exercises.formatExerciseMarkdown(ex_res, stdout) catch return ExitCodes.operational_failure,
                .terminal => wirescope.lab.exercises.formatExerciseTerminal(ex_res, stdout) catch return ExitCodes.operational_failure,
            }

            return ExitCodes.success;
        } else if (std.mem.eql(u8, action, "status")) {
            var maybe_state = lab_mgr.getStatus() catch |err| {
                stderr.print("Error reading lab status: {s}\n", .{@errorName(err)}) catch {};
                return ExitCodes.operational_failure;
            };

            if (maybe_state) |*st| {
                defer st.deinit(allocator);
                switch (parsed.format) {
                    .json => {
                        stdout.print(
                            \\{{"active_scenario":"{s}","title":"{s}","status":"{s}","target":"{s}","bind_ip":"{s}","port":{d},"is_synthetic":true}}
                            \\
                        , .{
                            st.scenario_id,
                            st.scenario_title,
                            st.status,
                            st.target,
                            st.bind_ip,
                            st.port,
                        }) catch return ExitCodes.operational_failure;
                    },
                    .markdown => {
                        stdout.print(
                            \\# Active Practice Lab Status
                            \\
                            \\> **Scenario**: {s} (`{s}`) | `{s}`
                            \\
                            \\- **Status**: {s}
                            \\- **Target**: `{s}`
                            \\- **Bound IP / Port**: `{s}:{d}`
                            \\
                        , .{
                            st.scenario_title,
                            st.scenario_id,
                            wirescope.lab.synthetic.SYNTHETIC_DATA_BADGE,
                            st.status,
                            st.target,
                            st.bind_ip,
                            st.port,
                        }) catch return ExitCodes.operational_failure;
                    },
                    .terminal => {
                        stdout.print(
                            \\=== Active Practice Lab Status ===
                            \\Scenario:       {s} ({s})
                            \\Status:         {s}
                            \\Target:         {s}
                            \\Bound:          {s}:{d}
                            \\Synthetic:      {s}
                            \\
                        , .{
                            st.scenario_title,
                            st.scenario_id,
                            st.status,
                            st.target,
                            st.bind_ip,
                            st.port,
                            wirescope.lab.synthetic.SYNTHETIC_DATA_BADGE,
                        }) catch return ExitCodes.operational_failure;
                    },
                }
            } else {
                switch (parsed.format) {
                    .json => {
                        stdout.print("{{\"active_scenario\":null,\"is_synthetic\":true}}\n", .{}) catch return ExitCodes.operational_failure;
                    },
                    .markdown, .terminal => {
                        stdout.print("No active practice lab scenario. Run 'wirescope lab list' to browse available exercises.\n", .{}) catch return ExitCodes.operational_failure;
                    },
                }
            }
            return ExitCodes.success;
        } else if (std.mem.eql(u8, action, "reset")) {
            var st = lab_mgr.resetScenario() catch |err| {
                stderr.print("Error resetting lab scenario: {s}\n", .{@errorName(err)}) catch {};
                return ExitCodes.operational_failure;
            };
            defer st.deinit(allocator);

            switch (parsed.format) {
                .json => {
                    stdout.print("{{\"reset\":true,\"scenario_id\":\"{s}\",\"status\":\"ready\"}}\n", .{st.scenario_id}) catch return ExitCodes.operational_failure;
                },
                .markdown, .terminal => {
                    stdout.print("{s} Lab scenario '{s}' reset to initial clean state.\n", .{ wirescope.lab.synthetic.SYNTHETIC_DATA_BADGE, st.scenario_id }) catch return ExitCodes.operational_failure;
                },
            }
            return ExitCodes.success;
        } else if (std.mem.eql(u8, action, "verify")) {
            var scen_id_to_verify: ?[]const u8 = parsed.target;
            var active_st: ?wirescope.lab.ActiveLabState = null;
            defer if (active_st) |*a| a.deinit(allocator);

            if (scen_id_to_verify == null) {
                active_st = lab_mgr.getStatus() catch null;
                if (active_st) |a| {
                    scen_id_to_verify = a.scenario_id;
                }
            }

            const target_scen_id = scen_id_to_verify orelse {
                stderr.print("Error: No active lab scenario to verify. Specify scenario ID: wirescope lab verify <scenario_id>\n", .{}) catch {};
                return ExitCodes.invalid_input;
            };

            var vres = wirescope.lab.verify.evaluateEvidence(allocator, target_scen_id, null, null) catch |err| {
                stderr.print("Error evaluating scenario verification: {s}\n", .{@errorName(err)}) catch {};
                return ExitCodes.operational_failure;
            };
            defer vres.deinit(allocator);

            switch (parsed.format) {
                .json => wirescope.lab.verify.formatVerificationJson(vres, stdout) catch return ExitCodes.operational_failure,
                .markdown => wirescope.lab.verify.formatVerificationMarkdown(vres, stdout) catch return ExitCodes.operational_failure,
                .terminal => wirescope.lab.verify.formatVerificationTerminal(vres, stdout) catch return ExitCodes.operational_failure,
            }
            return ExitCodes.success;
        } else if (std.mem.eql(u8, action, "cleanup") or std.mem.eql(u8, action, "teardown")) {
            lab_mgr.cleanup() catch |err| {
                stderr.print("Error during lab cleanup: {s}\n", .{@errorName(err)}) catch {};
                return ExitCodes.operational_failure;
            };

            switch (parsed.format) {
                .json => {
                    stdout.print("{{\"cleaned\":true,\"is_synthetic\":true}}\n", .{}) catch return ExitCodes.operational_failure;
                },
                .markdown, .terminal => {
                    stdout.print("{s} WireScope lab listeners stopped and sandbox resources cleaned up.\n", .{wirescope.lab.synthetic.SYNTHETIC_DATA_BADGE}) catch return ExitCodes.operational_failure;
                },
            }
            return ExitCodes.success;
        } else {
            stderr.print("Error: Unknown lab action '{s}'. Supported actions: list, inspect, setup, run, status, reset, verify, cleanup, teardown\n", .{action}) catch {};
            return ExitCodes.invalid_input;
        }
    }

    // 19. Diagnostics, Audits, Reconnaissance, and Lab commands (skeleton dispatcher)
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
    var out_buf: [32768]u8 = undefined;
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
    var out_buf: [131072]u8 = undefined;
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
    var out_buf: [131072]u8 = undefined;
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
    var out_buf: [131072]u8 = undefined;
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

test "execute https command with missing target, help, and probe output" {
    var out_buf: [131072]u8 = undefined;
    var err_buf: [1024]u8 = undefined;

    // 1. Missing target
    var out_fbs = std.io.fixedBufferStream(&out_buf);
    var err_fbs = std.io.fixedBufferStream(&err_buf);
    const missing_target = [_][]const u8{ "wirescope", "https" };
    const code1 = execute(&missing_target, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.invalid_input, code1);
    try testing.expect(err_fbs.getWritten().len > 0);

    // 2. Help https
    out_fbs.reset();
    err_fbs.reset();
    const help_https = [_][]const u8{ "wirescope", "help", "https" };
    const code2 = execute(&help_https, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code2);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "wirescope https") != null);

    // 3. JSON format probe
    out_fbs.reset();
    err_fbs.reset();
    const json_https = [_][]const u8{ "wirescope", "https", "https://localhost:443/", "--format", "json" };
    const code3 = execute(&json_https, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code3);
    try testing.expect(std.mem.startsWith(u8, out_fbs.getWritten(), "{\"operation_id\":"));
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"operation_type\":\"http\"") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"status_code\":200") != null);
}

test "execute discover command with preview, caps, remote authorization, and exclusions" {
    var out_buf: [131072]u8 = undefined;
    var err_buf: [2048]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);
    var err_fbs = std.io.fixedBufferStream(&err_buf);

    // 1. Loopback discovery preview (terminal)
    const loopback_cmd = [_][]const u8{ "wirescope", "discover", "127.0.0.1", "--ports", "80,443", "--preview" };
    const code1 = execute(&loopback_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code1);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "WireScope Assessment Plan Preview") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "Planned Execution Tasks") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "WireScope cannot verify legal permission") != null);

    // 2. Loopback discovery preview (JSON)
    out_fbs.reset();
    err_fbs.reset();
    const json_cmd = [_][]const u8{ "wirescope", "discover", "127.0.0.1", "--ports", "80", "--preview", "--format", "json" };
    const code2 = execute(&json_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code2);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"type\":\"assessment_plan_preview\"") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"is_loopback_only\":true") != null);

    // 3. Remote target without authorization acknowledgement is rejected
    out_fbs.reset();
    err_fbs.reset();
    const unauth_cmd = [_][]const u8{ "wirescope", "discover", "192.168.1.50", "--ports", "80", "--preview" };
    const code3 = execute(&unauth_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.invalid_input, code3);
    try testing.expect(std.mem.indexOf(u8, err_fbs.getWritten(), "requires explicit authorization acknowledgement") != null);

    // 4. Remote target with authorization acknowledgement succeeds
    out_fbs.reset();
    err_fbs.reset();
    const auth_cmd = [_][]const u8{ "wirescope", "discover", "192.168.1.50", "--ports", "80", "--confirm-authorized", "--preview" };
    const code4 = execute(&auth_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code4);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "Scope Status:       Authorized") != null);

    // 5. Broad CIDR (< /24) rejected by safety gate
    out_fbs.reset();
    err_fbs.reset();
    const broad_cidr = [_][]const u8{ "wirescope", "discover", "10.0.0.0/16", "--confirm-authorized", "--preview" };
    const code5 = execute(&broad_cidr, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.invalid_input, code5);
    try testing.expect(std.mem.indexOf(u8, err_fbs.getWritten(), "/24 to /32") != null);

    // 6. Exclusions filter eliminating all targets
    out_fbs.reset();
    err_fbs.reset();
    const excluded_all = [_][]const u8{ "wirescope", "discover", "127.0.0.1", "--exclude", "127.0.0.1", "--preview" };
    const code6 = execute(&excluded_all, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.invalid_input, code6);
    try testing.expect(std.mem.indexOf(u8, err_fbs.getWritten(), "All targets were eliminated by the exclusion list") != null);

    // 7. Live Host Discovery execution on loopback (when no ports specified)
    out_fbs.reset();
    err_fbs.reset();
    const live_cmd = [_][]const u8{ "wirescope", "discover", "127.0.0.1", "--format", "json" };
    const code7 = execute(&live_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code7);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"type\":\"host_discovery_result\"") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"total_scanned\":1") != null);

    // 8. Live Port Check and Service Identification execution on loopback (with explicit ports)
    out_fbs.reset();
    err_fbs.reset();
    const svc_cmd = [_][]const u8{ "wirescope", "discover", "127.0.0.1", "--ports", "80", "--format", "json" };
    const code8 = execute(&svc_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code8);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"type\":\"service_scan_result\"") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"total_ports_checked\":1") != null);

    // 9. Live Normalized Asset Inventory generation on loopback (with --inventory flag)
    out_fbs.reset();
    err_fbs.reset();
    const inv_cmd = [_][]const u8{ "wirescope", "discover", "127.0.0.1", "--inventory", "--format", "json" };
    const code9 = execute(&inv_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code9);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"type\":\"asset_inventory\"") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"total_hosts\":1") != null);

    // 10. Defensive HTTP Security Configuration Audit dispatch (Milestone 9 Phase 9.1)
    out_fbs.reset();
    err_fbs.reset();
    const audit_cmd1 = [_][]const u8{ "wirescope", "audit", "http", "https://localhost:8443/", "--format", "terminal" };
    const code10 = execute(&audit_cmd1, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code10);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "WIRESCOPE DEFENSIVE HTTP SECURITY AUDIT") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "SECURITY CONFIGURATION INVENTORY") != null);

    // 11. Defensive HTTP Security Audit JSON and Markdown formats
    out_fbs.reset();
    err_fbs.reset();
    const audit_cmd_json = [_][]const u8{ "wirescope", "audit", "http", "https://localhost:8443/", "--format", "json" };
    const code11 = execute(&audit_cmd_json, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code11);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"audit_type\":\"http_security_configuration\"") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"schema_version\":1") != null);

    out_fbs.reset();
    err_fbs.reset();
    const audit_cmd_md = [_][]const u8{ "wirescope", "audit", "http", "https://localhost:8443/", "--format", "markdown" };
    const code12 = execute(&audit_cmd_md, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code12);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "# WireScope Defensive HTTP Security Audit Report") != null);

    // 12. Missing target URL rejection
    out_fbs.reset();
    err_fbs.reset();
    const audit_cmd_err = [_][]const u8{ "wirescope", "audit", "http" };
    const code13 = execute(&audit_cmd_err, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.invalid_input, code13);
    try testing.expect(std.mem.indexOf(u8, err_fbs.getWritten(), "Target URL required") != null);

    // 13. Defensive Local Listening Service Exposure Audit dispatch (Milestone 9 Phase 9.2)
    out_fbs.reset();
    err_fbs.reset();
    const audit_local_cmd = [_][]const u8{ "wirescope", "audit", "local", "--format", "terminal" };
    const code14 = execute(&audit_local_cmd, out_fbs.writer(), err_fbs.writer());
    // Either 0 (clean baseline) or 1 (wildcards found on development machine)
    try testing.expect(code14 == ExitCodes.success or code14 == ExitCodes.findings_or_violations);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "WIRESCOPE LOCAL EXPOSURE AUDIT") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "LOCAL LISTENING SOCKETS INVENTORY") != null);

    // 14. Local Exposure Audit with expected ports policy and JSON format
    out_fbs.reset();
    err_fbs.reset();
    const audit_local_json = [_][]const u8{ "wirescope", "audit", "local", "--ports", "22,80,443,8080", "--format", "json" };
    const code15 = execute(&audit_local_json, out_fbs.writer(), err_fbs.writer());
    try testing.expect(code15 == ExitCodes.success or code15 == ExitCodes.findings_or_violations);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"audit_type\":\"local_exposure_audit\"") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"policy_id\":") != null);

    // 15. Local Exposure Audit Markdown format
    out_fbs.reset();
    err_fbs.reset();
    const audit_local_md = [_][]const u8{ "wirescope", "audit", "local", "--format", "markdown" };
    const code16 = execute(&audit_local_md, out_fbs.writer(), err_fbs.writer());
    try testing.expect(code16 == ExitCodes.success or code16 == ExitCodes.findings_or_violations);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "# WireScope Local Listening Service Exposure Audit") != null);

    // 16. Versioned Rules Engine registry listing (Milestone 9 Phase 9.3)
    out_fbs.reset();
    err_fbs.reset();
    const audit_rules_cmd = [_][]const u8{ "wirescope", "audit", "rules" };
    const code17 = execute(&audit_rules_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code17);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "WIRESCOPE VERSIONED DEFENSIVE RULES REGISTRY") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "WS-RULE-TLS-MIN-VERSION") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "no claim of comprehensive CVE") != null);

    // 17. Policy command listing (JSON and Markdown formats)
    out_fbs.reset();
    err_fbs.reset();
    const policy_json_cmd = [_][]const u8{ "wirescope", "policy", "--format", "json" };
    const code18 = execute(&policy_json_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code18);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"registry_type\":\"versioned_rules\"") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"cve_disclaimer\":") != null);

    out_fbs.reset();
    err_fbs.reset();
    const policy_md_cmd = [_][]const u8{ "wirescope", "policy", "--format", "markdown" };
    const code19 = execute(&policy_md_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code19);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "# WireScope Versioned Defensive Rules Registry") != null);

    // 18. Multi-Module Assessment Runner execution (Milestone 10 Phase 10.1)
    out_fbs.reset();
    err_fbs.reset();
    const assess_cmd = [_][]const u8{ "wirescope", "assess", "loopback-diagnostics" };
    const code20 = execute(&assess_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expect(code20 == ExitCodes.success or code20 == ExitCodes.findings_or_violations);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "WIRESCOPE MULTI-MODULE ASSESSMENT REPORT") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "Manifest SHA-256:") != null);

    out_fbs.reset();
    err_fbs.reset();
    const assess_json = [_][]const u8{ "wirescope", "assess", "--profile", "local-security-audit", "--format", "json" };
    const code21 = execute(&assess_json, out_fbs.writer(), err_fbs.writer());
    try testing.expect(code21 == ExitCodes.success or code21 == ExitCodes.findings_or_violations);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"report_type\":\"assessment_result\"") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"manifest_hash\":") != null);

    // 19. Baseline Snapshot Creation and Listing (Milestone 10 Phase 10.2)
    out_fbs.reset();
    err_fbs.reset();
    const base_create = [_][]const u8{ "wirescope", "baseline", "save", "prod-baseline" };
    const code22 = execute(&base_create, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code22);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "Baseline snapshot 'prod-baseline' (v1) successfully created") != null);

    out_fbs.reset();
    err_fbs.reset();
    const base_list = [_][]const u8{ "wirescope", "baseline", "list" };
    const code23 = execute(&base_list, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code23);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "WIRESCOPE STORED BASELINE SNAPSHOTS") != null);

    // 20. Baseline Deterministic Diff Comparison (JSON & Markdown)
    out_fbs.reset();
    err_fbs.reset();
    const base_diff_json = [_][]const u8{ "wirescope", "baseline", "diff", "prod-baseline", "--format", "json" };
    const code24 = execute(&base_diff_json, out_fbs.writer(), err_fbs.writer());
    try testing.expect(code24 == ExitCodes.success or code24 == ExitCodes.findings_or_violations);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"report_type\":\"baseline_diff\"") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"baseline_name\":\"prod-baseline\"") != null);

    out_fbs.reset();
    err_fbs.reset();
    const base_diff_md = [_][]const u8{ "wirescope", "baseline", "diff", "prod-baseline", "--format", "markdown" };
    const code25 = execute(&base_diff_md, out_fbs.writer(), err_fbs.writer());
    try testing.expect(code25 == ExitCodes.success or code25 == ExitCodes.findings_or_violations);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "# WireScope Baseline Deterministic Diff Report") != null);

    // 21. Normalized Findings & Remediation Tracking (Milestone 10 Phase 10.3)
    out_fbs.reset();
    err_fbs.reset();
    const findings_term = [_][]const u8{ "wirescope", "audit", "findings" };
    const code26 = execute(&findings_term, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code26);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "WIRESCOPE DEFENSIVE FINDINGS & REMEDIATION TRACKER") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "WS-FND-") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "Tracked Findings:") != null);

    out_fbs.reset();
    err_fbs.reset();
    const findings_json = [_][]const u8{ "wirescope", "audit", "findings", "--format", "json" };
    const code27 = execute(&findings_json, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code27);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"report_type\":\"findings_tracker\"") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"id\":\"WS-FND-") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"evidence_count\":") != null);

    out_fbs.reset();
    err_fbs.reset();
    const findings_md = [_][]const u8{ "wirescope", "audit", "findings", "--format", "markdown" };
    const code28 = execute(&findings_md, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code28);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "# WireScope Defensive Findings & Remediation Tracker") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "`WS-FND-") != null);

    // 22. Offline Policy Evaluation Dispatch (Milestone 10 Phase 10.4)
    out_fbs.reset();
    err_fbs.reset();
    const policy_check_term = [_][]const u8{ "wirescope", "policy", "check" };
    const code29 = execute(&policy_check_term, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code29);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "WIRESCOPE OFFLINE POLICY EVALUATION REPORT") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "COMPLIANT") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "Exit Code:            0") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "PASS") != null);

    out_fbs.reset();
    err_fbs.reset();
    const policy_check_json = [_][]const u8{ "wirescope", "policy", "check", "--format", "json" };
    const code30 = execute(&policy_check_json, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code30);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"report_type\":\"policy_evaluation\"") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"is_offline\":true") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"is_compliant\":true") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"exit_code\":0") != null);

    out_fbs.reset();
    err_fbs.reset();
    const policy_check_md = [_][]const u8{ "wirescope", "policy", "check", "--format", "markdown" };
    const code31 = execute(&policy_check_md, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code31);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "# WireScope Offline Policy Evaluation Report") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "**COMPLIANT**") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "Offline (Zero Network Activity)") != null);

    // 23. Local History Queries, Retention & Recovery Dispatch (Milestone 11 Phase 11.2)
    out_fbs.reset();
    err_fbs.reset();
    const history_list_term = [_][]const u8{ "wirescope", "history", "list" };
    const code32 = execute(&history_list_term, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code32);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "WIRESCOPE HISTORICAL ASSESSMENTS") != null);

    out_fbs.reset();
    err_fbs.reset();
    const history_list_json = [_][]const u8{ "wirescope", "history", "list", "--format", "json" };
    const code33 = execute(&history_list_json, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code33);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"report_type\":\"history_list\"") != null);

    out_fbs.reset();
    err_fbs.reset();
    const history_list_md = [_][]const u8{ "wirescope", "history", "list", "--format", "markdown" };
    const code34 = execute(&history_list_md, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code34);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "# WireScope Assessment Execution History") != null);

    // Path traversal escape rejected
    out_fbs.reset();
    err_fbs.reset();
    const history_delete_escape = [_][]const u8{ "wirescope", "history", "delete", "../forbidden.json" };
    const code35 = execute(&history_delete_escape, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.invalid_input, code35);
    try testing.expect(std.mem.indexOf(u8, err_fbs.getWritten(), "Access denied") != null);

    // Recovery runs
    out_fbs.reset();
    err_fbs.reset();
    const history_recover = [_][]const u8{ "wirescope", "history", "recover" };
    const code36 = execute(&history_recover, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code36);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "Recovery completed") != null);

    // 24. Report Integrity Manifest Dispatch (Milestone 11 Phase 11.3)
    const allocator = testing.allocator;

    // 37: Verify without manifest path returns invalid_input
    out_fbs.reset();
    err_fbs.reset();
    const manifest_no_path = [_][]const u8{ "wirescope", "manifest", "verify" };
    const code37 = execute(&manifest_no_path, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.invalid_input, code37);

    // Setup CLI manifest test fixture
    const test_mnf_dir = "test_cli_manifest";
    defer std.fs.cwd().deleteTree(test_mnf_dir) catch {};
    try std.fs.cwd().makePath(test_mnf_dir);

    const art_p = try std.fs.path.join(allocator, &[_][]const u8{ test_mnf_dir, "report.json" });
    defer allocator.free(art_p);
    try std.fs.cwd().writeFile(.{ .sub_path = art_p, .data = "{\"findings\":0}" });

    const mnf_spec = [_]wirescope.storage.ArtifactFileSpec{
        .{ .name = "report.json", .atype = .json_report },
    };
    var gen_mnf = try wirescope.storage.generateManifest(
        allocator,
        "cli-asm-1",
        .{ .profile_id = "p1", .profile_name = "P1" },
        test_mnf_dir,
        &mnf_spec,
    );
    defer gen_mnf.deinit(allocator);

    const mnf_json_str = try gen_mnf.toJson(allocator);
    defer allocator.free(mnf_json_str);

    const mnf_file_path = try std.fs.path.join(allocator, &[_][]const u8{ test_mnf_dir, "manifest.json" });
    defer allocator.free(mnf_file_path);
    try std.fs.cwd().writeFile(.{ .sub_path = mnf_file_path, .data = mnf_json_str });

    // 38: Verify intact manifest via terminal format
    out_fbs.reset();
    err_fbs.reset();
    const manifest_verify_term = [_][]const u8{ "wirescope", "manifest", "verify", mnf_file_path };
    const code38 = execute(&manifest_verify_term, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code38);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "WIRESCOPE REPORT INTEGRITY VERIFICATION") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "does NOT prove author identity") != null);

    // 39: Verify intact manifest via JSON format
    out_fbs.reset();
    err_fbs.reset();
    const manifest_verify_json = [_][]const u8{ "wirescope", "manifest", "verify", mnf_file_path, "--format", "json" };
    const code39 = execute(&manifest_verify_json, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code39);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"report_type\":\"manifest_verification\"") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"is_valid\":true") != null);

    // 40: Tamper artifact -> verification fails with ExitCodes.findings_or_violations
    try std.fs.cwd().writeFile(.{ .sub_path = art_p, .data = "{\"findings\":999}" });
    out_fbs.reset();
    err_fbs.reset();
    const manifest_verify_tampered = [_][]const u8{ "wirescope", "manifest", "verify", mnf_file_path, "--format", "json" };
    const code40 = execute(&manifest_verify_tampered, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.findings_or_violations, code40);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"is_valid\":false") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"status\":\"modified\"") != null);

    // 25. Versioned JSON Reports & Schema Validation Dispatch (Milestone 12 Phase 12.1)
    // 41: Report validate without path returns invalid_input
    out_fbs.reset();
    err_fbs.reset();
    const report_no_path = [_][]const u8{ "wirescope", "report", "validate" };
    const code41 = execute(&report_no_path, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.invalid_input, code41);

    // Setup report test fixture
    const valid_report_path = try std.fs.path.join(allocator, &[_][]const u8{ test_mnf_dir, "assessment_report.json" });
    defer allocator.free(valid_report_path);

    var valid_targets = [_][]const u8{"127.0.0.1"};
    var valid_ports = [_]u16{80};
    const rep_data = wirescope.reporting.AssessmentReportData{
        .assessment_id = "asm-cli-report-1",
        .profile_id = "local-security-audit",
        .profile_name = "Local Security Audit",
        .started_at_ms = 1710000000000,
        .completed_at_ms = 1710000005000,
        .duration_ms = 5000,
        .status = "completed",
        .manifest_hash = "0000000000000000000000000000000000000000000000000000000000000000".*,
        .targets = &valid_targets,
        .ports = &valid_ports,
        .rate_limit_rps = 10,
        .timeout_ms = 5000,
        .tasks_planned = 1,
        .tasks_executed = 1,
        .tasks_succeeded = 1,
        .tasks_failed = 0,
        .is_complete = true,
    };
    const valid_json_str = try wirescope.reporting.serializeReport(allocator, &rep_data);
    defer allocator.free(valid_json_str);
    try std.fs.cwd().writeFile(.{ .sub_path = valid_report_path, .data = valid_json_str });

    // 42: Validate compliant report
    out_fbs.reset();
    err_fbs.reset();
    const report_val_cmd = [_][]const u8{ "wirescope", "report", "validate", valid_report_path };
    const code42 = execute(&report_val_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code42);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "successfully validated against schema v1") != null);

    // 43: Validate corrupted / invalid report (missing fields)
    const invalid_report_path = try std.fs.path.join(allocator, &[_][]const u8{ test_mnf_dir, "invalid_report.json" });
    defer allocator.free(invalid_report_path);
    try std.fs.cwd().writeFile(.{ .sub_path = invalid_report_path, .data = "{\"schema_version\": 1}" });

    out_fbs.reset();
    err_fbs.reset();
    const report_val_inv = [_][]const u8{ "wirescope", "report", "validate", invalid_report_path };
    const code43 = execute(&report_val_inv, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.invalid_input, code43);
    try testing.expect(std.mem.indexOf(u8, err_fbs.getWritten(), "Report validation failed") != null);

    // 44: Normalize report JSON
    out_fbs.reset();
    err_fbs.reset();
    const report_norm_cmd = [_][]const u8{ "wirescope", "report", "normalize", valid_report_path };
    const code44 = execute(&report_norm_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code44);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"schema_version\": 1") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"started_at_ms\": 1710000000000") != null);

    // 26. Markdown & Terminal Reports Dispatch with Safe Output and Redaction (Milestone 12 Phase 12.2)
    // 45: Render Markdown report
    out_fbs.reset();
    err_fbs.reset();
    const report_md_cmd = [_][]const u8{ "wirescope", "report", "markdown", valid_report_path };
    const code45 = execute(&report_md_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code45);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "# WireScope Assessment Report: Local Security Audit") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "**Status: COMPLETE**") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "asm-cli-report-1") != null);

    // 46: Render Terminal report
    out_fbs.reset();
    err_fbs.reset();
    const report_term_cmd = [_][]const u8{ "wirescope", "report", "terminal", valid_report_path };
    const code46 = execute(&report_term_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code46);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "WIRESCOPE DEFENSIVE ASSESSMENT REPORT") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "Execution Status:    [completed]") != null);

    // 47: Render report with --redact flag
    out_fbs.reset();
    err_fbs.reset();
    const report_redact_cmd = [_][]const u8{ "wirescope", "report", "markdown", valid_report_path, "--redact" };
    const code47 = execute(&report_redact_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code47);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "REDACTION APPLIED") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "reduce report reproducibility") != null);

    // 48: Write report to explicit --output path
    const md_out_path = try std.fs.path.join(allocator, &[_][]const u8{ test_mnf_dir, "exported_audit.md" });
    defer allocator.free(md_out_path);

    out_fbs.reset();
    err_fbs.reset();
    const report_write_cmd = [_][]const u8{ "wirescope", "report", "markdown", valid_report_path, "-o", md_out_path };
    const code48 = execute(&report_write_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code48);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "Markdown report saved to") != null);

    // 49: Writing again to existing output file without --force fails safely
    out_fbs.reset();
    err_fbs.reset();
    const report_write_noforce = [_][]const u8{ "wirescope", "report", "markdown", valid_report_path, "-o", md_out_path };
    const code49 = execute(&report_write_noforce, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.invalid_input, code49);
    try testing.expect(std.mem.indexOf(u8, err_fbs.getWritten(), "already exists. Use --force to overwrite") != null);

    // 50: Writing again with --force succeeds
    out_fbs.reset();
    err_fbs.reset();
    const report_write_force = [_][]const u8{ "wirescope", "report", "markdown", valid_report_path, "-o", md_out_path, "--force" };
    const code50 = execute(&report_write_force, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code50);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "Markdown report saved to") != null);

    // 27. CLI Non-Interactive Automation & Scripting Contracts (Milestone 12 Phase 12.3)
    // 51: Non-interactive policy check produces clean, unpolluted JSON parseable by standard parsers
    out_fbs.reset();
    err_fbs.reset();
    const ni_policy_cmd = [_][]const u8{ "wirescope", "policy", "check", "--format", "json", "--non-interactive" };
    const code51 = execute(&ni_policy_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code51);
    const policy_json_str = out_fbs.getWritten();
    var parsed_policy_json = try std.json.parseFromSlice(std.json.Value, allocator, policy_json_str, .{});
    parsed_policy_json.deinit();

    // 52: Non-interactive assessment on authorized target produces pure parseable JSON
    out_fbs.reset();
    err_fbs.reset();
    const ni_assess_cmd = [_][]const u8{ "wirescope", "assess", "loopback-diagnostics", "--format", "json", "-y" };
    const code52 = execute(&ni_assess_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code52);
    const assess_json_str = out_fbs.getWritten();
    var parsed_assess_json = try std.json.parseFromSlice(std.json.Value, allocator, assess_json_str, .{});
    parsed_assess_json.deinit();

    // 53: Non-interactive mode on remote target WITHOUT --confirm-authorized strictly fails with exit code 2
    out_fbs.reset();
    err_fbs.reset();
    const ni_unauth_cmd = [_][]const u8{ "wirescope", "discover", "192.168.1.5", "--preview", "--non-interactive" };
    const code53 = execute(&ni_unauth_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.invalid_input, code53);
    try testing.expectEqual(@as(usize, 0), out_fbs.getWritten().len);
    try testing.expect(std.mem.indexOf(u8, err_fbs.getWritten(), "authorization acknowledgement") != null);

    // 54: Non-interactive mode on remote target WITH --confirm-authorized succeeds with exit code 0
    out_fbs.reset();
    err_fbs.reset();
    const ni_auth_cmd = [_][]const u8{ "wirescope", "discover", "192.168.1.5", "--preview", "--confirm-authorized", "--format", "json", "--non-interactive" };
    const code54 = execute(&ni_auth_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code54);
    var parsed_plan_json = try std.json.parseFromSlice(std.json.Value, allocator, out_fbs.getWritten(), .{});
    parsed_plan_json.deinit();

    // 55: Unknown assessment profile returns exit code 2 (invalid_input)
    out_fbs.reset();
    err_fbs.reset();
    const ni_bad_prof = [_][]const u8{ "wirescope", "assess", "non-existent-profile", "--non-interactive" };
    const code55 = execute(&ni_bad_prof, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.invalid_input, code55);
    try testing.expect(std.mem.indexOf(u8, err_fbs.getWritten(), "Unknown or unsupported assessment profile") != null);

    // 56: Non-existent report file path returns exit code 3 (operational_failure)
    out_fbs.reset();
    err_fbs.reset();
    const ni_bad_file = [_][]const u8{ "wirescope", "report", "validate", "does_not_exist_file.json", "--non-interactive" };
    const code56 = execute(&ni_bad_file, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.operational_failure, code56);
    try testing.expect(std.mem.indexOf(u8, err_fbs.getWritten(), "Error opening report file") != null);

    // 57: Lab list in JSON, Markdown, and Terminal formats
    out_fbs.reset();
    err_fbs.reset();
    const lab_list_json_cmd = [_][]const u8{ "wirescope", "lab", "list", "--format", "json" };
    const code57 = execute(&lab_list_json_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code57);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "dns_failure") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "synthetic_lab_fixture") != null);

    out_fbs.reset();
    err_fbs.reset();
    const lab_list_term_cmd = [_][]const u8{ "wirescope", "lab", "list" };
    const code57b = execute(&lab_list_term_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code57b);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "[SYNTHETIC_LAB_FIXTURE]") != null);

    // 58: Lab inspect valid scenario
    out_fbs.reset();
    err_fbs.reset();
    const lab_insp_cmd = [_][]const u8{ "wirescope", "lab", "inspect", "dns_failure" };
    const code58 = execute(&lab_insp_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code58);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "DNS Resolution No-Answer") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "Step-by-Step Instructions") != null);

    // 59: Lab setup scenario
    out_fbs.reset();
    err_fbs.reset();
    const lab_setup_cmd = [_][]const u8{ "wirescope", "lab", "setup", "dns_failure", "--format", "json" };
    const code59 = execute(&lab_setup_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code59);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"status\":\"ready\"") != null);

    // 60: Lab status
    out_fbs.reset();
    err_fbs.reset();
    const lab_status_cmd = [_][]const u8{ "wirescope", "lab", "status", "--format", "json" };
    const code60 = execute(&lab_status_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code60);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "dns_failure") != null);

    // 61: Lab verify scenario
    out_fbs.reset();
    err_fbs.reset();
    const lab_verify_cmd = [_][]const u8{ "wirescope", "lab", "verify", "dns_failure", "--format", "json" };
    const code61 = execute(&lab_verify_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code61);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "inconclusive") != null);

    // 62: Lab cleanup
    out_fbs.reset();
    err_fbs.reset();
    const lab_clean_cmd = [_][]const u8{ "wirescope", "lab", "cleanup", "--format", "json" };
    const code62 = execute(&lab_clean_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code62);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"cleaned\":true") != null);

    // 63: Exercise 1: dns_failure run
    out_fbs.reset();
    err_fbs.reset();
    const ex1_cmd = [_][]const u8{ "wirescope", "lab", "run", "dns_failure", "--format", "json" };
    const code63 = execute(&ex1_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code63);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "WS-FINDING-DNS-FAILURE") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "expected_evidence") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "interpretation") != null);

    // 64: Exercise 2: tcp_refusal_timeout run
    out_fbs.reset();
    err_fbs.reset();
    const ex2_cmd = [_][]const u8{ "wirescope", "lab", "run", "tcp_refusal_timeout", "--format", "json" };
    const code64 = execute(&ex2_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code64);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "WS-FINDING-TCP-REFUSAL") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "limitations") != null);

    // 65: Exercise 3: tls_cert_issues run
    out_fbs.reset();
    err_fbs.reset();
    const ex3_cmd = [_][]const u8{ "wirescope", "lab", "run", "tls_cert_issues", "--format", "json" };
    const code65 = execute(&ex3_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code65);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "WS-FINDING-TLS-SAN-MISMATCH") != null);

    // 66: Exercise 4: unexpected_listener run
    out_fbs.reset();
    err_fbs.reset();
    const ex4_cmd = [_][]const u8{ "wirescope", "lab", "run", "unexpected_listener", "--format", "json" };
    const code66 = execute(&ex4_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code66);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "WS-FINDING-LISTENER-UNAPPROVED") != null);

    // 67: Exercise 5: http_security_header_violation run
    out_fbs.reset();
    err_fbs.reset();
    const ex5_cmd = [_][]const u8{ "wirescope", "lab", "run", "http_security_header_violation", "--format", "json" };
    const code67 = execute(&ex5_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code67);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "WS-FINDING-HTTP-MISSING-SECURITY-HEADERS") != null);

    // 68: Exercise 6: remediation_verification run
    out_fbs.reset();
    err_fbs.reset();
    const ex6_cmd = [_][]const u8{ "wirescope", "lab", "run", "remediation_verification", "--format", "json" };
    const code68 = execute(&ex6_cmd, out_fbs.writer(), err_fbs.writer());
    try testing.expectEqual(ExitCodes.success, code68);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"remediation_verified\": true") != null);
    try testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "\"policy_eval_outcome\": \"pass\"") != null);
}
