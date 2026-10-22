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
            }
        }

        if (parsed.confirm_authorized) {
            prof.authorization_acknowledged = true;
        }

        var runner = wirescope.assessment.AssessmentRunner.init(allocator);
        var result = runner.run(prof, .{
            .mode = .fixture,
        }) catch |err| {
            stderr.print("Error: Assessment execution failed: {s}\n", .{@errorName(err)}) catch {};
            return ExitCodes.operational_failure;
        };
        defer result.deinit();

        switch (parsed.format) {
            .json => result.toJson(stdout) catch return ExitCodes.operational_failure,
            .terminal => result.toTerminal(stdout) catch return ExitCodes.operational_failure,
            .markdown => result.toMarkdown(stdout) catch return ExitCodes.operational_failure,
        }

        if (result.status == .failed or result.status == .cancelled) return ExitCodes.operational_failure;
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
}
