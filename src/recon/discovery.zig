const std = @import("std");
const testing = std.testing;

const plan_mod = @import("plan.zig");
const scope_mod = @import("scope.zig");
const probes = @import("../probes/root.zig");

pub const AssessmentPlan = plan_mod.AssessmentPlan;
pub const LEGAL_DISCLAIMER = plan_mod.LEGAL_DISCLAIMER;
pub const TcpConnector = probes.TcpConnector;
pub const RealTcpConnector = probes.RealTcpConnector;
pub const MockTcpConnector = probes.MockTcpConnector;
pub const TcpFailureCategory = probes.TcpFailureCategory;
pub const CancellationToken = probes.CancellationToken;

/// Reachability state of an inspected host during bounded discovery
pub const HostReachabilityState = enum {
    reachable,
    inconclusive,
    failed,
    cancelled,

    pub fn asString(self: HostReachabilityState) []const u8 {
        return switch (self) {
            .reachable => "reachable",
            .inconclusive => "inconclusive",
            .failed => "failed",
            .cancelled => "cancelled",
        };
    }
};

/// Method employed for host reachability verification
pub const DiscoveryMethod = enum {
    tcp_probe,

    pub fn asString(self: DiscoveryMethod) []const u8 {
        return switch (self) {
            .tcp_probe => "tcp_probe",
        };
    }
};

/// Observable evidence backing a reachability conclusion
pub const DiscoveryEvidence = struct {
    response_port: ?u16 = null,
    response_type: []const u8,
    rtt_ms: ?f64 = null,
    notes: []const u8,
};

/// Observed host with state, method, and empirical evidence
pub const DiscoveredHost = struct {
    target: []const u8,
    state: HostReachabilityState,
    method: DiscoveryMethod,
    evidence: DiscoveryEvidence,

    pub fn deinit(self: *DiscoveredHost, allocator: std.mem.Allocator) void {
        allocator.free(self.target);
        allocator.free(self.evidence.response_type);
        allocator.free(self.evidence.notes);
    }
};

/// Resource constraints and operational parameters for bounded discovery
pub const DiscoveryConfig = struct {
    timeout_ms: u32 = 2000,
    concurrency: u16 = 4,
    rate_limit_delay_ms: u32 = 5,
    discovery_ports: []const u16 = &.{ 80, 443 },
    max_hosts: usize = 256,
};

/// Aggregated host discovery outcome
pub const HostDiscoveryResult = struct {
    hosts: []DiscoveredHost,
    total_scanned: usize,
    reachable_count: usize,
    inconclusive_count: usize,
    failed_count: usize,
    cancelled_count: usize,
    elapsed_ms: u64,
    legal_disclaimer: []const u8 = LEGAL_DISCLAIMER,

    pub fn deinit(self: *HostDiscoveryResult, allocator: std.mem.Allocator) void {
        for (self.hosts) |*h| {
            h.deinit(allocator);
        }
        if (self.hosts.len > 0) {
            allocator.free(self.hosts);
        }
    }

    /// Formats human-readable CLI terminal output
    pub fn toTerminal(self: *const HostDiscoveryResult, writer: anytype) !void {
        try writer.print(
            \\WireScope Bounded Host Discovery Results
            \\========================================
            \\Total Targets Scanned: {d}
            \\Reachable Hosts:       {d}
            \\Inconclusive (No Resp): {d}
            \\Failed / Unreachable:   {d}
            \\Cancelled Operations:  {d}
            \\Elapsed Time:          {d} ms
            \\
            \\Observed Targets:
            \\
        , .{
            self.total_scanned,
            self.reachable_count,
            self.inconclusive_count,
            self.failed_count,
            self.cancelled_count,
            self.elapsed_ms,
        });

        for (self.hosts, 0..) |host, idx| {
            const state_tag: []const u8 = switch (host.state) {
                .reachable => "[REACHABLE]",
                .inconclusive => "[INCONCLUSIVE]",
                .failed => "[FAILED]",
                .cancelled => "[CANCELLED]",
            };

            try writer.print("  {d:>3}. {s:<14} {s:<18}", .{ idx + 1, state_tag, host.target });
            if (host.evidence.response_port) |p| {
                try writer.print(" (port {d})", .{p});
            }
            if (host.evidence.rtt_ms) |rtt| {
                try writer.print(" RTT={d:.2}ms", .{rtt});
            }
            try writer.print("\n       Evidence: {s}\n       Note:     {s}\n", .{
                host.evidence.response_type,
                host.evidence.notes,
            });
        }

        try writer.print(
            \\
            \\[LEGAL DISCLAIMER]
            \\{s}
            \\
        , .{self.legal_disclaimer});
    }

    /// Formats machine-readable JSON output
    pub fn toJson(self: *const HostDiscoveryResult, writer: anytype) !void {
        try writer.print(
            \\{{"type":"host_discovery_result","summary":{{"total_scanned":{d},"reachable_count":{d},"inconclusive_count":{d},"failed_count":{d},"cancelled_count":{d},"elapsed_ms":{d}}},"legal_disclaimer":"{s}","hosts":[
        , .{
            self.total_scanned,
            self.reachable_count,
            self.inconclusive_count,
            self.failed_count,
            self.cancelled_count,
            self.elapsed_ms,
            self.legal_disclaimer,
        });

        for (self.hosts, 0..) |host, idx| {
            if (idx > 0) try writer.print(",", .{});
            try writer.print(
                \\{{"target":"{s}","state":"{s}","method":"{s}","response_type":"{s}","response_port":
            , .{
                host.target,
                host.state.asString(),
                host.method.asString(),
                host.evidence.response_type,
            });

            if (host.evidence.response_port) |p| {
                try writer.print("{d}", .{p});
            } else {
                try writer.print("null", .{});
            }

            try writer.print(",\"rtt_ms\":", .{});
            if (host.evidence.rtt_ms) |rtt| {
                try writer.print("{d:.2}", .{rtt});
            } else {
                try writer.print("null", .{});
            }

            try writer.print(",\"notes\":\"{s}\"}}", .{host.evidence.notes});
        }

        try writer.print("]}}\n", .{});
    }
};

/// Performs bounded, rate-limited host discovery strictly constrained to approved scope
pub fn discoverHosts(
    allocator: std.mem.Allocator,
    plan: *const AssessmentPlan,
    config: DiscoveryConfig,
    connector: TcpConnector,
    cancel: *const CancellationToken,
) !HostDiscoveryResult {
    // 1. Enforce safety caps: maximum host count
    if (plan.scope.targets.len > config.max_hosts) {
        return error.ExcessiveHostCount;
    }

    const start_time = std.time.milliTimestamp();

    var host_list = std.ArrayList(DiscoveredHost).init(allocator);
    errdefer {
        for (host_list.items) |*h| h.deinit(allocator);
        host_list.deinit();
    }

    var reachable_count: usize = 0;
    var inconclusive_count: usize = 0;
    var failed_count: usize = 0;
    var cancelled_count: usize = 0;

    const probe_ports = if (plan.scope.ports.len > 0)
        plan.scope.ports
    else
        config.discovery_ports;

    // 2. Iterate strictly through normalized targets in plan
    for (plan.scope.targets, 0..) |target, target_idx| {
        // Check for cancellation
        if (cancel.isCancelled()) {
            const tgt_dup = try allocator.dupe(u8, target);
            const resp_type = try allocator.dupe(u8, "cancelled");
            const notes = try allocator.dupe(u8, "Operation cancelled by user or deadline");
            try host_list.append(.{
                .target = tgt_dup,
                .state = .cancelled,
                .method = .tcp_probe,
                .evidence = .{
                    .response_port = null,
                    .response_type = resp_type,
                    .rtt_ms = null,
                    .notes = notes,
                },
            });
            cancelled_count += 1;
            break;
        }

        // IPv6 Roadblock Check: Support IPv4 first; IPv6 is deferred until scope strategy is designed
        if (std.mem.indexOfScalar(u8, target, ':') != null) {
            const tgt_dup = try allocator.dupe(u8, target);
            const resp_type = try allocator.dupe(u8, "ipv6_deferred");
            const notes = try allocator.dupe(u8, "IPv6 discovery is deferred until scope and test strategy are designed per project roadmap");
            try host_list.append(.{
                .target = tgt_dup,
                .state = .inconclusive,
                .method = .tcp_probe,
                .evidence = .{
                    .response_port = null,
                    .response_type = resp_type,
                    .rtt_ms = null,
                    .notes = notes,
                },
            });
            inconclusive_count += 1;
            continue;
        }

        // Apply rate limit delay between successive target probes (avoid burst flooding)
        if (target_idx > 0 and config.rate_limit_delay_ms > 0) {
            std.time.sleep(@as(u64, config.rate_limit_delay_ms) * std.time.ns_per_ms);
        }

        var determined_state: HostReachabilityState = .inconclusive;
        var final_port: ?u16 = null;
        var final_rtt_ms: ?f64 = null;
        var final_resp_type: []const u8 = "";
        var final_notes: []const u8 = "";

        // Probe discovery ports sequentially until an active response is observed
        for (probe_ports) |port| {
            if (cancel.isCancelled()) {
                determined_state = .cancelled;
                final_resp_type = "cancelled";
                final_notes = "Operation cancelled before completing port probe";
                break;
            }

            // Verify individual target:port compliance with plan scope
            if (!plan.scope.isTargetPermitted(target, port)) {
                continue;
            }

            const probe_res = connector.connect(allocator, target, port, config.timeout_ms, cancel) catch |err| {
                determined_state = .failed;
                final_port = port;
                final_resp_type = @errorName(err);
                final_notes = "Operational connection error occurred during reachability probe";
                break;
            };
            defer {
                var mut_res = probe_res;
                mut_res.deinit(allocator);
            }

            const rtt_calc = if (probe_res.elapsed_ns > 0)
                @as(f64, @floatFromInt(probe_res.elapsed_ns)) / 1_000_000.0
            else
                null;

            switch (probe_res.failure_category) {
                .success => {
                    // Host actively accepted TCP connection (SYN-ACK)
                    determined_state = .reachable;
                    final_port = port;
                    final_rtt_ms = rtt_calc;
                    final_resp_type = "tcp_syn_ack (open)";
                    final_notes = "Host active: TCP connection established successfully";
                    break; // Definitive proof of reachability obtained!
                },
                .refusal => {
                    // Host actively returned TCP RST (connection refused)
                    // This is conclusive proof of network reachability and active OS network stack!
                    determined_state = .reachable;
                    final_port = port;
                    final_rtt_ms = rtt_calc;
                    final_resp_type = "tcp_rst (connection refused)";
                    final_notes = "Host active: TCP RST received; network stack actively responding";
                    break; // Definitive proof of reachability obtained!
                },
                .cancelled => {
                    determined_state = .cancelled;
                    final_port = port;
                    final_resp_type = "cancelled";
                    final_notes = "Probe cancelled by user token";
                    break;
                },
                .permission_denied => {
                    determined_state = .failed;
                    final_port = port;
                    final_resp_type = "permission_denied";
                    final_notes = "Permission denied opening probe socket";
                    break;
                },
                .network_unreachable => {
                    determined_state = .failed;
                    final_port = port;
                    final_resp_type = "network_unreachable";
                    final_notes = "Local network route unreachable for target host";
                    break;
                },
                .timeout, .operational_failure, .malformed_input => {
                    // No response received or error on this port.
                    // If all ports timeout, reachability remains strictly INCONCLUSIVE
                    // because silent firewall drops or packet loss could explain absence of reply.
                    determined_state = .inconclusive;
                    final_port = port;
                    final_resp_type = "timeout (no response)";
                    final_notes = "Inconclusive: No response received; silent packet drop or firewall filtering may explain absence of reply";
                },
            }
        }

        switch (determined_state) {
            .reachable => reachable_count += 1,
            .inconclusive => inconclusive_count += 1,
            .failed => failed_count += 1,
            .cancelled => cancelled_count += 1,
        }

        const tgt_dup = try allocator.dupe(u8, target);
        const resp_dup = try allocator.dupe(u8, final_resp_type);
        const notes_dup = try allocator.dupe(u8, final_notes);

        try host_list.append(.{
            .target = tgt_dup,
            .state = determined_state,
            .method = .tcp_probe,
            .evidence = .{
                .response_port = final_port,
                .response_type = resp_dup,
                .rtt_ms = final_rtt_ms,
                .notes = notes_dup,
            },
        });
    }

    const elapsed = @as(u64, @intCast(@max(0, std.time.milliTimestamp() - start_time)));

    return HostDiscoveryResult{
        .hosts = try host_list.toOwnedSlice(),
        .total_scanned = plan.scope.targets.len,
        .reachable_count = reachable_count,
        .inconclusive_count = inconclusive_count,
        .failed_count = failed_count,
        .cancelled_count = cancelled_count,
        .elapsed_ms = elapsed,
        .legal_disclaimer = LEGAL_DISCLAIMER,
    };
}

// -------------------------------------------------------------------------
// UNIT TESTS FOR BOUNDED HOST DISCOVERY
// -------------------------------------------------------------------------

test "discovery: reachable host via open port (SYN-ACK)" {
    const targets = [_][]const u8{"127.0.0.1"};
    var plan = try AssessmentPlan.create(testing.allocator, .{
        .targets = &targets,
        .confirm_authorized = true,
    });
    defer plan.deinit(testing.allocator);

    const seq = [_]MockTcpConnector.MockSample{
        .{ .outcome = .success, .latency_ns = 5_000_000 },
    };
    var mock = MockTcpConnector{ .sequence = &seq };
    const cancel = CancellationToken.init();

    var res = try discoverHosts(
        testing.allocator,
        &plan,
        .{ .rate_limit_delay_ms = 0 },
        mock.connector(),
        &cancel,
    );
    defer res.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), res.total_scanned);
    try testing.expectEqual(@as(usize, 1), res.reachable_count);
    try testing.expectEqual(@as(usize, 0), res.inconclusive_count);
    try testing.expectEqual(HostReachabilityState.reachable, res.hosts[0].state);
    try testing.expectEqualStrings("tcp_syn_ack (open)", res.hosts[0].evidence.response_type);
}

test "discovery: reachable host via closed port (TCP RST refusal)" {
    const targets = [_][]const u8{"127.0.0.1"};
    var plan = try AssessmentPlan.create(testing.allocator, .{
        .targets = &targets,
        .confirm_authorized = true,
    });
    defer plan.deinit(testing.allocator);

    const seq = [_]MockTcpConnector.MockSample{
        .{ .outcome = .refusal, .latency_ns = 2_000_000 },
    };
    var mock = MockTcpConnector{ .sequence = &seq };
    const cancel = CancellationToken.init();

    var res = try discoverHosts(
        testing.allocator,
        &plan,
        .{ .rate_limit_delay_ms = 0 },
        mock.connector(),
        &cancel,
    );
    defer res.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), res.reachable_count);
    try testing.expectEqual(HostReachabilityState.reachable, res.hosts[0].state);
    try testing.expectEqualStrings("tcp_rst (connection refused)", res.hosts[0].evidence.response_type);
    try testing.expect(std.mem.indexOf(u8, res.hosts[0].evidence.notes, "network stack actively responding") != null);
}

test "discovery: lack of response remains strictly inconclusive" {
    const targets = [_][]const u8{"192.168.1.150"};
    var plan = try AssessmentPlan.create(testing.allocator, .{
        .targets = &targets,
        .confirm_authorized = true,
    });
    defer plan.deinit(testing.allocator);

    // Both discovery ports timeout (no response)
    const seq = [_]MockTcpConnector.MockSample{
        .{ .outcome = .timeout, .latency_ns = 2000_000_000 },
        .{ .outcome = .timeout, .latency_ns = 2000_000_000 },
    };
    var mock = MockTcpConnector{ .sequence = &seq };
    const cancel = CancellationToken.init();

    var res = try discoverHosts(
        testing.allocator,
        &plan,
        .{ .rate_limit_delay_ms = 0 },
        mock.connector(),
        &cancel,
    );
    defer res.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), res.inconclusive_count);
    try testing.expectEqual(@as(usize, 0), res.reachable_count);
    try testing.expectEqual(HostReachabilityState.inconclusive, res.hosts[0].state);
    try testing.expect(std.mem.indexOf(u8, res.hosts[0].evidence.notes, "silent packet drop or firewall filtering") != null);
}

test "discovery: cancellation halts discovery early" {
    const targets = [_][]const u8{ "127.0.0.1", "127.0.0.2" };
    var plan = try AssessmentPlan.create(testing.allocator, .{
        .targets = &targets,
        .confirm_authorized = true,
    });
    defer plan.deinit(testing.allocator);

    var cancel = CancellationToken.init();
    cancel.cancel(); // Pre-cancelled

    var mock = MockTcpConnector{};
    var res = try discoverHosts(
        testing.allocator,
        &plan,
        .{ .rate_limit_delay_ms = 0 },
        mock.connector(),
        &cancel,
    );
    defer res.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), res.cancelled_count);
    try testing.expectEqual(HostReachabilityState.cancelled, res.hosts[0].state);
}

test "discovery: serialization to terminal and JSON" {
    const targets = [_][]const u8{"127.0.0.1"};
    var plan = try AssessmentPlan.create(testing.allocator, .{
        .targets = &targets,
        .confirm_authorized = true,
    });
    defer plan.deinit(testing.allocator);

    const seq = [_]MockTcpConnector.MockSample{
        .{ .outcome = .success, .latency_ns = 3_500_000 },
    };
    var mock = MockTcpConnector{ .sequence = &seq };
    const cancel = CancellationToken.init();

    var res = try discoverHosts(
        testing.allocator,
        &plan,
        .{ .rate_limit_delay_ms = 0 },
        mock.connector(),
        &cancel,
    );
    defer res.deinit(testing.allocator);

    // Terminal
    var term_buf = std.ArrayList(u8).init(testing.allocator);
    defer term_buf.deinit();
    try res.toTerminal(term_buf.writer());
    try testing.expect(std.mem.indexOf(u8, term_buf.items, "WireScope Bounded Host Discovery Results") != null);
    try testing.expect(std.mem.indexOf(u8, term_buf.items, "[REACHABLE]") != null);

    // JSON
    var json_buf = std.ArrayList(u8).init(testing.allocator);
    defer json_buf.deinit();
    try res.toJson(json_buf.writer());
    try testing.expect(std.mem.indexOf(u8, json_buf.items, "\"type\":\"host_discovery_result\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_buf.items, "\"reachable_count\":1") != null);
}
