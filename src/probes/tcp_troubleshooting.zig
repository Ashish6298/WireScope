const std = @import("std");
const testing = std.testing;

const tcp = @import("tcp.zig");
const core = @import("../core/root.zig");

const TcpFailureCategory = tcp.TcpFailureCategory;
const TcpProbeResult = tcp.TcpProbeResult;
const TcpBatchProbeResult = tcp.TcpBatchProbeResult;

/// Diagnostic troubleshooting guidance separating observed facts from unverified hypotheses
pub const TcpTroubleshooting = struct {
    summary: []const u8,
    observed_facts: []const []const u8,
    hypotheses: []const []const u8,
    recommended_actions: []const []const u8,
    context_notes: ?[]const u8 = null,

    pub fn toJson(self: TcpTroubleshooting, writer: anytype) !void {
        try writer.print("{{\"summary\":\"{s}\",\"observed_facts\":[", .{self.summary});
        for (self.observed_facts, 0..) |fact, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.print("\"{s}\"", .{fact});
        }
        try writer.writeAll("],\"hypotheses\":[");
        for (self.hypotheses, 0..) |hyp, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.print("\"{s}\"", .{hyp});
        }
        try writer.writeAll("],\"recommended_actions\":[");
        for (self.recommended_actions, 0..) |act, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.print("\"{s}\"", .{act});
        }
        try writer.writeAll("],\"context_notes\":");
        if (self.context_notes) |n| {
            try writer.print("\"{s}\"", .{n});
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll("}");
    }

    pub fn toTerminal(self: TcpTroubleshooting, writer: anytype) !void {
        try writer.writeAll("Troubleshooting Guidance:\n");
        try writer.print("  Summary: {s}\n", .{self.summary});

        if (self.observed_facts.len > 0) {
            try writer.writeAll("  Observed Facts:\n");
            for (self.observed_facts) |fact| {
                try writer.print("    * {s}\n", .{fact});
            }
        }

        if (self.hypotheses.len > 0) {
            try writer.writeAll("  Possible Causes (Hypotheses):\n");
            for (self.hypotheses) |hyp| {
                try writer.print("    - {s}\n", .{hyp});
            }
        }

        if (self.recommended_actions.len > 0) {
            try writer.writeAll("  Recommended Actions:\n");
            for (self.recommended_actions) |act| {
                try writer.print("    > {s}\n", .{act});
            }
        }

        if (self.context_notes) |notes| {
            try writer.print("  Context: {s}\n", .{notes});
        }
        try writer.writeAll("\n");
    }
};

/// Generates diagnostic guidance for a single TCP probe outcome
pub fn generateSingleTroubleshooting(result: *const TcpProbeResult) TcpTroubleshooting {
    return switch (result.failure_category) {
        .success => .{
            .summary = "TCP 3-way handshake completed successfully.",
            .observed_facts = &.{
                "Remote host responded with SYN-ACK to initial SYN packet.",
                "Socket connection transitioned to ESTABLISHED state.",
            },
            .hypotheses = &.{},
            .recommended_actions = &.{
                "If diagnosing service availability, proceed with application-layer or TLS diagnostics.",
                "Run repeated measurements ('-c 5') to evaluate path stability and jitter.",
            },
            .context_notes = "Connect latency reflects network RTT and target OS TCP accept queue processing.",
        },
        .refusal => .{
            .summary = "Connection was actively refused by the destination host (TCP RST received).",
            .observed_facts = &.{
                "Remote host or intermediate proxy actively replied with a TCP RST (reset) packet.",
                "Network routing to the target IP is functional since RST packets returned.",
            },
            .hypotheses = &.{
                "No service or daemon is currently listening on the specified port.",
                "Target daemon is bound exclusively to loopback (127.0.0.1) or an internal interface.",
                "Host-based firewall (e.g. Windows Filtering Platform, iptables) actively rejected the packet.",
            },
            .recommended_actions = &.{
                "Verify the target service is running on the destination host.",
                "Inspect local listeners ('wirescope listeners') if testing the local machine.",
                "Check server configuration to ensure service is bound to 0.0.0.0 or the correct IP.",
                "Verify host firewall configuration permits incoming connections on this port.",
            },
            .context_notes = "RST indicates an active rejection, confirming the host is reachable and running.",
        },
        .timeout => .{
            .summary = "Connection attempt timed out without receiving a response.",
            .observed_facts = &.{
                "TCP SYN packet was transmitted but no SYN-ACK or RST was received before deadline.",
            },
            .hypotheses = &.{
                "A network firewall, cloud security group, or NAT gateway is silently dropping incoming SYN packets.",
                "Target host is offline, powered off, or experiencing total network failure.",
                "Asymmetric routing or return-path filtering is dropping SYN-ACK responses.",
                "Severe network congestion or link degradation caused packet loss on all retransmissions.",
            },
            .recommended_actions = &.{
                "Inspect local routes and default gateway ('wirescope routes').",
                "Verify network interface operational state ('wirescope interfaces').",
                "Check intermediate network firewalls and cloud security groups for drop/block rules.",
                "Test adjacent ports on the same host to distinguish host down vs port filtered.",
            },
            .context_notes = "Timeouts typically indicate packet dropping (filtering) rather than an unconfigured port.",
        },
        .network_unreachable => .{
            .summary = "Operating system reported network or host unreachable (ENETUNREACH / EHOSTUNREACH).",
            .observed_facts = &.{
                "Local network stack found no route to the specified target IP address.",
            },
            .hypotheses = &.{
                "Host network interface is disconnected or unassigned an IP address.",
                "Default gateway is missing, misconfigured, or unreachable on the local subnet.",
                "An upstream router returned ICMP Destination Unreachable (Network/Host Unreachable).",
            },
            .recommended_actions = &.{
                "Verify physical cable or Wi-Fi association on local interfaces ('wirescope interfaces').",
                "Inspect local routing table to ensure a valid default route exists ('wirescope routes').",
                "Ping or inspect local gateway connectivity.",
            },
            .context_notes = "Failure originated in the local or first-hop routing layer before reaching the target.",
        },
        .permission_denied => .{
            .summary = "Operating system denied permission to open or connect the socket.",
            .observed_facts = &.{
                "Socket subsystem returned EACCES or WSAEACCES.",
            },
            .hypotheses = &.{
                "Local endpoint protection, antivirus, or host firewall blocked the connection.",
                "Process privileges or sandbox isolation policies restrict outbound network activity.",
            },
            .recommended_actions = &.{
                "Check local security software logs and host outbound firewall rules.",
                "Verify user permissions and execution environment restrictions.",
            },
            .context_notes = "Permission failures are local host constraints, not remote network issues.",
        },
        .cancelled => .{
            .summary = "Probe operation was cancelled by the user or an overarching timeout deadline.",
            .observed_facts = &.{
                "Cancellation token was triggered prior to handshake completion.",
            },
            .hypotheses = &.{
                "User requested immediate termination.",
                "Assessment engine overall deadline elapsed before individual probe completed.",
            },
            .recommended_actions = &.{
                "Increase operation timeout if the target is on a high-latency network path.",
            },
            .context_notes = "Cancelled probes are marked as partial results to prevent ambiguous metrics.",
        },
        .malformed_input => .{
            .summary = "Target specification or port syntax is invalid.",
            .observed_facts = &.{
                "Input parsing rejected the target string prior to socket creation.",
            },
            .hypotheses = &.{
                "Port number is outside valid RFC 793 range [1, 65535].",
                "Hostname contains invalid characters or violates RFC 1035/1123 label standards.",
            },
            .recommended_actions = &.{
                "Ensure target syntax follows <host>:<port> or [<ipv6>]:<port>.",
                "Verify port number is an integer between 1 and 65535.",
            },
            .context_notes = "Rejected pre-network; zero network packets were transmitted.",
        },
        .operational_failure => .{
            .summary = "Local system or socket subsystem encountered an operational failure.",
            .observed_facts = &.{
                "Operating system returned an internal socket or system error.",
            },
            .hypotheses = &.{
                "Ephemeral port exhaustion or socket descriptor limit reached on the host.",
                "Network stack or Winsock/libc subsystem encountered an unexpected condition.",
            },
            .recommended_actions = &.{
                "Inspect system resource utilization and open handle counts.",
                "Verify network subsystem health and restart network adapter if problem persists.",
            },
            .context_notes = "Operational failures reflect host resource constraints rather than remote target state.",
        },
    };
}

/// Generates diagnostic troubleshooting for repeated batch measurements, identifying anomalies
pub fn generateBatchTroubleshooting(batch: *const TcpBatchProbeResult) TcpTroubleshooting {
    const total = batch.stats.total_samples;
    const success = batch.stats.successful_samples;
    const failed = batch.stats.failed_samples;

    // 1. All failed
    if (success == 0 and total > 0) {
        if (batch.failure_breakdown.refusals == total) {
            return .{
                .summary = "All connection attempts were actively refused (100% loss via TCP RST).",
                .observed_facts = &.{
                    "Destination host consistently responded with TCP RST across all sample attempts.",
                },
                .hypotheses = &.{
                    "Service is consistently not running on this port.",
                    "Port is closed and host firewall is configured to REJECT with reset.",
                },
                .recommended_actions = &.{
                    "Verify the target daemon is running and bound to the expected interface.",
                    "Inspect local listening services ('wirescope listeners') if targeting localhost.",
                },
                .context_notes = "Consistent RST responses confirm network reachability and host activity.",
            };
        } else if (batch.failure_breakdown.timeouts == total) {
            return .{
                .summary = "All connection attempts timed out without response (100% loss).",
                .observed_facts = &.{
                    "No response was received for any SYN packet across all sample attempts.",
                },
                .hypotheses = &.{
                    "A firewall or security gateway is silently dropping packets directed to this port.",
                    "Target host is completely offline or unreachable.",
                    "Local default gateway or upstream route is dropping packets.",
                },
                .recommended_actions = &.{
                    "Inspect local routes ('wirescope routes') and interface states ('wirescope interfaces').",
                    "Verify security groups and firewall ingress/egress rules for this port.",
                },
                .context_notes = "Consistent timeouts indicate packet dropping rather than a closed port.",
            };
        } else {
            return .{
                .summary = "All connection attempts failed with varied errors.",
                .observed_facts = &.{
                    "Zero connections succeeded out of all planned sample attempts.",
                },
                .hypotheses = &.{
                    "Network path instability or aggressive security filtering.",
                },
                .recommended_actions = &.{
                    "Review failure breakdown details for specific error categories.",
                },
                .context_notes = "Refer to the failure breakdown count for categorized causes.",
            };
        }
    }

    // 2. Partial loss (Intermittent failures / anomalous loss)
    if (failed > 0 and success > 0) {
        return .{
            .summary = "Intermittent connectivity observed (partial packet loss).",
            .observed_facts = &.{
                "Some TCP connection attempts succeeded while others failed.",
            },
            .hypotheses = &.{
                "Intermediate network packet loss or congestion causing dropped SYN/SYN-ACK packets.",
                "Target host or firewall rate-limiting rapid connection attempts (SYN flood defense).",
                "Target service listen backlog queue is full, causing intermittent connection drops.",
            },
            .recommended_actions = &.{
                "Increase inter-sample interval ('-i 1000' or higher) to rule out rate-limiting.",
                "Check target server CPU load and TCP listen backlog depth.",
                "Inspect local network interfaces for packet drop counters.",
            },
            .context_notes = "Partial loss in TCP connects indicates transport instability or rate-policing.",
        };
    }

    // 3. All successful, check for latency/jitter anomalies
    if (success == total and success >= 2) {
        const mean_ns = batch.stats.mean_ns orelse 0;
        const jitter_ns = batch.stats.jitter_rfc3550_ns orelse 0;
        const min_ns = batch.stats.min_ns orelse 0;
        const max_ns = batch.stats.max_ns orelse 0;

        // Check for high jitter anomaly (jitter > 50% of mean, or max > 4x min with min > 1ms)
        const is_high_jitter = (mean_ns > 0 and jitter_ns * 2 > mean_ns) or
            (min_ns > 1_000_000 and max_ns > min_ns * 4);

        if (is_high_jitter) {
            return .{
                .summary = "Connections succeeded, but significant latency variation (jitter) was detected.",
                .observed_facts = &.{
                    "100% of connection attempts succeeded with 0% loss.",
                    "Successive delay variation (RFC 3550 jitter) is high relative to mean connect latency.",
                },
                .hypotheses = &.{
                    "Bufferbloat or transient congestion on intermediate network hops.",
                    "Equal-Cost Multi-Path (ECMP) routing traversing asymmetric physical paths.",
                    "Wireless or cellular link quality fluctuations during sampling.",
                    "Target server experiencing periodic garbage collection or CPU scheduling delays.",
                },
                .recommended_actions = &.{
                    "Run a larger sample batch ('-c 20 -i 500') to establish baseline variance.",
                    "Inspect local default gateway latency to isolate local Wi-Fi/LAN vs WAN jitter.",
                },
                .context_notes = "TCP connect jitter measures variations in 3-way handshake round-trip times.",
            };
        }
    }

    // 4. Stable, nominal success
    return .{
        .summary = "TCP connectivity is stable with consistent round-trip timings.",
        .observed_facts = &.{
            "All planned connection samples completed with 0% packet loss.",
            "Round-trip connect times demonstrate nominal path stability.",
        },
        .hypotheses = &.{},
        .recommended_actions = &.{
            "If diagnosing higher-level protocols, proceed with TLS or HTTP application probes.",
        },
        .context_notes = "Measurements reflect healthy transport connectivity along the network path.",
    };
}

// ============================================================================
// Unit Tests
// ============================================================================

test "troubleshooting for single probe failure categories" {
    // 1. Success
    const ok_res = TcpProbeResult{
        .host = "127.0.0.1",
        .port = 80,
        .is_open = true,
        .failure_category = .success,
        .elapsed_ns = 1_000_000,
        .connect_time_ns = 1_000_000,
    };
    const ok_tb = generateSingleTroubleshooting(&ok_res);
    try testing.expect(std.mem.indexOf(u8, ok_tb.summary, "handshake completed successfully") != null);
    try testing.expectEqual(@as(usize, 0), ok_tb.hypotheses.len);

    // 2. Refusal
    const ref_res = TcpProbeResult{
        .host = "127.0.0.1",
        .port = 80,
        .is_open = false,
        .failure_category = .refusal,
        .elapsed_ns = 1_000_000,
        .connect_time_ns = 1_000_000,
    };
    const ref_tb = generateSingleTroubleshooting(&ref_res);
    try testing.expect(std.mem.indexOf(u8, ref_tb.summary, "actively refused") != null);
    try testing.expect(ref_tb.hypotheses.len >= 2);
    try testing.expect(ref_tb.recommended_actions.len >= 2);

    // 3. Timeout
    const to_res = TcpProbeResult{
        .host = "127.0.0.1",
        .port = 80,
        .is_open = false,
        .failure_category = .timeout,
        .elapsed_ns = 3_000_000_000,
        .connect_time_ns = 3_000_000_000,
    };
    const to_tb = generateSingleTroubleshooting(&to_res);
    try testing.expect(std.mem.indexOf(u8, to_tb.summary, "timed out") != null);
    try testing.expect(to_tb.hypotheses.len >= 3);

    // 4. Network Unreachable
    const unreach_res = TcpProbeResult{
        .host = "192.0.2.1",
        .port = 80,
        .is_open = false,
        .failure_category = .network_unreachable,
        .elapsed_ns = 100_000,
        .connect_time_ns = 0,
    };
    const unreach_tb = generateSingleTroubleshooting(&unreach_res);
    try testing.expect(std.mem.indexOf(u8, unreach_tb.summary, "network or host unreachable") != null);

    // 5. Permission Denied
    const perm_res = TcpProbeResult{
        .host = "127.0.0.1",
        .port = 80,
        .is_open = false,
        .failure_category = .permission_denied,
        .elapsed_ns = 100_000,
        .connect_time_ns = 0,
    };
    const perm_tb = generateSingleTroubleshooting(&perm_res);
    try testing.expect(std.mem.indexOf(u8, perm_tb.summary, "denied permission") != null);
}

test "batch troubleshooting for 100% loss and partial loss" {
    // 1. 100% Refusal
    var ref_samples = [_]tcp.TcpSampleRecord{
        .{ .sample_index = 1, .is_open = false, .failure_category = .refusal, .connect_time_ns = 0, .elapsed_ns = 1000 },
        .{ .sample_index = 2, .is_open = false, .failure_category = .refusal, .connect_time_ns = 0, .elapsed_ns = 1000 },
    };
    var ref_batch = TcpBatchProbeResult{
        .host = "127.0.0.1",
        .port = 80,
        .requested_count = 2,
        .interval_ms = 10,
        .samples = &ref_samples,
        .stats = .{ .total_samples = 2, .successful_samples = 0, .failed_samples = 2, .loss_percent = 100.0 },
        .failure_breakdown = .{ .refusals = 2 },
    };
    const ref_tb = generateBatchTroubleshooting(&ref_batch);
    try testing.expect(std.mem.indexOf(u8, ref_tb.summary, "actively refused") != null);

    // 2. Partial loss (50% loss)
    var partial_samples = [_]tcp.TcpSampleRecord{
        .{ .sample_index = 1, .is_open = true, .failure_category = .success, .connect_time_ns = 10_000_000, .elapsed_ns = 10_000_000 },
        .{ .sample_index = 2, .is_open = false, .failure_category = .timeout, .connect_time_ns = 0, .elapsed_ns = 2_000_000_000 },
    };
    var partial_batch = TcpBatchProbeResult{
        .host = "127.0.0.1",
        .port = 80,
        .requested_count = 2,
        .interval_ms = 10,
        .samples = &partial_samples,
        .stats = .{ .total_samples = 2, .successful_samples = 1, .failed_samples = 1, .loss_percent = 50.0 },
        .failure_breakdown = .{ .timeouts = 1 },
    };
    const partial_tb = generateBatchTroubleshooting(&partial_batch);
    try testing.expect(std.mem.indexOf(u8, partial_tb.summary, "Intermittent connectivity") != null);
    try testing.expect(partial_tb.hypotheses.len >= 2);
}

test "batch troubleshooting detects high jitter anomaly" {
    // 3. Jitter anomaly: mean = 10ms, jitter = 15ms (> 50% of mean)
    var jitter_samples = [_]tcp.TcpSampleRecord{
        .{ .sample_index = 1, .is_open = true, .failure_category = .success, .connect_time_ns = 5_000_000, .elapsed_ns = 5_000_000 },
        .{ .sample_index = 2, .is_open = true, .failure_category = .success, .connect_time_ns = 25_000_000, .elapsed_ns = 25_000_000 },
    };
    var jitter_batch = TcpBatchProbeResult{
        .host = "127.0.0.1",
        .port = 80,
        .requested_count = 2,
        .interval_ms = 10,
        .samples = &jitter_samples,
        .stats = .{
            .total_samples = 2,
            .successful_samples = 2,
            .failed_samples = 0,
            .loss_percent = 0.0,
            .min_ns = 5_000_000,
            .max_ns = 25_000_000,
            .mean_ns = 15_000_000,
            .median_ns = 15_000_000,
            .jitter_rfc3550_ns = 20_000_000,
        },
        .failure_breakdown = .{},
    };
    const jitter_tb = generateBatchTroubleshooting(&jitter_batch);
    try testing.expect(std.mem.indexOf(u8, jitter_tb.summary, "significant latency variation (jitter)") != null);
    try testing.expect(jitter_tb.hypotheses.len >= 3);
}

test "tcp troubleshooting terminal and json serialization" {
    const res = TcpProbeResult{
        .host = "127.0.0.1",
        .port = 80,
        .is_open = false,
        .failure_category = .refusal,
        .elapsed_ns = 1_000_000,
        .connect_time_ns = 1_000_000,
    };
    const tb = generateSingleTroubleshooting(&res);

    var term_buf: [2048]u8 = undefined;
    var term_fbs = std.io.fixedBufferStream(&term_buf);
    try tb.toTerminal(term_fbs.writer());
    const term_str = term_fbs.getWritten();
    try testing.expect(std.mem.indexOf(u8, term_str, "Troubleshooting Guidance:") != null);
    try testing.expect(std.mem.indexOf(u8, term_str, "Observed Facts:") != null);
    try testing.expect(std.mem.indexOf(u8, term_str, "Possible Causes (Hypotheses):") != null);

    var json_buf: [2048]u8 = undefined;
    var json_fbs = std.io.fixedBufferStream(&json_buf);
    try tb.toJson(json_fbs.writer());
    const json_str = json_fbs.getWritten();
    try testing.expect(std.mem.indexOf(u8, json_str, "\"summary\":\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"hypotheses\":[") != null);
}
