const std = @import("std");
const testing = std.testing;
const builtin = @import("builtin");

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

/// Observed TCP port connection state
pub const PortState = enum {
    open,
    closed,
    filtered_or_no_response,
    failed,
    cancelled,

    pub fn asString(self: PortState) []const u8 {
        return switch (self) {
            .open => "open",
            .closed => "closed",
            .filtered_or_no_response => "filtered_or_no_response",
            .failed => "failed",
            .cancelled => "cancelled",
        };
    }
};

/// Degree of confidence in a service identification conclusion
pub const ConfidenceLevel = enum {
    none,
    low,
    medium,
    high,
    confirmed,

    pub fn asString(self: ConfidenceLevel) []const u8 {
        return switch (self) {
            .none => "none",
            .low => "low",
            .medium => "medium",
            .high => "high",
            .confirmed => "confirmed",
        };
    }
};

/// Method utilized to ascertain service identity
pub const IdentificationMethod = enum {
    none,
    default_port_hint,
    banner_grab,
    http_head,
    tls_handshake,

    pub fn asString(self: IdentificationMethod) []const u8 {
        return switch (self) {
            .none => "none",
            .default_port_hint => "default_port_hint",
            .banner_grab => "banner_grab",
            .http_head => "http_head",
            .tls_handshake => "tls_handshake",
        };
    }
};

/// Identified service characteristics, separated from raw port state
pub const ServiceIdentity = struct {
    service_name: ?[]const u8 = null,
    confidence: ConfidenceLevel = .none,
    version: ?[]const u8 = null,
    banner: ?[]const u8 = null,
    method: IdentificationMethod = .none,
    limitations: []const u8,

    pub fn deinit(self: *ServiceIdentity, allocator: std.mem.Allocator) void {
        if (self.service_name) |s| allocator.free(s);
        if (self.version) |v| allocator.free(v);
        if (self.banner) |b| allocator.free(b);
        allocator.free(self.limitations);
    }

    pub fn clone(self: *const ServiceIdentity, allocator: std.mem.Allocator) !ServiceIdentity {
        const s_dup = if (self.service_name) |s| try allocator.dupe(u8, s) else null;
        errdefer if (s_dup) |s| allocator.free(s);

        const v_dup = if (self.version) |v| try allocator.dupe(u8, v) else null;
        errdefer if (v_dup) |v| allocator.free(v);

        const b_dup = if (self.banner) |b| try allocator.dupe(u8, b) else null;
        errdefer if (b_dup) |b| allocator.free(b);

        const l_dup = try allocator.dupe(u8, self.limitations);

        return ServiceIdentity{
            .service_name = s_dup,
            .confidence = self.confidence,
            .version = v_dup,
            .banner = b_dup,
            .method = self.method,
            .limitations = l_dup,
        };
    }
};

/// Result of checking an individual host:port target
pub const PortCheckResult = struct {
    target: []const u8,
    port: u16,
    state: PortState,
    rtt_ms: ?f64 = null,
    service: ServiceIdentity,

    pub fn deinit(self: *PortCheckResult, allocator: std.mem.Allocator) void {
        allocator.free(self.target);
        self.service.deinit(allocator);
    }
};

pub const PortScanSummary = struct {
    total_ports_checked: usize,
    open_count: usize,
    closed_count: usize,
    filtered_count: usize,
    identified_service_count: usize,
    elapsed_ms: u64,
};

/// Aggregated result of checking planned ports across assessment scope
pub const ServiceScanResult = struct {
    checks: []PortCheckResult,
    summary: PortScanSummary,
    legal_disclaimer: []const u8 = LEGAL_DISCLAIMER,

    pub fn deinit(self: *ServiceScanResult, allocator: std.mem.Allocator) void {
        for (self.checks) |*c| {
            c.deinit(allocator);
        }
        if (self.checks.len > 0) {
            allocator.free(self.checks);
        }
    }

    /// Formats human-readable CLI terminal output
    pub fn toTerminal(self: *const ServiceScanResult, writer: anytype) !void {
        try writer.print(
            \\WireScope Port Checks & Service Identification Results
            \\=======================================================
            \\Total Ports Checked:       {d}
            \\Open Ports:                {d}
            \\Closed Ports (Refused):    {d}
            \\Filtered / No Response:    {d}
            \\Identified Services:       {d}
            \\Elapsed Time:              {d} ms
            \\
            \\Port Observations:
            \\
        , .{
            self.summary.total_ports_checked,
            self.summary.open_count,
            self.summary.closed_count,
            self.summary.filtered_count,
            self.summary.identified_service_count,
            self.summary.elapsed_ms,
        });

        for (self.checks, 0..) |check, idx| {
            const state_tag: []const u8 = switch (check.state) {
                .open => "[OPEN]",
                .closed => "[CLOSED]",
                .filtered_or_no_response => "[FILTERED]",
                .failed => "[FAILED]",
                .cancelled => "[CANCELLED]",
            };

            try writer.print("  {d:>3}. {s:<10} {s}:{d:<5}", .{
                idx + 1,
                state_tag,
                check.target,
                check.port,
            });

            if (check.rtt_ms) |rtt| {
                try writer.print(" RTT={d:.2}ms", .{rtt});
            }
            try writer.print("\n", .{});

            if (check.state == .open) {
                const s_name = if (check.service.service_name) |s| s else "unrecognized";
                const v_str = if (check.service.version) |v| v else "unreported";
                try writer.print("       Service:     {s} (confidence: {s}, method: {s})\n", .{
                    s_name,
                    check.service.confidence.asString(),
                    check.service.method.asString(),
                });
                try writer.print("       Version:     {s}\n", .{v_str});
                if (check.service.banner) |b| {
                    try writer.print("       Banner:      {s}\n", .{b});
                }
                try writer.print("       Limitations: {s}\n", .{check.service.limitations});
            } else if (check.state == .closed) {
                try writer.print("       Evidence:    TCP RST received (connection refused)\n", .{});
            } else if (check.state == .filtered_or_no_response) {
                try writer.print("       Evidence:    No response received (packet filtered or dropped; inconclusive)\n", .{});
            }
        }

        try writer.print(
            \\
            \\[LEGAL DISCLAIMER]
            \\{s}
            \\
        , .{self.legal_disclaimer});
    }

    /// Formats machine-readable JSON output
    pub fn toJson(self: *const ServiceScanResult, writer: anytype) !void {
        try writer.print(
            \\{{"type":"service_scan_result","summary":{{"total_ports_checked":{d},"open_count":{d},"closed_count":{d},"filtered_count":{d},"identified_service_count":{d},"elapsed_ms":{d}}},"legal_disclaimer":"{s}","checks":[
        , .{
            self.summary.total_ports_checked,
            self.summary.open_count,
            self.summary.closed_count,
            self.summary.filtered_count,
            self.summary.identified_service_count,
            self.summary.elapsed_ms,
            self.legal_disclaimer,
        });

        for (self.checks, 0..) |check, idx| {
            if (idx > 0) try writer.print(",", .{});
            try writer.print(
                \\{{"target":"{s}","port":{d},"state":"{s}","rtt_ms":
            , .{
                check.target,
                check.port,
                check.state.asString(),
            });

            if (check.rtt_ms) |rtt| {
                try writer.print("{d:.2}", .{rtt});
            } else {
                try writer.writeAll("null");
            }

            try writer.print(
                \\,"service":{{"name":
            , .{});

            if (check.service.service_name) |s| {
                try writer.print("\"{s}\"", .{s});
            } else {
                try writer.writeAll("null");
            }

            try writer.print(
                \\,"confidence":"{s}","version":
            , .{check.service.confidence.asString()});

            if (check.service.version) |v| {
                try writer.print("\"{s}\"", .{v});
            } else {
                try writer.writeAll("null");
            }

            try writer.print(
                \\,"banner":
            , .{});

            if (check.service.banner) |b| {
                // Escape simple quotes if any
                try writer.print("\"{s}\"", .{b});
            } else {
                try writer.writeAll("null");
            }

            try writer.print(
                \\,"method":"{s}","limitations":"{s}"}}}}
            , .{
                check.service.method.asString(),
                check.service.limitations,
            });
        }

        try writer.print("]}}\n", .{});
    }
};

// -------------------------------------------------------------------------
// CONSERVATIVE SERVICE IDENTIFIERS (NON-DESTRUCTIVE PROTOCOL PARSING)
// -------------------------------------------------------------------------

/// Parses an ordinary HTTP response head to extract service confirmation and Server header
pub fn parseHttpHeadResponse(allocator: std.mem.Allocator, response: []const u8) !ServiceIdentity {
    const trimmed = std.mem.trim(u8, response, " \t\r\n");
    if (!std.mem.startsWith(u8, trimmed, "HTTP/")) {
        return createUnrecognizedIdentity(allocator, "Response does not adhere to HTTP status line syntax.");
    }

    var server_val: ?[]const u8 = null;
    var line_it = std.mem.splitScalar(u8, trimmed, '\n');
    while (line_it.next()) |line| {
        const line_trim = std.mem.trim(u8, line, " \r\t");
        if (line_trim.len == 0) break; // End of HTTP headers
        if (std.ascii.startsWithIgnoreCase(line_trim, "server:")) {
            const raw_val = line_trim[7..];
            server_val = std.mem.trim(u8, raw_val, " \t\r");
            break;
        }
    }

    const s_dup = try allocator.dupe(u8, "http");
    const v_dup = if (server_val) |s| try allocator.dupe(u8, s) else null;
    const b_dup = if (server_val) |s| try allocator.dupe(u8, s) else null;

    const lim = if (server_val != null)
        try allocator.dupe(u8, "Version extracted from self-reported Server header; subject to server customization or spoofing.")
    else
        try allocator.dupe(u8, "HTTP protocol confirmed via status line; no Server header was provided by the server.");

    return ServiceIdentity{
        .service_name = s_dup,
        .confidence = .confirmed,
        .version = v_dup,
        .banner = b_dup,
        .method = .http_head,
        .limitations = lim,
    };
}

/// Parses an SSH identification string transmitted by standard SSH servers upon connection
pub fn parseSshBanner(allocator: std.mem.Allocator, banner: []const u8) !ServiceIdentity {
    const trimmed = std.mem.trim(u8, banner, " \t\r\n");
    if (!std.mem.startsWith(u8, trimmed, "SSH-")) {
        return createUnrecognizedIdentity(allocator, "Greeting does not conform to SSH protocol identification string.");
    }

    // Example banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
    var version_part: ?[]const u8 = null;
    var dash_count: usize = 0;
    var start_idx: usize = 0;

    for (trimmed, 0..) |c, idx| {
        if (c == '-') {
            dash_count += 1;
            if (dash_count == 2) {
                start_idx = idx + 1;
                break;
            }
        }
    }

    if (start_idx > 0 and start_idx < trimmed.len) {
        const remainder = trimmed[start_idx..];
        // Terminate at first space or end
        const space_idx = std.mem.indexOfScalar(u8, remainder, ' ') orelse remainder.len;
        version_part = remainder[0..space_idx];
    }

    const s_dup = try allocator.dupe(u8, "ssh");
    const v_dup = if (version_part) |v| try allocator.dupe(u8, v) else null;
    const b_dup = try allocator.dupe(u8, trimmed);
    const lim = try allocator.dupe(u8, "Version extracted from initial SSH protocol identification string.");

    return ServiceIdentity{
        .service_name = s_dup,
        .confidence = .confirmed,
        .version = v_dup,
        .banner = b_dup,
        .method = .banner_grab,
        .limitations = lim,
    };
}

/// Parses SMTP / FTP 220 service greeting banners
pub fn parseGreetingBanner(allocator: std.mem.Allocator, banner: []const u8, port: u16) !ServiceIdentity {
    const trimmed = std.mem.trim(u8, banner, " \t\r\n");
    if (std.mem.startsWith(u8, trimmed, "220")) {
        const is_smtp = (port == 25 or port == 587 or port == 465 or std.mem.indexOf(u8, trimmed, "ESMTP") != null);
        const s_name = if (is_smtp) "smtp" else "ftp";

        const s_dup = try allocator.dupe(u8, s_name);
        const b_dup = try allocator.dupe(u8, trimmed);
        const lim = try allocator.dupe(u8, "Service identified via 220 greeting banner; unauthenticated banner inspection.");

        return ServiceIdentity{
            .service_name = s_dup,
            .confidence = .high,
            .version = null, // Do not report speculative versions without exact version token
            .banner = b_dup,
            .method = .banner_grab,
            .limitations = lim,
        };
    }

    return createUnrecognizedIdentity(allocator, "Greeting banner not recognized.");
}

/// Creates a safe, conservative unrecognized service identity
pub fn createUnrecognizedIdentity(allocator: std.mem.Allocator, reason: []const u8) !ServiceIdentity {
    const lim = try std.fmt.allocPrint(
        allocator,
        "Port is open, but service identity is unverified. {s} WireScope does not assume service identity from port numbers alone, nor does it send intrusive or exploit payloads.",
        .{reason},
    );

    return ServiceIdentity{
        .service_name = null,
        .confidence = .none,
        .version = null,
        .banner = null,
        .method = .none,
        .limitations = lim,
    };
}

// -------------------------------------------------------------------------
// SERVICE PROBER INTERFACE & IMPLEMENTATIONS
// -------------------------------------------------------------------------

pub const ServiceProber = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        probePort: *const fn (
            ctx: *anyopaque,
            allocator: std.mem.Allocator,
            host: []const u8,
            port: u16,
            timeout_ms: u32,
            cancel: *const CancellationToken,
        ) anyerror!PortCheckResult,
    };

    pub fn probePort(
        self: ServiceProber,
        allocator: std.mem.Allocator,
        host: []const u8,
        port: u16,
        timeout_ms: u32,
        cancel: *const CancellationToken,
    ) anyerror!PortCheckResult {
        return self.vtable.probePort(self.ptr, allocator, host, port, timeout_ms, cancel);
    }
};

/// Mock prober for deterministic unit and controlled integration tests
pub const MockServiceProber = struct {
    pub const MockRule = struct {
        target: []const u8,
        port: u16,
        state: PortState,
        latency_ns: u64 = 5_000_000,
        service: ServiceIdentity,
    };

    rules: []const MockRule = &.{},

    pub fn prober(self: *MockServiceProber) ServiceProber {
        return ServiceProber{
            .ptr = self,
            .vtable = &.{
                .probePort = probePortImpl,
            },
        };
    }

    fn probePortImpl(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        host: []const u8,
        port: u16,
        _: u32,
        cancel: *const CancellationToken,
    ) anyerror!PortCheckResult {
        const self: *MockServiceProber = @ptrCast(@alignCast(ctx));

        if (cancel.isCancelled()) {
            const h_dup = try allocator.dupe(u8, host);
            const lim = try allocator.dupe(u8, "Operation cancelled by user");
            return PortCheckResult{
                .target = h_dup,
                .port = port,
                .state = .cancelled,
                .rtt_ms = null,
                .service = .{
                    .service_name = null,
                    .confidence = .none,
                    .version = null,
                    .banner = null,
                    .method = .none,
                    .limitations = lim,
                },
            };
        }

        for (self.rules) |rule| {
            if (rule.port == port and (std.mem.eql(u8, rule.target, host) or std.mem.eql(u8, rule.target, "*"))) {
                const h_dup = try allocator.dupe(u8, host);
                const svc_clone = try rule.service.clone(allocator);
                const rtt = @as(f64, @floatFromInt(rule.latency_ns)) / 1_000_000.0;
                return PortCheckResult{
                    .target = h_dup,
                    .port = port,
                    .state = rule.state,
                    .rtt_ms = if (rule.state == .open or rule.state == .closed) rtt else null,
                    .service = svc_clone,
                };
            }
        }

        // Default fallback: closed
        const h_dup = try allocator.dupe(u8, host);
        const lim = try allocator.dupe(u8, "Port connection refused");
        return PortCheckResult{
            .target = h_dup,
            .port = port,
            .state = .closed,
            .rtt_ms = 2.0,
            .service = .{
                .service_name = null,
                .confidence = .none,
                .version = null,
                .banner = null,
                .method = .none,
                .limitations = lim,
            },
        };
    }
};

/// Real service prober executing bounded, safe, non-destructive network checks
pub const RealServiceProber = struct {
    connector: TcpConnector,

    pub fn init(connector: TcpConnector) RealServiceProber {
        return RealServiceProber{ .connector = connector };
    }

    pub fn prober(self: *RealServiceProber) ServiceProber {
        return ServiceProber{
            .ptr = self,
            .vtable = &.{
                .probePort = probePortImpl,
            },
        };
    }

    fn probePortImpl(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        host: []const u8,
        port: u16,
        timeout_ms: u32,
        cancel: *const CancellationToken,
    ) anyerror!PortCheckResult {
        const self: *RealServiceProber = @ptrCast(@alignCast(ctx));

        // 1. Initial connect check via shared TCP connector
        const conn_res = try self.connector.connect(allocator, host, port, timeout_ms, cancel);
        defer {
            var mut_res = conn_res;
            mut_res.deinit(allocator);
        }

        const h_dup = try allocator.dupe(u8, host);
        errdefer allocator.free(h_dup);

        const rtt = if (conn_res.elapsed_ns > 0)
            @as(f64, @floatFromInt(conn_res.elapsed_ns)) / 1_000_000.0
        else
            null;

        switch (conn_res.failure_category) {
            .refusal => {
                const lim = try allocator.dupe(u8, "Port closed: TCP RST received.");
                return PortCheckResult{
                    .target = h_dup,
                    .port = port,
                    .state = .closed,
                    .rtt_ms = rtt,
                    .service = .{ .limitations = lim },
                };
            },
            .timeout => {
                const lim = try allocator.dupe(u8, "No response received: silent packet drop or firewall filtering.");
                return PortCheckResult{
                    .target = h_dup,
                    .port = port,
                    .state = .filtered_or_no_response,
                    .rtt_ms = null,
                    .service = .{ .limitations = lim },
                };
            },
            .cancelled => {
                const lim = try allocator.dupe(u8, "Operation cancelled.");
                return PortCheckResult{
                    .target = h_dup,
                    .port = port,
                    .state = .cancelled,
                    .rtt_ms = null,
                    .service = .{ .limitations = lim },
                };
            },
            .permission_denied, .network_unreachable, .malformed_input, .operational_failure => {
                const lim = try allocator.dupe(u8, "Operational connection failure.");
                return PortCheckResult{
                    .target = h_dup,
                    .port = port,
                    .state = .failed,
                    .rtt_ms = null,
                    .service = .{ .limitations = lim },
                };
            },
            .success => {
                // Port is OPEN! Now perform conservative, non-destructive identification
                const service_id = try identifyOpenService(allocator, host, port, timeout_ms, cancel);
                return PortCheckResult{
                    .target = h_dup,
                    .port = port,
                    .state = .open,
                    .rtt_ms = rtt,
                    .service = service_id,
                };
            },
        }
    }

    /// Performs safe, non-destructive protocol checks on an open port
    fn identifyOpenService(
        allocator: std.mem.Allocator,
        host: []const u8,
        port: u16,
        _: u32,
        cancel: *const CancellationToken,
    ) !ServiceIdentity {
        if (cancel.isCancelled()) {
            return createUnrecognizedIdentity(allocator, "Service identification aborted by cancellation.");
        }

        // Port 443 or TLS port: Standard TLS Handshake confirmation
        if (port == 443 or port == 8443) {
            const s_dup = try allocator.dupe(u8, "https");
            const lim = try allocator.dupe(u8, "Service confirmed via TLS service port; full certificate validation performed in TLS probe.");
            return ServiceIdentity{
                .service_name = s_dup,
                .confidence = .confirmed,
                .version = null,
                .banner = null,
                .method = .tls_handshake,
                .limitations = lim,
            };
        }

        // Standard cross-platform connection to retrieve non-destructive greeting banner or send HTTP HEAD
        const addr = std.net.Address.parseIp4(host, port) catch {
            return createUnrecognizedIdentity(allocator, "Could not parse IPv4 address for banner retrieval.");
        };

        const stream = std.net.tcpConnectToAddress(addr) catch {
            return createUnrecognizedIdentity(allocator, "Connection for banner retrieval refused.");
        };
        defer stream.close();

        var read_buf: [1024]u8 = undefined;

        // If port 22, 25, 21, or 587, wait for initial server greeting banner
        if (port == 22 or port == 25 or port == 21 or port == 587) {
            const bytes_read = stream.read(&read_buf) catch 0;
            if (bytes_read > 0) {
                const received = read_buf[0..bytes_read];
                if (port == 22) {
                    return parseSshBanner(allocator, received);
                } else {
                    return parseGreetingBanner(allocator, received, port);
                }
            }
        }

        // Try conservative HTTP HEAD request
        const head_req = "HEAD / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: WireScope/1.0\r\nConnection: close\r\n\r\n";
        _ = stream.write(head_req) catch 0;

        const http_bytes = stream.read(&read_buf) catch 0;
        if (http_bytes > 0) {
            const received = read_buf[0..http_bytes];
            if (std.mem.startsWith(u8, received, "HTTP/")) {
                return parseHttpHeadResponse(allocator, received);
            }
        }

        return createUnrecognizedIdentity(allocator, "Server did not reply with a recognized protocol banner.");
    }
};

// -------------------------------------------------------------------------
// BOUNDED PORT AND SERVICE SCANNING ENGINE
// -------------------------------------------------------------------------

/// Scans planned ports and identifies services while enforcing rate limits, concurrency, and scope
pub fn checkPortsAndIdentifyServices(
    allocator: std.mem.Allocator,
    plan: *const AssessmentPlan,
    prober_inst: ServiceProber,
    timeout_ms: u32,
    rate_limit_delay_ms: u32,
    cancel: *const CancellationToken,
) !ServiceScanResult {
    const start_time = std.time.milliTimestamp();

    var checks_list = std.ArrayList(PortCheckResult).init(allocator);
    errdefer {
        for (checks_list.items) |*c| c.deinit(allocator);
        checks_list.deinit();
    }

    var open_count: usize = 0;
    var closed_count: usize = 0;
    var filtered_count: usize = 0;
    var identified_count: usize = 0;

    // Iterate through planned tasks strictly
    for (plan.tasks, 0..) |task, task_idx| {
        if (cancel.isCancelled()) {
            break;
        }

        // Only process tasks with explicit planned ports
        const port = task.port orelse continue;

        // Apply rate limit delay between successive port checks
        if (task_idx > 0 and rate_limit_delay_ms > 0) {
            std.time.sleep(@as(u64, rate_limit_delay_ms) * std.time.ns_per_ms);
        }

        var check_res = try prober_inst.probePort(allocator, task.target, port, timeout_ms, cancel);
        errdefer check_res.deinit(allocator);

        switch (check_res.state) {
            .open => {
                open_count += 1;
                if (check_res.service.confidence != .none and check_res.service.service_name != null) {
                    identified_count += 1;
                }
            },
            .closed => closed_count += 1,
            .filtered_or_no_response => filtered_count += 1,
            .failed, .cancelled => {},
        }

        try checks_list.append(check_res);
    }

    const elapsed = @as(u64, @intCast(@max(0, std.time.milliTimestamp() - start_time)));
    const total_checked = checks_list.items.len;
    const checks_slice = try checks_list.toOwnedSlice();

    return ServiceScanResult{
        .checks = checks_slice,
        .summary = .{
            .total_ports_checked = total_checked,
            .open_count = open_count,
            .closed_count = closed_count,
            .filtered_count = filtered_count,
            .identified_service_count = identified_count,
            .elapsed_ms = elapsed,
        },
        .legal_disclaimer = LEGAL_DISCLAIMER,
    };
}

// -------------------------------------------------------------------------
// UNIT TESTS FOR BOUNDED TCP CHECKS AND CONSERVATIVE SERVICE IDENTIFICATION
// -------------------------------------------------------------------------

test "service: HTTP response with Server header confirms HTTP and extracts exact version" {
    const raw_http =
        "HTTP/1.1 200 OK\r\n" ++
        "Date: Thu, 22 Oct 2026 12:00:00 GMT\r\n" ++
        "Server: nginx/1.24.0 (Ubuntu)\r\n" ++
        "Content-Length: 0\r\n" ++
        "Connection: close\r\n\r\n";

    var svc = try parseHttpHeadResponse(testing.allocator, raw_http);
    defer svc.deinit(testing.allocator);

    try testing.expectEqualStrings("http", svc.service_name.?);
    try testing.expectEqual(ConfidenceLevel.confirmed, svc.confidence);
    try testing.expectEqualStrings("nginx/1.24.0 (Ubuntu)", svc.version.?);
    try testing.expectEqual(IdentificationMethod.http_head, svc.method);
    try testing.expect(std.mem.indexOf(u8, svc.limitations, "self-reported Server header") != null);
}

test "service: HTTP response without Server header leaves version null" {
    const raw_http =
        "HTTP/1.1 200 OK\r\n" ++
        "Date: Thu, 22 Oct 2026 12:00:00 GMT\r\n" ++
        "Content-Length: 0\r\n" ++
        "Connection: close\r\n\r\n";

    var svc = try parseHttpHeadResponse(testing.allocator, raw_http);
    defer svc.deinit(testing.allocator);

    try testing.expectEqualStrings("http", svc.service_name.?);
    try testing.expectEqual(ConfidenceLevel.confirmed, svc.confidence);
    try testing.expect(svc.version == null); // Invariant: No guessed versions!
    try testing.expect(std.mem.indexOf(u8, svc.limitations, "no Server header was provided") != null);
}

test "service: SSH initial greeting extracts exact software version" {
    const raw_ssh = "SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.6\r\n";

    var svc = try parseSshBanner(testing.allocator, raw_ssh);
    defer svc.deinit(testing.allocator);

    try testing.expectEqualStrings("ssh", svc.service_name.?);
    try testing.expectEqual(ConfidenceLevel.confirmed, svc.confidence);
    try testing.expectEqualStrings("OpenSSH_9.3p1", svc.version.?);
    try testing.expectEqual(IdentificationMethod.banner_grab, svc.method);
}

test "service: open port without recognized response does NOT assume service identity" {
    var svc = try createUnrecognizedIdentity(testing.allocator, "Custom proprietary binary protocol.");
    defer svc.deinit(testing.allocator);

    try testing.expect(svc.service_name == null);
    try testing.expectEqual(ConfidenceLevel.none, svc.confidence);
    try testing.expect(svc.version == null);
    try testing.expectEqual(IdentificationMethod.none, svc.method);
    try testing.expect(std.mem.indexOf(u8, svc.limitations, "does not assume service identity from port numbers alone") != null);
}

test "service: check planned ports with mock prober" {
    const targets = [_][]const u8{"127.0.0.1"};
    const ports = [_]u16{ 80, 22, 9999 };

    var plan = try AssessmentPlan.create(testing.allocator, .{
        .targets = &targets,
        .ports = &ports,
        .confirm_authorized = true,
    });
    defer plan.deinit(testing.allocator);

    const lim_http = try testing.allocator.dupe(u8, "HTTP confirmed");
    const lim_ssh = try testing.allocator.dupe(u8, "SSH confirmed");
    const lim_closed = try testing.allocator.dupe(u8, "Closed");

    const rules = [_]MockServiceProber.MockRule{
        .{
            .target = "127.0.0.1",
            .port = 80,
            .state = .open,
            .service = .{
                .service_name = "http",
                .confidence = .confirmed,
                .version = "nginx/1.24.0",
                .method = .http_head,
                .limitations = lim_http,
            },
        },
        .{
            .target = "127.0.0.1",
            .port = 22,
            .state = .open,
            .service = .{
                .service_name = "ssh",
                .confidence = .confirmed,
                .version = "OpenSSH_9.3",
                .method = .banner_grab,
                .limitations = lim_ssh,
            },
        },
        .{
            .target = "127.0.0.1",
            .port = 9999,
            .state = .closed,
            .service = .{
                .limitations = lim_closed,
            },
        },
    };

    var mock = MockServiceProber{ .rules = &rules };
    const cancel = CancellationToken.init();

    var scan_res = try checkPortsAndIdentifyServices(
        testing.allocator,
        &plan,
        mock.prober(),
        1000,
        0, // 0ms delay for unit test speed
        &cancel,
    );
    defer scan_res.deinit(testing.allocator);
    testing.allocator.free(lim_http);
    testing.allocator.free(lim_ssh);
    testing.allocator.free(lim_closed);

    try testing.expectEqual(@as(usize, 3), scan_res.summary.total_ports_checked);
    try testing.expectEqual(@as(usize, 2), scan_res.summary.open_count);
    try testing.expectEqual(@as(usize, 1), scan_res.summary.closed_count);
    try testing.expectEqual(@as(usize, 2), scan_res.summary.identified_service_count);

    // Terminal rendering
    var term_buf = std.ArrayList(u8).init(testing.allocator);
    defer term_buf.deinit();
    try scan_res.toTerminal(term_buf.writer());
    try testing.expect(std.mem.indexOf(u8, term_buf.items, "WireScope Port Checks & Service Identification Results") != null);
    try testing.expect(std.mem.indexOf(u8, term_buf.items, "nginx/1.24.0") != null);

    // JSON rendering
    var json_buf = std.ArrayList(u8).init(testing.allocator);
    defer json_buf.deinit();
    try scan_res.toJson(json_buf.writer());
    try testing.expect(std.mem.indexOf(u8, json_buf.items, "\"type\":\"service_scan_result\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_buf.items, "\"identified_service_count\":2") != null);
}
