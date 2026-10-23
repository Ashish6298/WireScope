const std = @import("std");
const testing = std.testing;
const schema = @import("schema.zig");

pub const SeverityRank = enum(u8) {
    critical = 0,
    high = 1,
    medium = 2,
    low = 3,
    info = 4,

    pub fn fromString(str: []const u8) SeverityRank {
        if (std.mem.eql(u8, str, "critical")) return .critical;
        if (std.mem.eql(u8, str, "high")) return .high;
        if (std.mem.eql(u8, str, "medium")) return .medium;
        if (std.mem.eql(u8, str, "low")) return .low;
        return .info;
    }
};

pub const CheckItem = struct {
    sequence_id: usize,
    check_type: []const u8,
    target: []const u8,
    status: []const u8,
    duration_ms: u64,
};

pub const DnsObsItem = struct {
    target: []const u8,
    answers: [][]const u8,
    is_success: bool,
    duration_ms: u32,
};

pub const TcpObsItem = struct {
    target: []const u8,
    port: u16,
    is_open: bool,
    rtt_ms: ?u32 = null,
};

pub const TlsObsItem = struct {
    target: []const u8,
    port: u16,
    protocol_version: []const u8,
    hostname_matches: bool,
    is_valid_chain: bool,
    days_to_expiration: ?i32 = null,
};

pub const HttpObsItem = struct {
    target_url: []const u8,
    status_code: u16,
    is_https: bool,
    is_html: bool,
    is_json_api: bool,
    hsts_header: ?[]const u8 = null,
    csp_header: ?[]const u8 = null,
    x_content_type_options: ?[]const u8 = null,
};

pub const ListenerObsItem = struct {
    transport: []const u8,
    address: []const u8,
    port: u16,
    binding_type: []const u8,
    pid: ?u32 = null,
    process_name: ?[]const u8 = null,
    is_unlisted: bool = false,
    permission_limited: bool = false,
};

pub const AssetItem = struct {
    target: []const u8,
    ip_address: ?[]const u8 = null,
    open_ports: []const u16 = &.{},
    service_banner: ?[]const u8 = null,
};

pub const FindingItem = struct {
    rule_id: []const u8,
    rule_version: u32,
    title: []const u8,
    severity: []const u8,
    confidence: []const u8,
    evidence: []const u8,
    remediation: []const u8,
    target: []const u8,
};

pub const PolicyResultItem = struct {
    rule_id: []const u8,
    outcome: []const u8,
    target: []const u8,
    message: []const u8,
};

pub const LimitationItem = struct {
    category: []const u8,
    component: []const u8,
    description: []const u8,
};

pub const TaskFailureItem = struct {
    sequence_id: usize,
    check_type: []const u8,
    target: []const u8,
    error_message: []const u8,
    duration_ms: u64,
};

pub const AssessmentReportData = struct {
    assessment_id: []const u8,
    profile_id: []const u8,
    profile_name: []const u8,
    started_at_ms: i64,
    completed_at_ms: i64,
    duration_ms: u64,
    status: []const u8,
    manifest_hash: [64]u8,

    targets: [][]const u8,
    ports: []u16,
    exclusions: [][]const u8 = &.{},
    rate_limit_rps: u32,
    timeout_ms: u64,
    allow_out_of_scope_redirects: bool = false,

    tasks_planned: usize,
    tasks_executed: usize,
    tasks_succeeded: usize,
    tasks_failed: usize,
    is_complete: bool,
    interruption_reason: ?[]const u8 = null,

    checks: []CheckItem = &.{},
    dns_obs: []DnsObsItem = &.{},
    tcp_obs: []TcpObsItem = &.{},
    tls_obs: []TlsObsItem = &.{},
    http_obs: []HttpObsItem = &.{},
    listener_obs: []ListenerObsItem = &.{},
    assets: []AssetItem = &.{},
    findings: []FindingItem = &.{},
    policy_results: []PolicyResultItem = &.{},
    limitations: []LimitationItem = &.{},
    task_failures: []TaskFailureItem = &.{},
};

// -----------------------------------------------------------------------------
// Consistent Sorting Algorithms
// -----------------------------------------------------------------------------

pub fn sortTargets(targets: [][]const u8) void {
    std.mem.sort([]const u8, targets, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lessThan);
}

pub fn sortPorts(ports: []u16) void {
    std.mem.sort(u16, ports, {}, struct {
        fn lessThan(_: void, a: u16, b: u16) bool {
            return a < b;
        }
    }.lessThan);
}

pub fn sortFindings(findings: []FindingItem) void {
    std.mem.sort(FindingItem, findings, {}, struct {
        fn lessThan(_: void, a: FindingItem, b: FindingItem) bool {
            const rank_a = @intFromEnum(SeverityRank.fromString(a.severity));
            const rank_b = @intFromEnum(SeverityRank.fromString(b.severity));
            if (rank_a != rank_b) return rank_a < rank_b;

            const rule_order = std.mem.order(u8, a.rule_id, b.rule_id);
            if (rule_order != .eq) return rule_order == .lt;

            return std.mem.order(u8, a.target, b.target) == .lt;
        }
    }.lessThan);
}

pub fn sortChecks(checks: []CheckItem) void {
    std.mem.sort(CheckItem, checks, {}, struct {
        fn lessThan(_: void, a: CheckItem, b: CheckItem) bool {
            return a.sequence_id < b.sequence_id;
        }
    }.lessThan);
}

pub fn sortPolicyResults(results: []PolicyResultItem) void {
    std.mem.sort(PolicyResultItem, results, {}, struct {
        fn lessThan(_: void, a: PolicyResultItem, b: PolicyResultItem) bool {
            const rule_order = std.mem.order(u8, a.rule_id, b.rule_id);
            if (rule_order != .eq) return rule_order == .lt;
            return std.mem.order(u8, a.target, b.target) == .lt;
        }
    }.lessThan);
}

pub fn sortDnsObservations(items: []DnsObsItem) void {
    std.mem.sort(DnsObsItem, items, {}, struct {
        fn lessThan(_: void, a: DnsObsItem, b: DnsObsItem) bool {
            return std.mem.order(u8, a.target, b.target) == .lt;
        }
    }.lessThan);
}

pub fn sortTcpObservations(items: []TcpObsItem) void {
    std.mem.sort(TcpObsItem, items, {}, struct {
        fn lessThan(_: void, a: TcpObsItem, b: TcpObsItem) bool {
            const tgt_order = std.mem.order(u8, a.target, b.target);
            if (tgt_order != .eq) return tgt_order == .lt;
            return a.port < b.port;
        }
    }.lessThan);
}

pub fn sortTlsObservations(items: []TlsObsItem) void {
    std.mem.sort(TlsObsItem, items, {}, struct {
        fn lessThan(_: void, a: TlsObsItem, b: TlsObsItem) bool {
            const tgt_order = std.mem.order(u8, a.target, b.target);
            if (tgt_order != .eq) return tgt_order == .lt;
            return a.port < b.port;
        }
    }.lessThan);
}

pub fn sortHttpObservations(items: []HttpObsItem) void {
    std.mem.sort(HttpObsItem, items, {}, struct {
        fn lessThan(_: void, a: HttpObsItem, b: HttpObsItem) bool {
            return std.mem.order(u8, a.target_url, b.target_url) == .lt;
        }
    }.lessThan);
}

pub fn sortListenerObservations(items: []ListenerObsItem) void {
    std.mem.sort(ListenerObsItem, items, {}, struct {
        fn lessThan(_: void, a: ListenerObsItem, b: ListenerObsItem) bool {
            const addr_order = std.mem.order(u8, a.address, b.address);
            if (addr_order != .eq) return addr_order == .lt;
            if (a.port != b.port) return a.port < b.port;
            return std.mem.order(u8, a.transport, b.transport) == .lt;
        }
    }.lessThan);
}

pub fn sortLimitations(items: []LimitationItem) void {
    std.mem.sort(LimitationItem, items, {}, struct {
        fn lessThan(_: void, a: LimitationItem, b: LimitationItem) bool {
            const cat_order = std.mem.order(u8, a.category, b.category);
            if (cat_order != .eq) return cat_order == .lt;
            return std.mem.order(u8, a.component, b.component) == .lt;
        }
    }.lessThan);
}

// -----------------------------------------------------------------------------
// Report JSON Serialization
// -----------------------------------------------------------------------------

fn writeOptString(writer: anytype, opt: ?[]const u8) !void {
    if (opt) |s| {
        try writer.print("\"{s}\"", .{s});
    } else {
        try writer.writeAll("null");
    }
}

fn writeOptInt(writer: anytype, comptime T: type, opt: ?T) !void {
    if (opt) |v| {
        try writer.print("{d}", .{v});
    } else {
        try writer.writeAll("null");
    }
}

pub fn serializeReport(allocator: std.mem.Allocator, data: *const AssessmentReportData) ![]const u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const writer = buf.writer();

    try writer.print(
        \\{{
        \\  "schema_version": {d},
        \\  "report_type": "{s}",
        \\  "tool": {{
        \\    "name": "{s}",
        \\    "version": "{s}"
        \\  }},
        \\  "metadata": {{
        \\    "assessment_id": "{s}",
        \\    "profile_id": "{s}",
        \\    "profile_name": "{s}",
        \\    "started_at_ms": {d},
        \\    "completed_at_ms": {d},
        \\    "duration_ms": {d},
        \\    "status": "{s}",
        \\    "manifest_hash": "{s}"
        \\  }},
        \\  "scope": {{
        \\    "targets": [
    , .{
        schema.REPORT_SCHEMA_VERSION,
        schema.REPORT_DOCUMENT_TYPE,
        schema.TOOL_NAME,
        schema.TOOL_VERSION,
        data.assessment_id,
        data.profile_id,
        data.profile_name,
        data.started_at_ms,
        data.completed_at_ms,
        data.duration_ms,
        data.status,
        &data.manifest_hash,
    });

    for (data.targets, 0..) |t, i| {
        try writer.print("\"{s}\"{s}", .{ t, if (i + 1 < data.targets.len) ", " else "" });
    }

    try writer.print(
        \\],
        \\    "ports": [
    , .{});

    for (data.ports, 0..) |p, i| {
        try writer.print("{d}{s}", .{ p, if (i + 1 < data.ports.len) ", " else "" });
    }

    try writer.print(
        \\],
        \\    "exclusions": [
    , .{});

    for (data.exclusions, 0..) |e, i| {
        try writer.print("\"{s}\"{s}", .{ e, if (i + 1 < data.exclusions.len) ", " else "" });
    }

    try writer.print(
        \\],
        \\    "rate_limit_rps": {d},
        \\    "timeout_ms": {d},
        \\    "allow_out_of_scope_redirects": {s}
        \\  }},
        \\  "completion_state": {{
        \\    "tasks_planned": {d},
        \\    "tasks_executed": {d},
        \\    "tasks_succeeded": {d},
        \\    "tasks_failed": {d},
        \\    "is_complete": {s},
        \\    "interruption_reason": 
    , .{
        data.rate_limit_rps,
        data.timeout_ms,
        if (data.allow_out_of_scope_redirects) "true" else "false",
        data.tasks_planned,
        data.tasks_executed,
        data.tasks_succeeded,
        data.tasks_failed,
        if (data.is_complete) "true" else "false",
    });
    try writeOptString(writer, data.interruption_reason);

    try writer.writeAll(
        \\
        \\  },
        \\  "checks": [
    );

    for (data.checks, 0..) |c, i| {
        try writer.print(
            \\
            \\    {{
            \\      "sequence_id": {d},
            \\      "check_type": "{s}",
            \\      "target": "{s}",
            \\      "status": "{s}",
            \\      "duration_ms": {d}
            \\    }}{s}
        , .{
            c.sequence_id,
            c.check_type,
            c.target,
            c.status,
            c.duration_ms,
            if (i + 1 < data.checks.len) "," else "",
        });
    }

    try writer.print(
        \\
        \\  ],
        \\  "observations": {{
        \\    "dns": [
    , .{});

    for (data.dns_obs, 0..) |d, i| {
        try writer.print(
            \\
            \\      {{
            \\        "target": "{s}",
            \\        "answers": [
        , .{d.target});
        for (d.answers, 0..) |ans, a_idx| {
            try writer.print("\"{s}\"{s}", .{ ans, if (a_idx + 1 < d.answers.len) ", " else "" });
        }
        try writer.print(
            \\],
            \\        "is_success": {s},
            \\        "duration_ms": {d}
            \\      }}{s}
        , .{
            if (d.is_success) "true" else "false",
            d.duration_ms,
            if (i + 1 < data.dns_obs.len) "," else "",
        });
    }

    try writer.print(
        \\
        \\    ],
        \\    "tcp": [
    , .{});

    for (data.tcp_obs, 0..) |t, i| {
        try writer.print(
            \\
            \\      {{
            \\        "target": "{s}",
            \\        "port": {d},
            \\        "is_open": {s},
            \\        "rtt_ms": 
        , .{
            t.target,
            t.port,
            if (t.is_open) "true" else "false",
        });
        try writeOptInt(writer, u32, t.rtt_ms);
        try writer.print(
            \\
            \\      }}{s}
        , .{
            if (i + 1 < data.tcp_obs.len) "," else "",
        });
    }

    try writer.print(
        \\
        \\    ],
        \\    "tls": [
    , .{});

    for (data.tls_obs, 0..) |tl, i| {
        try writer.print(
            \\
            \\      {{
            \\        "target": "{s}",
            \\        "port": {d},
            \\        "protocol_version": "{s}",
            \\        "hostname_matches": {s},
            \\        "is_valid_chain": {s},
            \\        "days_to_expiration": 
        , .{
            tl.target,
            tl.port,
            tl.protocol_version,
            if (tl.hostname_matches) "true" else "false",
            if (tl.is_valid_chain) "true" else "false",
        });
        try writeOptInt(writer, i32, tl.days_to_expiration);
        try writer.print(
            \\
            \\      }}{s}
        , .{
            if (i + 1 < data.tls_obs.len) "," else "",
        });
    }

    try writer.print(
        \\
        \\    ],
        \\    "http": [
    , .{});

    for (data.http_obs, 0..) |h, i| {
        try writer.print(
            \\
            \\      {{
            \\        "target_url": "{s}",
            \\        "status_code": {d},
            \\        "is_https": {s},
            \\        "is_html": {s},
            \\        "is_json_api": {s},
            \\        "hsts_header": 
        , .{
            h.target_url,
            h.status_code,
            if (h.is_https) "true" else "false",
            if (h.is_html) "true" else "false",
            if (h.is_json_api) "true" else "false",
        });
        try writeOptString(writer, h.hsts_header);
        try writer.writeAll(",\n        \"csp_header\": ");
        try writeOptString(writer, h.csp_header);
        try writer.writeAll(",\n        \"x_content_type_options\": ");
        try writeOptString(writer, h.x_content_type_options);
        try writer.print(
            \\
            \\      }}{s}
        , .{
            if (i + 1 < data.http_obs.len) "," else "",
        });
    }

    try writer.print(
        \\
        \\    ],
        \\    "listeners": [
    , .{});

    for (data.listener_obs, 0..) |l, i| {
        try writer.print(
            \\
            \\      {{
            \\        "transport": "{s}",
            \\        "address": "{s}",
            \\        "port": {d},
            \\        "binding_type": "{s}",
            \\        "pid": 
        , .{
            l.transport,
            l.address,
            l.port,
            l.binding_type,
        });
        try writeOptInt(writer, u32, l.pid);
        try writer.writeAll(",\n        \"process_name\": ");
        try writeOptString(writer, l.process_name);
        try writer.print(
            \\,
            \\        "is_unlisted": {s},
            \\        "permission_limited": {s}
            \\      }}{s}
        , .{
            if (l.is_unlisted) "true" else "false",
            if (l.permission_limited) "true" else "false",
            if (i + 1 < data.listener_obs.len) "," else "",
        });
    }

    try writer.print(
        \\
        \\    ]
        \\  }},
        \\  "assets": [
    , .{});

    for (data.assets, 0..) |a, i| {
        try writer.print(
            \\
            \\    {{
            \\      "target": "{s}",
            \\      "ip_address": 
        , .{a.target});
        try writeOptString(writer, a.ip_address);
        try writer.writeAll(",\n      \"open_ports\": [");
        for (a.open_ports, 0..) |op, op_idx| {
            try writer.print("{d}{s}", .{ op, if (op_idx + 1 < a.open_ports.len) ", " else "" });
        }
        try writer.writeAll("],\n      \"service_banner\": ");
        try writeOptString(writer, a.service_banner);
        try writer.print(
            \\
            \\    }}{s}
        , .{
            if (i + 1 < data.assets.len) "," else "",
        });
    }

    try writer.print(
        \\
        \\  ],
        \\  "findings": [
    , .{});

    for (data.findings, 0..) |f, i| {
        try writer.print(
            \\
            \\    {{
            \\      "rule_id": "{s}",
            \\      "rule_version": {d},
            \\      "title": "{s}",
            \\      "severity": "{s}",
            \\      "confidence": "{s}",
            \\      "evidence": "{s}",
            \\      "remediation": "{s}",
            \\      "target": "{s}"
            \\    }}{s}
        , .{
            f.rule_id,
            f.rule_version,
            f.title,
            f.severity,
            f.confidence,
            f.evidence,
            f.remediation,
            f.target,
            if (i + 1 < data.findings.len) "," else "",
        });
    }

    try writer.print(
        \\
        \\  ],
        \\  "policy_results": [
    , .{});

    for (data.policy_results, 0..) |pr, i| {
        try writer.print(
            \\
            \\    {{
            \\      "rule_id": "{s}",
            \\      "outcome": "{s}",
            \\      "target": "{s}",
            \\      "message": "{s}"
            \\    }}{s}
        , .{
            pr.rule_id,
            pr.outcome,
            pr.target,
            pr.message,
            if (i + 1 < data.policy_results.len) "," else "",
        });
    }

    try writer.print(
        \\
        \\  ],
        \\  "limitations": [
    , .{});

    for (data.limitations, 0..) |lim, i| {
        try writer.print(
            \\
            \\    {{
            \\      "category": "{s}",
            \\      "component": "{s}",
            \\      "description": "{s}"
            \\    }}{s}
        , .{
            lim.category,
            lim.component,
            lim.description,
            if (i + 1 < data.limitations.len) "," else "",
        });
    }

    try writer.print(
        \\
        \\  ],
        \\  "task_failures": [
    , .{});

    for (data.task_failures, 0..) |tf, i| {
        try writer.print(
            \\
            \\    {{
            \\      "sequence_id": {d},
            \\      "check_type": "{s}",
            \\      "target": "{s}",
            \\      "error_message": "{s}",
            \\      "duration_ms": {d}
            \\    }}{s}
        , .{
            tf.sequence_id,
            tf.check_type,
            tf.target,
            tf.error_message,
            tf.duration_ms,
            if (i + 1 < data.task_failures.len) "," else "",
        });
    }

    try writer.print("\n  ]\n}}\n", .{});
    return buf.toOwnedSlice();
}

// -----------------------------------------------------------------------------
// Volatile Normalization for Golden Tests
// -----------------------------------------------------------------------------

/// Normalizes volatile fields in raw JSON report string (timestamps, manifest hash, durations)
/// to produce bit-for-bit deterministic output for golden testing.
pub fn normalizeJsonReport(allocator: std.mem.Allocator, raw_json: []const u8) ![]const u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw_json, .{});
    defer parsed.deinit();

    if (parsed.value != .object) return error.InvalidJson;
    var root = parsed.value.object;

    // 1. Normalize metadata
    if (root.getPtr("metadata")) |meta_val| {
        if (meta_val.* == .object) {
            var meta_obj = &meta_val.object;
            try meta_obj.put("started_at_ms", .{ .integer = 1710000000000 });
            try meta_obj.put("completed_at_ms", .{ .integer = 1710000005000 });
            try meta_obj.put("duration_ms", .{ .integer = 5000 });
            try meta_obj.put("manifest_hash", .{ .string = "0000000000000000000000000000000000000000000000000000000000000000" });
        }
    }

    // 2. Normalize checks duration
    if (root.getPtr("checks")) |checks_val| {
        if (checks_val.* == .array) {
            for (checks_val.array.items) |*chk| {
                if (chk.* == .object) {
                    try chk.object.put("duration_ms", .{ .integer = 10 });
                }
            }
        }
    }

    // 3. Normalize observations
    if (root.getPtr("observations")) |obs_val| {
        if (obs_val.* == .object) {
            var obs_obj = &obs_val.object;
            // DNS duration
            if (obs_obj.getPtr("dns")) |dns_val| {
                if (dns_val.* == .array) {
                    for (dns_val.array.items) |*d| {
                        if (d.* == .object) {
                            try d.object.put("duration_ms", .{ .integer = 10 });
                        }
                    }
                }
            }
            // TCP RTT
            if (obs_obj.getPtr("tcp")) |tcp_val| {
                if (tcp_val.* == .array) {
                    for (tcp_val.array.items) |*t| {
                        if (t.* == .object and t.object.get("rtt_ms") != null and t.object.get("rtt_ms").? != .null) {
                            try t.object.put("rtt_ms", .{ .integer = 10 });
                        }
                    }
                }
            }
            // Listener PID
            if (obs_obj.getPtr("listeners")) |lis_val| {
                if (lis_val.* == .array) {
                    for (lis_val.array.items) |*l| {
                        if (l.* == .object and l.object.get("pid") != null and l.object.get("pid").? != .null) {
                            try l.object.put("pid", .{ .integer = 1234 });
                        }
                    }
                }
            }
        }
    }

    // 4. Normalize task failures duration
    if (root.getPtr("task_failures")) |tf_val| {
        if (tf_val.* == .array) {
            for (tf_val.array.items) |*tf| {
                if (tf.* == .object) {
                    try tf.object.put("duration_ms", .{ .integer = 10 });
                }
            }
        }
    }

    // Stringify back deterministically
    var out_buf = std.ArrayList(u8).init(allocator);
    errdefer out_buf.deinit();

    try std.json.stringify(parsed.value, .{ .whitespace = .indent_2 }, out_buf.writer());
    return out_buf.toOwnedSlice();
}

// -----------------------------------------------------------------------------
// Unit & Golden Tests (Phase 12.1 Acceptance Criteria)
// -----------------------------------------------------------------------------

test "json report: generated report parses and validates against versioned schema" {
    const allocator = testing.allocator;

    var targets = [_][]const u8{ "127.0.0.1", "localhost" };
    sortTargets(&targets);

    var ports = [_]u16{ 443, 80 };
    sortPorts(&ports);

    var checks = [_]CheckItem{
        .{ .sequence_id = 1, .check_type = "dns", .target = "localhost", .status = "succeeded", .duration_ms = 4 },
        .{ .sequence_id = 2, .check_type = "tcp", .target = "127.0.0.1", .status = "succeeded", .duration_ms = 12 },
    };
    sortChecks(&checks);

    var findings = [_]FindingItem{
        .{
            .rule_id = "WS-AUDIT-HTTP-HSTS-MISSING",
            .rule_version = 1,
            .title = "Missing HTTP Strict Transport Security Header",
            .severity = "medium",
            .confidence = "confirmed",
            .evidence = "Header 'Strict-Transport-Security' was not returned",
            .remediation = "Enable HSTS with max-age >= 31536000",
            .target = "https://127.0.0.1:443/",
        },
    };
    sortFindings(&findings);

    var report_data = AssessmentReportData{
        .assessment_id = "asm-golden-1",
        .profile_id = "local-security-audit",
        .profile_name = "Local Security Audit",
        .started_at_ms = 1710000000000,
        .completed_at_ms = 1710000005000,
        .duration_ms = 5000,
        .status = "completed",
        .manifest_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".*,
        .targets = &targets,
        .ports = &ports,
        .rate_limit_rps = 10,
        .timeout_ms = 5000,
        .tasks_planned = 2,
        .tasks_executed = 2,
        .tasks_succeeded = 2,
        .tasks_failed = 0,
        .is_complete = true,
        .checks = &checks,
        .findings = &findings,
    };

    const json_str = try serializeReport(allocator, &report_data);
    defer allocator.free(json_str);

    // Acceptance criterion 1: Generated report parses and validates against schema
    try schema.validateReportJson(allocator, json_str);
}

test "json report: partial and cancelled assessments are represented correctly" {
    const allocator = testing.allocator;

    var targets = [_][]const u8{"127.0.0.1"};
    var ports = [_]u16{80};

    var task_failures = [_]TaskFailureItem{
        .{
            .sequence_id = 2,
            .check_type = "tcp",
            .target = "127.0.0.1:80",
            .error_message = "Connection refused",
            .duration_ms = 15,
        },
    };

    // 1. Partial assessment report
    var partial_data = AssessmentReportData{
        .assessment_id = "asm-partial-1",
        .profile_id = "local-security-audit",
        .profile_name = "Local Security Audit",
        .started_at_ms = 1710000000000,
        .completed_at_ms = 1710000003000,
        .duration_ms = 3000,
        .status = "partial",
        .manifest_hash = "1111111111111111111111111111111111111111111111111111111111111111".*,
        .targets = &targets,
        .ports = &ports,
        .rate_limit_rps = 10,
        .timeout_ms = 5000,
        .tasks_planned = 2,
        .tasks_executed = 2,
        .tasks_succeeded = 1,
        .tasks_failed = 1,
        .is_complete = false,
        .interruption_reason = null,
        .task_failures = &task_failures,
    };

    const partial_json = try serializeReport(allocator, &partial_data);
    defer allocator.free(partial_json);

    try schema.validateReportJson(allocator, partial_json);
    try testing.expect(std.mem.indexOf(u8, partial_json, "\"status\": \"partial\"") != null);
    try testing.expect(std.mem.indexOf(u8, partial_json, "\"is_complete\": false") != null);
    try testing.expect(std.mem.indexOf(u8, partial_json, "\"tasks_failed\": 1") != null);

    // 2. Cancelled assessment report
    var cancelled_data = AssessmentReportData{
        .assessment_id = "asm-cancelled-1",
        .profile_id = "local-security-audit",
        .profile_name = "Local Security Audit",
        .started_at_ms = 1710000000000,
        .completed_at_ms = 1710000001000,
        .duration_ms = 1000,
        .status = "cancelled",
        .manifest_hash = "2222222222222222222222222222222222222222222222222222222222222222".*,
        .targets = &targets,
        .ports = &ports,
        .rate_limit_rps = 10,
        .timeout_ms = 5000,
        .tasks_planned = 5,
        .tasks_executed = 2,
        .tasks_succeeded = 2,
        .tasks_failed = 0,
        .is_complete = false,
        .interruption_reason = "Assessment cancelled by operator SIGINT",
    };

    const cancelled_json = try serializeReport(allocator, &cancelled_data);
    defer allocator.free(cancelled_json);

    try schema.validateReportJson(allocator, cancelled_json);
    try testing.expect(std.mem.indexOf(u8, cancelled_json, "\"status\": \"cancelled\"") != null);
    try testing.expect(std.mem.indexOf(u8, cancelled_json, "\"interruption_reason\": \"Assessment cancelled by operator SIGINT\"") != null);
}

test "json report: golden test verifies deterministic normalized output" {
    const allocator = testing.allocator;

    var targets = [_][]const u8{ "127.0.0.1", "localhost" };
    sortTargets(&targets);

    var ports = [_]u16{ 80, 443 };
    sortPorts(&ports);

    var checks = [_]CheckItem{
        .{ .sequence_id = 1, .check_type = "dns", .target = "localhost", .status = "succeeded", .duration_ms = 4 },
    };

    var report_data = AssessmentReportData{
        .assessment_id = "asm-golden-fixture",
        .profile_id = "local-security-audit",
        .profile_name = "Local Security Audit",
        .started_at_ms = 1719999999999, // volatile timestamp
        .completed_at_ms = 1720000004567, // volatile timestamp
        .duration_ms = 4568, // volatile duration
        .status = "completed",
        .manifest_hash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".*, // volatile hash
        .targets = &targets,
        .ports = &ports,
        .rate_limit_rps = 10,
        .timeout_ms = 5000,
        .tasks_planned = 1,
        .tasks_executed = 1,
        .tasks_succeeded = 1,
        .tasks_failed = 0,
        .is_complete = true,
        .checks = &checks,
    };

    const raw_json = try serializeReport(allocator, &report_data);
    defer allocator.free(raw_json);

    // Run normalization
    const normalized = try normalizeJsonReport(allocator, raw_json);
    defer allocator.free(normalized);

    // Verify normalized values
    try testing.expect(std.mem.indexOf(u8, normalized, "\"started_at_ms\": 1710000000000") != null);
    try testing.expect(std.mem.indexOf(u8, normalized, "\"completed_at_ms\": 1710000005000") != null);
    try testing.expect(std.mem.indexOf(u8, normalized, "\"duration_ms\": 5000") != null);
    try testing.expect(std.mem.indexOf(u8, normalized, "\"manifest_hash\": \"0000000000000000000000000000000000000000000000000000000000000000\"") != null);
    try testing.expect(std.mem.indexOf(u8, normalized, "\"duration_ms\": 10") != null);
}

test "json report: secrets and response bodies are omitted by default" {
    const allocator = testing.allocator;

    var targets = [_][]const u8{"127.0.0.1"};
    var ports = [_]u16{443};

    var http_obs = [_]HttpObsItem{
        .{
            .target_url = "https://127.0.0.1:443/login",
            .status_code = 200,
            .is_https = true,
            .is_html = true,
            .is_json_api = false,
            .hsts_header = "max-age=31536000",
            .csp_header = "default-src 'self'",
            .x_content_type_options = "nosniff",
        },
    };

    var report_data = AssessmentReportData{
        .assessment_id = "asm-clean-1",
        .profile_id = "local-security-audit",
        .profile_name = "Local Security Audit",
        .started_at_ms = 1710000000000,
        .completed_at_ms = 1710000005000,
        .duration_ms = 5000,
        .status = "completed",
        .manifest_hash = "3333333333333333333333333333333333333333333333333333333333333333".*,
        .targets = &targets,
        .ports = &ports,
        .rate_limit_rps = 10,
        .timeout_ms = 5000,
        .tasks_planned = 1,
        .tasks_executed = 1,
        .tasks_succeeded = 1,
        .tasks_failed = 0,
        .is_complete = true,
        .http_obs = &http_obs,
    };

    const json_str = try serializeReport(allocator, &report_data);
    defer allocator.free(json_str);

    // Acceptance criterion 5: No secret or response body is emitted
    try testing.expect(std.mem.indexOf(u8, json_str, "response_body") == null);
    try testing.expect(std.mem.indexOf(u8, json_str, "body_content") == null);
    try testing.expect(std.mem.indexOf(u8, json_str, "password") == null);
    try testing.expect(std.mem.indexOf(u8, json_str, "client_secret") == null);

    try schema.validateReportJson(allocator, json_str);
}
