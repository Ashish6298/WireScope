const std = @import("std");
const testing = std.testing;
const json_mod = @import("json.zig");
const schema = @import("schema.zig");
const redact_mod = @import("redact.zig");

const AssessmentReportData = json_mod.AssessmentReportData;
const FindingItem = json_mod.FindingItem;
const CheckItem = json_mod.CheckItem;
const DnsObsItem = json_mod.DnsObsItem;
const TcpObsItem = json_mod.TcpObsItem;
const TlsObsItem = json_mod.TlsObsItem;
const HttpObsItem = json_mod.HttpObsItem;
const ListenerObsItem = json_mod.ListenerObsItem;
const AssetItem = json_mod.AssetItem;
const PolicyResultItem = json_mod.PolicyResultItem;
const LimitationItem = json_mod.LimitationItem;
const TaskFailureItem = json_mod.TaskFailureItem;

pub const TerminalOptions = struct {
    redacted: bool = false,
};

/// Renders a full structured assessment report formatted for human-readable terminal display
pub fn renderTerminal(
    _: std.mem.Allocator,
    data: *const AssessmentReportData,
    writer: anytype,
    options: TerminalOptions,
) !void {
    // 1. Terminal Header Banner
    try writer.print(
        \\================================================================================
        \\WIRESCOPE DEFENSIVE ASSESSMENT REPORT
        \\================================================================================
        \\Assessment ID:       {s}
        \\Profile:             {s} ({s})
        \\Execution Status:    [{s}]
        \\Execution Duration:  {d} ms (Started: {d}ms | Completed: {d}ms)
        \\Tasks Executed:      {d} Planned, {d} Executed ({d} Succeeded, {d} Failed)
        \\Integrity Manifest:  {s}
        \\Schema Version:      v{d}
        \\
    , .{
        data.assessment_id,
        data.profile_name,
        data.profile_id,
        data.status,
        data.duration_ms,
        data.started_at_ms,
        data.completed_at_ms,
        data.tasks_planned,
        data.tasks_executed,
        data.tasks_succeeded,
        data.tasks_failed,
        data.manifest_hash,
        schema.REPORT_SCHEMA_VERSION,
    });

    // 2. Status Details / Warning
    if (std.mem.eql(u8, data.status, "completed") or (data.is_complete and std.mem.eql(u8, data.status, "complete"))) {
        try writer.print("Execution State:     COMPLETE (All planned assessment tasks finished successfully)\n", .{});
    } else if (std.mem.eql(u8, data.status, "partial") or (!data.is_complete and !std.mem.eql(u8, data.status, "cancelled") and !std.mem.eql(u8, data.status, "failed"))) {
        try writer.print(
            \\Execution State:     PARTIAL / INCOMPLETE
            \\                     (Observations preserved. Incomplete evidence does NOT imply absence of risk)
            \\
        , .{});
        if (data.interruption_reason) |reason| {
            try writer.print("Interruption Reason: {s}\n", .{reason});
        }
    } else if (std.mem.eql(u8, data.status, "cancelled")) {
        try writer.print("Execution State:     CANCELLED (Terminated early by operator)\n", .{});
        if (data.interruption_reason) |reason| {
            try writer.print("Cancellation Reason: {s}\n", .{reason});
        }
    } else if (std.mem.eql(u8, data.status, "failed")) {
        try writer.print("Execution State:     FAILED (Encountered operational execution failures)\n", .{});
        if (data.interruption_reason) |reason| {
            try writer.print("Failure Reason:      {s}\n", .{reason});
        }
    }

    // 3. Redaction Warning (if applicable)
    if (options.redacted) {
        try writer.print(
            \\
            \\[!] WARNING: Redaction was applied to this report. Redacting sensitive data may
            \\    alter evidence strings or token values, which can reduce reproducibility.
            \\
        , .{});
    }

    // 4. Scope Summary
    try writer.print(
        \\--------------------------------------------------------------------------------
        \\[SCOPE & PARAMETERS]
        \\  Targets:           
    , .{});
    if (data.targets.len == 0) {
        try writer.writeAll("none\n");
    } else {
        for (data.targets, 0..) |tgt, i| {
            if (i > 0) try writer.writeAll(", ");
            try writer.writeAll(tgt);
        }
        try writer.writeAll("\n");
    }

    try writer.writeAll("  Ports:             ");
    if (data.ports.len == 0) {
        try writer.writeAll("none\n");
    } else {
        for (data.ports, 0..) |p, i| {
            if (i > 0) try writer.writeAll(", ");
            try writer.print("{d}", .{p});
        }
        try writer.writeAll("\n");
    }

    try writer.print(
        \\  Rate Limit:        {d} RPS
        \\  Probe Timeout:     {d} ms
        \\  Redirect Scope:    Allow Out-of-Scope = {s}
        \\
    , .{
        data.rate_limit_rps,
        data.timeout_ms,
        if (data.allow_out_of_scope_redirects) "true" else "false",
    });

    // 5. Section: Observations (Neutral Empirical Telemetry)
    try writer.print(
        \\--------------------------------------------------------------------------------
        \\[1. EMPIRICAL OBSERVATIONS (NEUTRAL DATA)]
        \\  (Observations record raw responsive endpoints and do not imply security findings)
        \\  DNS Records:       {d} observed
        \\  TCP Port States:   {d} observed
        \\  TLS Handshakes:    {d} observed
        \\  HTTP Responses:    {d} observed (response bodies omitted by default)
        \\  System Listeners:  {d} observed
        \\
    , .{
        data.dns_obs.len,
        data.tcp_obs.len,
        data.tls_obs.len,
        data.http_obs.len,
        data.listener_obs.len,
    });

    // DNS Details
    if (data.dns_obs.len > 0) {
        try writer.writeAll("  * DNS Observations:\n");
        for (data.dns_obs) |d| {
            try writer.print("    - {s} -> {s} | Answers: [", .{
                d.target,
                if (d.is_success) "resolved" else "failed",
            });
            for (d.answers, 0..) |ans, i| {
                if (i > 0) try writer.writeAll(", ");
                try writer.writeAll(ans);
            }
            try writer.print("] ({d}ms)\n", .{d.duration_ms});
        }
    }

    // TCP Details
    if (data.tcp_obs.len > 0) {
        try writer.writeAll("  * TCP Port Probes:\n");
        for (data.tcp_obs) |t| {
            try writer.print("    - {s}:{d} -> {s}", .{
                t.target,
                t.port,
                if (t.is_open) "open" else "closed_or_filtered",
            });
            if (t.rtt_ms) |rtt| {
                try writer.print(" ({d}ms)\n", .{rtt});
            } else {
                try writer.writeAll("\n");
            }
        }
    }

    // TLS Details
    if (data.tls_obs.len > 0) {
        try writer.writeAll("  * TLS Configurations:\n");
        for (data.tls_obs) |tl| {
            try writer.print("    - {s}:{d} -> {s} | SNI Match: {s} | Valid Chain: {s} | Exp: ", .{
                tl.target,
                tl.port,
                tl.protocol_version,
                if (tl.hostname_matches) "yes" else "no",
                if (tl.is_valid_chain) "yes" else "no",
            });
            if (tl.days_to_expiration) |days| {
                try writer.print("{d}d\n", .{days});
            } else {
                try writer.writeAll("N/A\n");
            }
        }
    }

    // HTTP Details
    if (data.http_obs.len > 0) {
        try writer.writeAll("  * HTTP Endpoint Probes:\n");
        for (data.http_obs) |h| {
            try writer.print("    - {s} -> HTTP {d} (HTTPS: {s}) | HSTS: {s} | CSP: {s} | XCTO: {s}\n", .{
                h.target_url,
                h.status_code,
                if (h.is_https) "yes" else "no",
                h.hsts_header orelse "missing",
                h.csp_header orelse "missing",
                h.x_content_type_options orelse "missing",
            });
        }
    }

    // Active Listeners
    if (data.listener_obs.len > 0) {
        try writer.writeAll("  * Local Listeners:\n");
        for (data.listener_obs) |l| {
            try writer.print("    - {s} {s}:{d} ({s}) | Proc: {s} (PID {s}) | Unlisted: {s}\n", .{
                l.transport,
                l.address,
                l.port,
                l.binding_type,
                l.process_name orelse "N/A",
                if (l.pid != null) "known" else "unknown",
                if (l.is_unlisted) "YES" else "no",
            });
        }
    }

    // 6. Section: Security Findings
    try writer.print(
        \\--------------------------------------------------------------------------------
        \\[2. DEFENSIVE SECURITY FINDINGS]
        \\
    , .{});

    if (data.findings.len == 0) {
        try writer.print(
            \\  No security findings detected within tested scope.
            \\  (Note: Absence of findings does not guarantee endpoint security.)
            \\
        , .{});
    } else {
        for (data.findings, 1..) |f, i| {
            try writer.print(
                \\  [{d}] [{s}] {s} ({s} v{d})
                \\      Target:             {s}
                \\      Confidence:         {s}
                \\      Severity Rationale: Evaluated against policy check {s}
                \\      Observed Evidence:  {s}
                \\      Remediation:        {s}
                \\
            , .{
                i,
                f.severity,
                f.title,
                f.rule_id,
                f.rule_version,
                f.target,
                f.confidence,
                f.rule_id,
                f.evidence,
                f.remediation,
            });
        }
    }

    // 7. Section: Policy Evaluation Outcomes
    if (data.policy_results.len > 0) {
        try writer.print(
            \\--------------------------------------------------------------------------------
            \\[3. POLICY EVALUATION OUTCOMES]
            \\
        , .{});
        for (data.policy_results) |p| {
            try writer.print("  * [{s}] {s} on {s}: {s}\n", .{
                p.outcome,
                p.rule_id,
                p.target,
                p.message,
            });
        }
    }

    // 8. Section: Task Failures & Incomplete Evidence
    if (data.task_failures.len > 0) {
        try writer.print(
            \\--------------------------------------------------------------------------------
            \\[4. TASK EXECUTION FAILURES (INCOMPLETE EVIDENCE)]
            \\  * Note: Incomplete evidence does not imply the absence of vulnerabilities.
            \\
        , .{});
        for (data.task_failures) |tf| {
            try writer.print("  - Task #{d} ({s} -> {s}): {s} ({d}ms)\n", .{
                tf.sequence_id,
                tf.check_type,
                tf.target,
                tf.error_message,
                tf.duration_ms,
            });
        }
    }

    // 9. Section: Limitations & Diagnostic Constraints
    if (data.limitations.len > 0) {
        try writer.print(
            \\--------------------------------------------------------------------------------
            \\[5. DIAGNOSTIC CONSTRAINTS & LIMITATIONS]
            \\
        , .{});
        for (data.limitations) |lim| {
            try writer.print("  - [{s}/{s}] {s}\n", .{
                lim.category,
                lim.component,
                lim.description,
            });
        }
    }

    // 10. Footer
    try writer.writeAll(
        \\================================================================================
        \\WireScope Defensive Guarantee:
        \\  Conducted within declared scope limits without destructive payloads.
        \\  Neutral evidence cited; response bodies omitted by default.
        \\================================================================================
        \\
    );
}

/// Renders Terminal report into an allocated string slice
pub fn renderTerminalToString(
    allocator: std.mem.Allocator,
    data: *const AssessmentReportData,
    options: TerminalOptions,
) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    try renderTerminal(allocator, data, buf.writer(), options);
    return buf.toOwnedSlice();
}

// -----------------------------------------------------------------------------
// Golden & Acceptance Tests
// -----------------------------------------------------------------------------

test "terminal report: golden test for normal (complete) report" {
    const allocator = testing.allocator;

    var targets = [_][]const u8{"127.0.0.1"};
    var ports = [_]u16{ 80, 443 };
    var findings = [_]FindingItem{
        .{
            .rule_id = "WS-AUDIT-HTTP-CSP-MISSING",
            .rule_version = 1,
            .title = "Missing Content-Security-Policy Header",
            .severity = "low",
            .confidence = "confirmed",
            .evidence = "Content-Security-Policy header was omitted in 200 OK response",
            .remediation = "Define an appropriate Content-Security-Policy header",
            .target = "http://127.0.0.1:80/",
        },
    };
    var tcp_obs = [_]TcpObsItem{
        .{
            .target = "127.0.0.1",
            .port = 80,
            .is_open = true,
            .rtt_ms = 8,
        },
    };

    var report_data = AssessmentReportData{
        .assessment_id = "asm-term-norm-golden",
        .profile_id = "local-security-audit",
        .profile_name = "Local Security Audit",
        .started_at_ms = 1710000000000,
        .completed_at_ms = 1710000004000,
        .duration_ms = 4000,
        .status = "completed",
        .manifest_hash = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd".*,
        .targets = &targets,
        .ports = &ports,
        .rate_limit_rps = 10,
        .timeout_ms = 5000,
        .tasks_planned = 1,
        .tasks_executed = 1,
        .tasks_succeeded = 1,
        .tasks_failed = 0,
        .is_complete = true,
        .findings = &findings,
        .tcp_obs = &tcp_obs,
    };

    const out = try renderTerminalToString(allocator, &report_data, .{ .redacted = false });
    defer allocator.free(out);

    try testing.expect(std.mem.indexOf(u8, out, "WIRESCOPE DEFENSIVE ASSESSMENT REPORT") != null);
    try testing.expect(std.mem.indexOf(u8, out, "Execution Status:    [completed]") != null);
    try testing.expect(std.mem.indexOf(u8, out, "COMPLETE (All planned assessment tasks finished successfully)") != null);
    try testing.expect(std.mem.indexOf(u8, out, "EMPIRICAL OBSERVATIONS (NEUTRAL DATA)") != null);
    try testing.expect(std.mem.indexOf(u8, out, "WS-AUDIT-HTTP-CSP-MISSING") != null);
    try testing.expect(std.mem.indexOf(u8, out, "Missing Content-Security-Policy Header") != null);
    try testing.expect(std.mem.indexOf(u8, out, "Define an appropriate Content-Security-Policy") != null);
}

test "terminal report: golden test for partial report" {
    const allocator = testing.allocator;

    var targets = [_][]const u8{"127.0.0.1"};
    var ports = [_]u16{80};
    var task_failures = [_]TaskFailureItem{
        .{
            .sequence_id = 3,
            .check_type = "http",
            .target = "http://127.0.0.1:80/",
            .error_message = "Connection reset by peer",
            .duration_ms = 22,
        },
    };

    var report_data = AssessmentReportData{
        .assessment_id = "asm-term-partial-golden",
        .profile_id = "loopback-diagnostic",
        .profile_name = "Loopback Diagnostics",
        .started_at_ms = 1710000000000,
        .completed_at_ms = 1710000002000,
        .duration_ms = 2000,
        .status = "partial",
        .manifest_hash = "9999999999999999999999999999999999999999999999999999999999999999".*,
        .targets = &targets,
        .ports = &ports,
        .rate_limit_rps = 10,
        .timeout_ms = 5000,
        .tasks_planned = 4,
        .tasks_executed = 3,
        .tasks_succeeded = 2,
        .tasks_failed = 1,
        .is_complete = false,
        .interruption_reason = "Connection reset encountered during HTTP module execution",
        .task_failures = &task_failures,
    };

    const out = try renderTerminalToString(allocator, &report_data, .{ .redacted = false });
    defer allocator.free(out);

    try testing.expect(std.mem.indexOf(u8, out, "PARTIAL / INCOMPLETE") != null);
    try testing.expect(std.mem.indexOf(u8, out, "Incomplete evidence does NOT imply absence of risk") != null);
    try testing.expect(std.mem.indexOf(u8, out, "Connection reset encountered during HTTP module execution") != null);
    try testing.expect(std.mem.indexOf(u8, out, "TASK EXECUTION FAILURES (INCOMPLETE EVIDENCE)") != null);
    try testing.expect(std.mem.indexOf(u8, out, "Connection reset by peer") != null);
}

test "terminal report: golden test for failed report" {
    const allocator = testing.allocator;

    var targets = [_][]const u8{"10.255.255.1"};
    var ports = [_]u16{80};
    var task_failures = [_]TaskFailureItem{
        .{
            .sequence_id = 1,
            .check_type = "tcp",
            .target = "10.255.255.1:80",
            .error_message = "Network interface link down",
            .duration_ms = 10,
        },
    };

    var report_data = AssessmentReportData{
        .assessment_id = "asm-term-failed-golden",
        .profile_id = "local-security-audit",
        .profile_name = "Local Security Audit",
        .started_at_ms = 1710000000000,
        .completed_at_ms = 1710000001000,
        .duration_ms = 1000,
        .status = "failed",
        .manifest_hash = "8888888888888888888888888888888888888888888888888888888888888888".*,
        .targets = &targets,
        .ports = &ports,
        .rate_limit_rps = 10,
        .timeout_ms = 5000,
        .tasks_planned = 1,
        .tasks_executed = 1,
        .tasks_succeeded = 0,
        .tasks_failed = 1,
        .is_complete = false,
        .interruption_reason = "Network link failure",
        .task_failures = &task_failures,
    };

    const out = try renderTerminalToString(allocator, &report_data, .{ .redacted = false });
    defer allocator.free(out);

    try testing.expect(std.mem.indexOf(u8, out, "Execution State:     FAILED") != null);
    try testing.expect(std.mem.indexOf(u8, out, "Network link failure") != null);
    try testing.expect(std.mem.indexOf(u8, out, "Network interface link down") != null);
}

test "terminal report: golden test for cancelled report" {
    const allocator = testing.allocator;

    var targets = [_][]const u8{"127.0.0.1"};
    var ports = [_]u16{80};

    var report_data = AssessmentReportData{
        .assessment_id = "asm-term-cancelled-golden",
        .profile_id = "local-security-audit",
        .profile_name = "Local Security Audit",
        .started_at_ms = 1710000000000,
        .completed_at_ms = 1710000002000,
        .duration_ms = 2000,
        .status = "cancelled",
        .manifest_hash = "7777777777777777777777777777777777777777777777777777777777777777".*,
        .targets = &targets,
        .ports = &ports,
        .rate_limit_rps = 10,
        .timeout_ms = 5000,
        .tasks_planned = 5,
        .tasks_executed = 2,
        .tasks_succeeded = 2,
        .tasks_failed = 0,
        .is_complete = false,
        .interruption_reason = "SIGTERM signal received",
    };

    const out = try renderTerminalToString(allocator, &report_data, .{ .redacted = true });
    defer allocator.free(out);

    try testing.expect(std.mem.indexOf(u8, out, "Execution State:     CANCELLED") != null);
    try testing.expect(std.mem.indexOf(u8, out, "SIGTERM signal received") != null);
    // Redaction warning present
    try testing.expect(std.mem.indexOf(u8, out, "WARNING: Redaction was applied to this report") != null);
    try testing.expect(std.mem.indexOf(u8, out, "reduce reproducibility") != null);
    // Neutral evidence wording
    try testing.expect(std.mem.indexOf(u8, out, "No security findings detected within tested scope") != null);
    try testing.expect(std.mem.indexOf(u8, out, "Absence of findings does not guarantee endpoint security") != null);
}
