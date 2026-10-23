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

pub const MarkdownOptions = struct {
    redacted: bool = false,
};

/// Renders a full structured assessment report in GitHub Flavored Markdown format
pub fn renderMarkdown(
    _: std.mem.Allocator,
    data: *const AssessmentReportData,
    writer: anytype,
    options: MarkdownOptions,
) !void {
    // 1. Report Header
    try writer.print(
        \\# WireScope Assessment Report: {s}
        \\
        \\
    , .{data.profile_name});

    // 2. Execution Status Callout
    if (std.mem.eql(u8, data.status, "completed") or (data.is_complete and std.mem.eql(u8, data.status, "complete"))) {
        try writer.print(
            \\> [!NOTE]
            \\> **Status: COMPLETE** — All planned assessment tasks completed successfully within declared scope boundaries.
            \\
            \\
        , .{});
    } else if (std.mem.eql(u8, data.status, "partial") or (!data.is_complete and !std.mem.eql(u8, data.status, "cancelled") and !std.mem.eql(u8, data.status, "failed"))) {
        try writer.print(
            \\> [!WARNING]
            \\> **Status: PARTIAL (INCOMPLETE)** — Assessment was interrupted or terminated before all planned tasks completed. Completed observations are preserved, but incomplete evidence does NOT imply the absence of open services or vulnerabilities.
            \\
        , .{});
        if (data.interruption_reason) |reason| {
            try writer.print(
                \\> **Interruption Reason:** {s}
                \\
            , .{reason});
        }
        try writer.print("\n", .{});
    } else if (std.mem.eql(u8, data.status, "cancelled")) {
        try writer.print(
            \\> [!CAUTION]
            \\> **Status: CANCELLED** — Assessment was cancelled by operator request before completion. Partial observations are recorded, but scope verification is incomplete.
            \\
        , .{});
        if (data.interruption_reason) |reason| {
            try writer.print(
                \\> **Cancellation Reason:** {s}
                \\
            , .{reason});
        }
        try writer.print("\n", .{});
    } else if (std.mem.eql(u8, data.status, "failed")) {
        try writer.print(
            \\> [!CAUTION]
            \\> **Status: FAILED** — Assessment encountered operational failures during task execution. Partial observations are preserved where available.
            \\
        , .{});
        if (data.interruption_reason) |reason| {
            try writer.print(
                \\> **Failure Reason:** {s}
                \\
            , .{reason});
        }
        try writer.print("\n", .{});
    }

    // 3. Redaction Warning (if redaction was applied)
    if (options.redacted) {
        try writer.writeAll(redact_mod.REDACTION_DISCLAIMER_MARKDOWN);
        try writer.writeAll("\n");
    }

    // 4. Executive Metadata Table
    try writer.print(
        \\## Assessment Metadata
        \\
        \\| Property | Value |
        \\| :--- | :--- |
        \\| **Assessment ID** | `{s}` |
        \\| **Profile** | {s} (`{s}`) |
        \\| **Execution Status** | **{s}** |
        \\| **Execution Duration** | {d} ms |
        \\| **Start Timestamp** | {d} ms |
        \\| **Completion Timestamp** | {d} ms |
        \\| **Tasks Planned** | {d} |
        \\| **Tasks Executed** | {d} |
        \\| **Tasks Succeeded** | {d} |
        \\| **Tasks Failed** | {d} |
        \\| **Integrity Manifest SHA-256** | `{s}` |
        \\| **Report Schema Version** | v{d} |
        \\
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

    // 5. Scope & Boundary Parameters
    try writer.writeAll(
        \\## Scope & Authorization Boundaries
        \\
        \\- **Target Endpoints:** 
    );
    if (data.targets.len == 0) {
        try writer.writeAll("`none`\n");
    } else {
        for (data.targets, 0..) |tgt, i| {
            if (i > 0) try writer.writeAll(", ");
            try writer.print("`{s}`", .{tgt});
        }
        try writer.writeAll("\n");
    }

    try writer.writeAll("- **Port Range:** ");
    if (data.ports.len == 0) {
        try writer.writeAll("`none`\n");
    } else {
        for (data.ports, 0..) |p, i| {
            if (i > 0) try writer.writeAll(", ");
            try writer.print("`{d}`", .{p});
        }
        try writer.writeAll("\n");
    }

    try writer.writeAll("- **Configured Exclusions:** ");
    if (data.exclusions.len == 0) {
        try writer.writeAll("`none`\n");
    } else {
        for (data.exclusions, 0..) |ex, i| {
            if (i > 0) try writer.writeAll(", ");
            try writer.print("`{s}`", .{ex});
        }
        try writer.writeAll("\n");
    }

    try writer.print(
        \\- **Rate Limit Delay:** {d} RPS
        \\- **Socket / Probe Timeout:** {d} ms
        \\- **Allow Out-of-Scope Redirects:** `{s}`
        \\
        \\
    , .{
        data.rate_limit_rps,
        data.timeout_ms,
        if (data.allow_out_of_scope_redirects) "true" else "false",
    });

    // 6. Section: Observations (Empirical Telemetry)
    try writer.print(
        \\## 1. Empirical Network Observations
        \\
        \\> [!NOTE]
        \\> **Observation vs. Finding Distinction:** Observations represent neutral, empirical measurements of responsive endpoints and system attributes. They do not constitute security findings, vulnerabilities, or policy violations on their own. Response bodies are omitted by default to prevent credential leakage.
        \\
        \\
    , .{});

    // DNS Observations
    if (data.dns_obs.len > 0) {
        try writer.writeAll(
            \\### DNS Observations
            \\
            \\| Target | Status | Resolved Answers | Duration |
            \\| :--- | :--- | :--- | :--- |
            \\
        );
        for (data.dns_obs) |d| {
            try writer.print("| `{s}` | `{s}` | ", .{
                d.target,
                if (d.is_success) "resolved" else "nxdomain_or_timeout",
            });
            if (d.answers.len == 0) {
                try writer.writeAll("`none`");
            } else {
                for (d.answers, 0..) |ans, i| {
                    if (i > 0) try writer.writeAll(", ");
                    try writer.print("`{s}`", .{ans});
                }
            }
            try writer.print(" | {d} ms |\n", .{d.duration_ms});
        }
        try writer.writeAll("\n");
    }

    // TCP Observations
    if (data.tcp_obs.len > 0) {
        try writer.writeAll(
            \\### TCP Port Observations
            \\
            \\| Target | Port | State | Round-Trip Latency |
            \\| :--- | :--- | :--- | :--- |
            \\
        );
        for (data.tcp_obs) |t| {
            try writer.print("| `{s}` | `{d}` | `{s}` | ", .{
                t.target,
                t.port,
                if (t.is_open) "open" else "closed_or_filtered",
            });
            if (t.rtt_ms) |rtt| {
                try writer.print("{d} ms", .{rtt});
            } else {
                try writer.writeAll("N/A");
            }
            try writer.writeAll(" |\n");
        }
        try writer.writeAll("\n");
    }

    // TLS Observations
    if (data.tls_obs.len > 0) {
        try writer.writeAll(
            \\### TLS Handshake Observations
            \\
            \\| Target | Port | Protocol Version | Hostname Match | Valid Chain | Expiration Days |
            \\| :--- | :--- | :--- | :--- | :--- | :--- |
            \\
        );
        for (data.tls_obs) |tl| {
            try writer.print("| `{s}` | `{d}` | `{s}` | `{s}` | `{s}` | ", .{
                tl.target,
                tl.port,
                tl.protocol_version,
                if (tl.hostname_matches) "yes" else "no",
                if (tl.is_valid_chain) "yes" else "no",
            });
            if (tl.days_to_expiration) |days| {
                try writer.print("{d} days", .{days});
            } else {
                try writer.writeAll("N/A");
            }
            try writer.writeAll(" |\n");
        }
        try writer.writeAll("\n");
    }

    // HTTP Observations
    if (data.http_obs.len > 0) {
        try writer.writeAll(
            \\### HTTP Header & Security Observations
            \\
            \\| Target URL | Status Code | HTTPS | HSTS Header | CSP Header | X-Content-Type |
            \\| :--- | :--- | :--- | :--- | :--- | :--- |
            \\
        );
        for (data.http_obs) |h| {
            try writer.print("| `{s}` | `{d}` | `{s}` | `{s}` | `{s}` | `{s}` |\n", .{
                h.target_url,
                h.status_code,
                if (h.is_https) "yes" else "no",
                h.hsts_header orelse "missing",
                h.csp_header orelse "missing",
                h.x_content_type_options orelse "missing",
            });
        }
        try writer.writeAll("\n");
    }

    // Listener Observations
    if (data.listener_obs.len > 0) {
        try writer.writeAll(
            \\### Active Local Listeners
            \\
            \\| Transport | Address | Port | Binding | Process | PID | Unlisted |
            \\| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
            \\
        );
        for (data.listener_obs) |l| {
            try writer.print("| `{s}` | `{s}` | `{d}` | `{s}` | `{s}` | ", .{
                l.transport,
                l.address,
                l.port,
                l.binding_type,
                l.process_name orelse "N/A",
            });
            if (l.pid) |p| {
                try writer.print("{d}", .{p});
            } else {
                try writer.writeAll("N/A");
            }
            try writer.print(" | `{s}` |\n", .{if (l.is_unlisted) "YES" else "no"});
        }
        try writer.writeAll("\n");
    }

    if (data.dns_obs.len == 0 and data.tcp_obs.len == 0 and data.tls_obs.len == 0 and data.http_obs.len == 0 and data.listener_obs.len == 0) {
        try writer.writeAll("No network observations recorded within the evaluated scope.\n\n");
    }

    // 7. Section: Security Findings (Defensive Policy Violations)
    try writer.print(
        \\## 2. Defensive Security Findings
        \\
        \\> [!IMPORTANT]
        \\> Security findings identify configuration gaps, protocol weaknesses, or defensive policy violations evaluated against deterministic rule sets.
        \\
        \\
    , .{});

    if (data.findings.len == 0) {
        try writer.writeAll(
            \\No security findings detected within the tested scope.
            \\
            \\*(Note: The absence of findings does not guarantee that an endpoint is secure or vulnerability-free. It confirms only that no configured defensive rules were triggered by the collected evidence within tested parameters.)*
            \\
            \\
        );
    } else {
        for (data.findings, 1..) |f, i| {
            try writer.print(
                \\### Finding {d}: [{s}] {s} (`{s}` v{d})
                \\
                \\- **Target / Resource:** `{s}`
                \\- **Severity:** **{s}**
                \\- **Confidence:** `{s}`
                \\- **Severity Rationale:** {s}
                \\- **Observed Evidence:** `{s}`
                \\- **Actionable Remediation:** {s}
                \\
                \\
            , .{
                i,
                f.severity,
                f.title,
                f.rule_id,
                f.rule_version,
                f.target,
                f.severity,
                f.confidence,
                f.title,
                f.evidence,
                f.remediation,
            });
        }
    }

    // 8. Section: Policy Evaluation Outcomes
    if (data.policy_results.len > 0) {
        try writer.writeAll(
            \\## 3. Offline Policy Evaluation Outcomes
            \\
            \\| Rule ID | Outcome | Target | Details |
            \\| :--- | :--- | :--- | :--- |
            \\
        );
        for (data.policy_results) |p| {
            try writer.print("| `{s}` | **{s}** | `{s}` | {s} |\n", .{
                p.rule_id,
                p.outcome,
                p.target,
                p.message,
            });
        }
        try writer.writeAll("\n");
    }

    // 9. Section: Task Failures & Incomplete Evidence
    if (data.task_failures.len > 0) {
        try writer.print(
            \\## 4. Task Execution Failures & Incomplete Evidence
            \\
            \\> [!CAUTION]
            \\> The following tasks failed during execution. Incomplete evidence does NOT imply the absence of vulnerabilities or open services on affected targets.
            \\
            \\| Seq | Check Type | Target | Error Message | Elapsed |
            \\| :--- | :--- | :--- | :--- | :--- |
            \\
        , .{});
        for (data.task_failures) |tf| {
            try writer.print("| #{d} | `{s}` | `{s}` | {s} | {d} ms |\n", .{
                tf.sequence_id,
                tf.check_type,
                tf.target,
                tf.error_message,
                tf.duration_ms,
            });
        }
        try writer.writeAll("\n");
    }

    // 10. Section: Limitations & Diagnostic Constraints
    if (data.limitations.len > 0) {
        try writer.writeAll(
            \\## 5. Diagnostic Constraints & Limitations
            \\
            \\| Category | Component | Limitation Description |
            \\| :--- | :--- | :--- |
            \\
        );
        for (data.limitations) |lim| {
            try writer.print("| `{s}` | `{s}` | {s} |\n", .{
                lim.category,
                lim.component,
                lim.description,
            });
        }
        try writer.writeAll("\n");
    }

    // 11. Defensive Disclaimer Footer
    try writer.writeAll(
        \\---
        \\*Generated by WireScope. WireScope operates strictly as a defensive assessment tool adhering to configured authorization boundaries and non-destructive auditing practices. No response bodies or credentials are logged or retained.*
        \\
    );
}

/// Renders Markdown report into an allocated string slice
pub fn renderMarkdownToString(
    allocator: std.mem.Allocator,
    data: *const AssessmentReportData,
    options: MarkdownOptions,
) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    try renderMarkdown(allocator, data, buf.writer(), options);
    return buf.toOwnedSlice();
}

// -----------------------------------------------------------------------------
// Golden & Acceptance Tests
// -----------------------------------------------------------------------------

test "markdown report: golden test for normal (complete) report" {
    const allocator = testing.allocator;

    var targets = [_][]const u8{"127.0.0.1"};
    var ports = [_]u16{ 80, 443 };
    var findings = [_]FindingItem{
        .{
            .rule_id = "WS-AUDIT-HTTP-HSTS-MISSING",
            .rule_version = 1,
            .title = "Missing HTTP Strict Transport Security Header",
            .severity = "medium",
            .confidence = "confirmed",
            .evidence = "Strict-Transport-Security header was not returned",
            .remediation = "Configure Strict-Transport-Security with max-age >= 31536000",
            .target = "https://127.0.0.1:443/",
        },
    };
    var http_obs = [_]HttpObsItem{
        .{
            .target_url = "https://127.0.0.1:443/",
            .status_code = 200,
            .is_https = true,
            .is_html = true,
            .is_json_api = false,
            .hsts_header = null,
            .csp_header = null,
            .x_content_type_options = "nosniff",
        },
    };

    var report_data = AssessmentReportData{
        .assessment_id = "asm-norm-golden",
        .profile_id = "local-security-audit",
        .profile_name = "Local Security Audit",
        .started_at_ms = 1710000000000,
        .completed_at_ms = 1710000005000,
        .duration_ms = 5000,
        .status = "completed",
        .manifest_hash = "1111111111111111111111111111111111111111111111111111111111111111".*,
        .targets = &targets,
        .ports = &ports,
        .rate_limit_rps = 10,
        .timeout_ms = 5000,
        .tasks_planned = 2,
        .tasks_executed = 2,
        .tasks_succeeded = 2,
        .tasks_failed = 0,
        .is_complete = true,
        .findings = &findings,
        .http_obs = &http_obs,
    };

    const md = try renderMarkdownToString(allocator, &report_data, .{ .redacted = false });
    defer allocator.free(md);

    // Assertions matching structured model and acceptance criteria
    try testing.expect(std.mem.indexOf(u8, md, "# WireScope Assessment Report: Local Security Audit") != null);
    try testing.expect(std.mem.indexOf(u8, md, "**Status: COMPLETE**") != null);
    try testing.expect(std.mem.indexOf(u8, md, "asm-norm-golden") != null);
    try testing.expect(std.mem.indexOf(u8, md, "Observation vs. Finding Distinction") != null);
    try testing.expect(std.mem.indexOf(u8, md, "WS-AUDIT-HTTP-HSTS-MISSING") != null);
    try testing.expect(std.mem.indexOf(u8, md, "Missing HTTP Strict Transport Security Header") != null);
    try testing.expect(std.mem.indexOf(u8, md, "Configure Strict-Transport-Security") != null);
}

test "markdown report: golden test for partial report" {
    const allocator = testing.allocator;

    var targets = [_][]const u8{"127.0.0.1"};
    var ports = [_]u16{80};
    var task_failures = [_]TaskFailureItem{
        .{
            .sequence_id = 2,
            .check_type = "tcp",
            .target = "127.0.0.1:80",
            .error_message = "Connection timed out after 5000ms",
            .duration_ms = 5000,
        },
    };

    var report_data = AssessmentReportData{
        .assessment_id = "asm-partial-golden",
        .profile_id = "local-security-audit",
        .profile_name = "Local Security Audit",
        .started_at_ms = 1710000000000,
        .completed_at_ms = 1710000006000,
        .duration_ms = 6000,
        .status = "partial",
        .manifest_hash = "2222222222222222222222222222222222222222222222222222222222222222".*,
        .targets = &targets,
        .ports = &ports,
        .rate_limit_rps = 10,
        .timeout_ms = 5000,
        .tasks_planned = 2,
        .tasks_executed = 2,
        .tasks_succeeded = 1,
        .tasks_failed = 1,
        .is_complete = false,
        .interruption_reason = "Partial timeout on target 127.0.0.1",
        .task_failures = &task_failures,
    };

    const md = try renderMarkdownToString(allocator, &report_data, .{ .redacted = false });
    defer allocator.free(md);

    try testing.expect(std.mem.indexOf(u8, md, "**Status: PARTIAL (INCOMPLETE)**") != null);
    try testing.expect(std.mem.indexOf(u8, md, "Partial timeout on target 127.0.0.1") != null);
    try testing.expect(std.mem.indexOf(u8, md, "incomplete evidence does NOT imply") != null);
    try testing.expect(std.mem.indexOf(u8, md, "Task Execution Failures & Incomplete Evidence") != null);
    try testing.expect(std.mem.indexOf(u8, md, "Connection timed out after 5000ms") != null);
}

test "markdown report: golden test for failed report" {
    const allocator = testing.allocator;

    var targets = [_][]const u8{"192.0.2.1"};
    var ports = [_]u16{443};
    var task_failures = [_]TaskFailureItem{
        .{
            .sequence_id = 1,
            .check_type = "tls",
            .target = "192.0.2.1:443",
            .error_message = "Host route unreachable",
            .duration_ms = 250,
        },
    };

    var report_data = AssessmentReportData{
        .assessment_id = "asm-failed-golden",
        .profile_id = "local-security-audit",
        .profile_name = "Local Security Audit",
        .started_at_ms = 1710000000000,
        .completed_at_ms = 1710000001000,
        .duration_ms = 1000,
        .status = "failed",
        .manifest_hash = "3333333333333333333333333333333333333333333333333333333333333333".*,
        .targets = &targets,
        .ports = &ports,
        .rate_limit_rps = 10,
        .timeout_ms = 5000,
        .tasks_planned = 1,
        .tasks_executed = 1,
        .tasks_succeeded = 0,
        .tasks_failed = 1,
        .is_complete = false,
        .interruption_reason = "Network unreachable failure",
        .task_failures = &task_failures,
    };

    const md = try renderMarkdownToString(allocator, &report_data, .{ .redacted = false });
    defer allocator.free(md);

    try testing.expect(std.mem.indexOf(u8, md, "**Status: FAILED**") != null);
    try testing.expect(std.mem.indexOf(u8, md, "Network unreachable failure") != null);
    try testing.expect(std.mem.indexOf(u8, md, "Host route unreachable") != null);
}

test "markdown report: golden test for cancelled report" {
    const allocator = testing.allocator;

    var targets = [_][]const u8{"127.0.0.1"};
    var ports = [_]u16{80};

    var report_data = AssessmentReportData{
        .assessment_id = "asm-cancelled-golden",
        .profile_id = "local-security-audit",
        .profile_name = "Local Security Audit",
        .started_at_ms = 1710000000000,
        .completed_at_ms = 1710000001500,
        .duration_ms = 1500,
        .status = "cancelled",
        .manifest_hash = "4444444444444444444444444444444444444444444444444444444444444444".*,
        .targets = &targets,
        .ports = &ports,
        .rate_limit_rps = 10,
        .timeout_ms = 5000,
        .tasks_planned = 10,
        .tasks_executed = 3,
        .tasks_succeeded = 3,
        .tasks_failed = 0,
        .is_complete = false,
        .interruption_reason = "SIGINT received by operator",
    };

    const md = try renderMarkdownToString(allocator, &report_data, .{ .redacted = true });
    defer allocator.free(md);

    try testing.expect(std.mem.indexOf(u8, md, "**Status: CANCELLED**") != null);
    try testing.expect(std.mem.indexOf(u8, md, "SIGINT received by operator") != null);
    // Redaction warning present
    try testing.expect(std.mem.indexOf(u8, md, "REDACTION APPLIED") != null);
    try testing.expect(std.mem.indexOf(u8, md, "reduce report reproducibility") != null);
    // Neutral evidence claim check
    try testing.expect(std.mem.indexOf(u8, md, "No security findings detected within the tested scope") != null);
    try testing.expect(std.mem.indexOf(u8, md, "absence of findings does not guarantee that an endpoint is secure") != null);
}
