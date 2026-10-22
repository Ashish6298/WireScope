const std = @import("std");
const testing = std.testing;

const core = @import("../core/root.zig");
const platform = @import("../platform/root.zig");

pub const Severity = core.Severity;
pub const Confidence = core.Confidence;
pub const Finding = core.Finding;
pub const FindingStatus = core.FindingStatus;
pub const BindingType = platform.BindingType;
pub const ListenerEntry = platform.ListenerEntry;
pub const ListenerInspectionResult = platform.ListenerInspectionResult;

/// Binding policy rule for expected listening services
pub const BindingPolicy = enum {
    loopback_only,
    wildcard_allowed,
    specific_only,

    pub fn toSlice(self: BindingPolicy) []const u8 {
        return @tagName(self);
    }
};

/// Expected service declaration in an exposure policy
pub const ExpectedServicePolicy = struct {
    port: u16,
    transport: []const u8 = "tcp",
    service_name: ?[]const u8 = null,
    allowed_binding: BindingPolicy = .loopback_only,
    expected_process: ?[]const u8 = null,

    pub fn deinit(self: *ExpectedServicePolicy, allocator: std.mem.Allocator) void {
        allocator.free(self.transport);
        if (self.service_name) |s| allocator.free(s);
        if (self.expected_process) |p| allocator.free(p);
    }

    pub fn clone(self: *const ExpectedServicePolicy, allocator: std.mem.Allocator) !ExpectedServicePolicy {
        return ExpectedServicePolicy{
            .port = self.port,
            .transport = try allocator.dupe(u8, self.transport),
            .service_name = if (self.service_name) |s| try allocator.dupe(u8, s) else null,
            .allowed_binding = self.allowed_binding,
            .expected_process = if (self.expected_process) |p| try allocator.dupe(u8, p) else null,
        };
    }
};

/// Local exposure evaluation policy defining expected services and binding constraints
pub const LocalExposurePolicy = struct {
    policy_id: []const u8 = "default-exposure-policy",
    policy_version: u32 = 1,
    description: []const u8 = "Default defensive exposure policy: flags unapproved wildcard bindings and unexpected listeners.",
    allow_unknown_loopback: bool = true,
    allow_unlisted_wildcards: bool = false,
    expected_services: []ExpectedServicePolicy = &.{},

    pub fn deinit(self: *LocalExposurePolicy, allocator: std.mem.Allocator) void {
        for (self.expected_services) |*s| {
            s.deinit(allocator);
        }
        if (self.expected_services.len > 0) {
            allocator.free(self.expected_services);
        }
    }

    pub fn clone(self: *const LocalExposurePolicy, allocator: std.mem.Allocator) !LocalExposurePolicy {
        var services = try allocator.alloc(ExpectedServicePolicy, self.expected_services.len);
        errdefer {
            for (services) |*s| s.deinit(allocator);
            allocator.free(services);
        }
        for (self.expected_services, 0..) |s, i| {
            services[i] = try s.clone(allocator);
        }

        return LocalExposurePolicy{
            .policy_id = self.policy_id,
            .policy_version = self.policy_version,
            .description = self.description,
            .allow_unknown_loopback = self.allow_unknown_loopback,
            .allow_unlisted_wildcards = self.allow_unlisted_wildcards,
            .expected_services = services,
        };
    }

    /// Parses comma-separated list of expected ports (e.g. "22,80,443") into a LocalExposurePolicy
    pub fn fromExpectedPorts(allocator: std.mem.Allocator, ports_str: []const u8) !LocalExposurePolicy {
        var list = std.ArrayList(ExpectedServicePolicy).init(allocator);
        errdefer {
            for (list.items) |*s| s.deinit(allocator);
            list.deinit();
        }

        var it = std.mem.splitScalar(u8, ports_str, ',');
        while (it.next()) |token| {
            const trimmed = std.mem.trim(u8, token, " \t\r\n");
            if (trimmed.len == 0) continue;

            const port = std.fmt.parseInt(u16, trimmed, 10) catch continue;
            try list.append(.{
                .port = port,
                .transport = try allocator.dupe(u8, "tcp"),
                .service_name = null,
                .allowed_binding = .wildcard_allowed, // Specified ports are permitted on wildcard/interface
                .expected_process = null,
            });
        }

        return LocalExposurePolicy{
            .policy_id = "custom-expected-ports-policy",
            .policy_version = 1,
            .description = "Custom policy generated from CLI expected port specification.",
            .allow_unknown_loopback = true,
            .allow_unlisted_wildcards = false,
            .expected_services = try list.toOwnedSlice(),
        };
    }
};

/// Defensive local exposure finding preserving supporting observations and false-positive caveats
pub const LocalExposureFinding = struct {
    rule_id: []const u8,
    rule_version: u32 = 1,
    title: []const u8,
    description: []const u8,
    severity: Severity,
    severity_rationale: []const u8,
    confidence: Confidence,
    affected_target: []const u8,
    evidence: []const u8,
    supporting_observations: []const u8,
    remediation: []const u8,
    false_positive_caveat: []const u8,
    limitations: []const u8,
    context_evaluation: []const u8,

    pub fn deinit(self: *LocalExposureFinding, allocator: std.mem.Allocator) void {
        allocator.free(self.rule_id);
        allocator.free(self.title);
        allocator.free(self.description);
        allocator.free(self.severity_rationale);
        allocator.free(self.affected_target);
        allocator.free(self.evidence);
        allocator.free(self.supporting_observations);
        allocator.free(self.remediation);
        allocator.free(self.false_positive_caveat);
        allocator.free(self.limitations);
        allocator.free(self.context_evaluation);
    }

    pub fn clone(self: *const LocalExposureFinding, allocator: std.mem.Allocator) !LocalExposureFinding {
        return LocalExposureFinding{
            .rule_id = try allocator.dupe(u8, self.rule_id),
            .rule_version = self.rule_version,
            .title = try allocator.dupe(u8, self.title),
            .description = try allocator.dupe(u8, self.description),
            .severity = self.severity,
            .severity_rationale = try allocator.dupe(u8, self.severity_rationale),
            .confidence = self.confidence,
            .affected_target = try allocator.dupe(u8, self.affected_target),
            .evidence = try allocator.dupe(u8, self.evidence),
            .supporting_observations = try allocator.dupe(u8, self.supporting_observations),
            .remediation = try allocator.dupe(u8, self.remediation),
            .false_positive_caveat = try allocator.dupe(u8, self.false_positive_caveat),
            .limitations = try allocator.dupe(u8, self.limitations),
            .context_evaluation = try allocator.dupe(u8, self.context_evaluation),
        };
    }

    pub fn toCoreFinding(self: *const LocalExposureFinding, allocator: std.mem.Allocator) !Finding {
        const now = std.time.milliTimestamp();
        return Finding{
            .rule_id = try allocator.dupe(u8, self.rule_id),
            .rule_version = self.rule_version,
            .title = try allocator.dupe(u8, self.title),
            .description = try allocator.dupe(u8, self.description),
            .severity = self.severity,
            .severity_rationale = try allocator.dupe(u8, self.severity_rationale),
            .confidence = self.confidence,
            .affected_target = try allocator.dupe(u8, self.affected_target),
            .evidence = try allocator.dupe(u8, self.evidence),
            .remediation = try allocator.dupe(u8, self.remediation),
            .status = .new,
            .first_seen_ms = now,
            .last_seen_ms = now,
        };
    }
};

/// Result of local listening service exposure audit
pub const LocalExposureAuditResult = struct {
    policy_id: []const u8,
    is_permission_limited: bool,
    total_listeners_observed: usize,
    wildcard_listeners_count: usize,
    loopback_listeners_count: usize,
    specific_listeners_count: usize,
    listeners: []ListenerEntry = &.{},
    findings: []LocalExposureFinding = &.{},
    checks_total: u32 = 0,
    checks_passed: u32 = 0,
    operational_limitations: []const u8,
    elapsed_ns: u64 = 0,

    pub fn deinit(self: *LocalExposureAuditResult, allocator: std.mem.Allocator) void {
        allocator.free(self.policy_id);
        allocator.free(self.operational_limitations);

        for (self.listeners) |*l| l.deinit(allocator);
        if (self.listeners.len > 0) allocator.free(self.listeners);

        for (self.findings) |*f| f.deinit(allocator);
        if (self.findings.len > 0) allocator.free(self.findings);
    }

    pub fn hasHighOrCriticalFindings(self: *const LocalExposureAuditResult) bool {
        for (self.findings) |f| {
            if (f.severity == .high or f.severity == .critical) return true;
        }
        return false;
    }

    pub fn toTerminal(self: *const LocalExposureAuditResult, writer: anytype) !void {
        try writer.print("================================================================================\n", .{});
        try writer.print("WIRESCOPE LOCAL EXPOSURE AUDIT\n", .{});
        try writer.print("================================================================================\n", .{});
        try writer.print("Policy ID:             {s}\n", .{self.policy_id});
        try writer.print("Listeners Observed:    {d} (Wildcard: {d}, Loopback: {d}, Specific: {d})\n", .{
            self.total_listeners_observed,
            self.wildcard_listeners_count,
            self.loopback_listeners_count,
            self.specific_listeners_count,
        });
        if (self.is_permission_limited) {
            try writer.writeAll("Permission Status:     RESTRICTED (Process names/PIDs partially limited by OS permissions)\n");
        } else {
            try writer.writeAll("Permission Status:     FULL ACCESS\n");
        }

        try writer.writeAll("\n--- LOCAL LISTENING SOCKETS INVENTORY ---\n");
        if (self.listeners.len == 0) {
            if (self.is_permission_limited) {
                try writer.writeAll("  No listening sockets could be enumerated due to OS permission constraints.\n");
            } else {
                try writer.writeAll("  No active listening TCP sockets detected on the local system.\n");
            }
        } else {
            try writer.print("  {s:<7} {s:<20} {s:<8} {s:<18} {s:<8} {s:<20}\n", .{
                "Proto", "Local Address", "Port", "Binding Type", "PID", "Process Name",
            });
            try writer.writeAll("  --------------------------------------------------------------------------------\n");
            for (self.listeners) |l| {
                var pid_buf: [16]u8 = undefined;
                const pid_str = if (l.pid) |p|
                    std.fmt.bufPrint(&pid_buf, "{d}", .{p}) catch "-"
                else
                    "-";
                const proc_str = l.process_name orelse "-";

                try writer.print("  {s:<7} {s:<20} {d:<8} {s:<18} {s:<8} {s:<20}\n", .{
                    l.transport,
                    l.local_address,
                    l.local_port,
                    l.binding_type.toSlice(),
                    pid_str,
                    proc_str,
                });
            }
        }

        try writer.writeAll("\n--- DEFENSIVE EXPOSURE FINDINGS ---\n");
        if (self.findings.len == 0) {
            try writer.writeAll("No unexpected listener exposures or unapproved wildcard bindings detected.\nAll observed listening sockets conform to policy.\n");
        } else {
            for (self.findings, 0..) |f, i| {
                try writer.print("\n[{d}] [{s}] {s} ({s})\n", .{ i + 1, f.severity.toSlice(), f.title, f.rule_id });
                try writer.print("    Severity Rationale:      {s}\n", .{f.severity_rationale});
                try writer.print("    Supporting Observations: {s}\n", .{f.supporting_observations});
                try writer.print("    Evidence:                {s}\n", .{f.evidence});
                try writer.print("    Context Evaluation:      {s}\n", .{f.context_evaluation});
                try writer.print("    Remediation:             {s}\n", .{f.remediation});
                try writer.print("    Caveat:                  {s}\n", .{f.false_positive_caveat});
                try writer.print("    Limitations:             {s}\n", .{f.limitations});
            }
        }

        try writer.writeAll("\n--- AUDIT SUMMARY ---\n");
        try writer.print("Checks evaluated: {d} | Compliant: {d} | Findings: {d}\n", .{
            self.checks_total,
            self.checks_passed,
            self.findings.len,
        });
        try writer.print("Operational limitations: {s}\n", .{self.operational_limitations});
        try writer.print("WireScope Disclaimer: The audit is read-only. No system or firewall settings were modified. No listener is called exploitable solely because it exists.\n", .{});
        try writer.print("================================================================================\n", .{});
    }

    pub fn toJson(self: *const LocalExposureAuditResult, writer: anytype) !void {
        try writer.print("{{\"audit_type\":\"local_exposure_audit\",\"schema_version\":1,\"policy_id\":\"{s}\",\"permission_limited\":{s},\"summary\":{{\"total_listeners\":{d},\"wildcard\":{d},\"loopback\":{d},\"specific\":{d},\"checks_total\":{d},\"checks_passed\":{d},\"findings_count\":{d},\"has_high_or_critical\":{s}}}", .{
            self.policy_id,
            if (self.is_permission_limited) "true" else "false",
            self.total_listeners_observed,
            self.wildcard_listeners_count,
            self.loopback_listeners_count,
            self.specific_listeners_count,
            self.checks_total,
            self.checks_passed,
            self.findings.len,
            if (self.hasHighOrCriticalFindings()) "true" else "false",
        });

        try writer.writeAll(",\"listeners\":[");
        for (self.listeners, 0..) |l, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.print("{{\"transport\":\"{s}\",\"local_address\":\"{s}\",\"local_port\":{d},\"binding_type\":\"{s}\",\"pid\":", .{
                l.transport,
                l.local_address,
                l.local_port,
                l.binding_type.toSlice(),
            });
            if (l.pid) |p| try writer.print("{d}", .{p}) else try writer.writeAll("null");
            try writer.writeAll(",\"process_name\":");
            if (l.process_name) |p| {
                try writeJsonStringEscaped(writer, p);
            } else {
                try writer.writeAll("null");
            }
            try writer.writeAll("}");
        }
        try writer.writeAll("]");

        try writer.writeAll(",\"findings\":[");
        for (self.findings, 0..) |f, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.print("{{\"rule_id\":\"{s}\",\"title\":", .{f.rule_id});
            try writeJsonStringEscaped(writer, f.title);
            try writer.writeAll(",\"severity\":\"");
            try writer.writeAll(f.severity.toSlice());
            try writer.writeAll("\",\"severity_rationale\":");
            try writeJsonStringEscaped(writer, f.severity_rationale);
            try writer.writeAll(",\"evidence\":");
            try writeJsonStringEscaped(writer, f.evidence);
            try writer.writeAll(",\"supporting_observations\":");
            try writeJsonStringEscaped(writer, f.supporting_observations);
            try writer.writeAll(",\"context_evaluation\":");
            try writeJsonStringEscaped(writer, f.context_evaluation);
            try writer.writeAll(",\"remediation\":");
            try writeJsonStringEscaped(writer, f.remediation);
            try writer.writeAll(",\"false_positive_caveat\":");
            try writeJsonStringEscaped(writer, f.false_positive_caveat);
            try writer.writeAll(",\"limitations\":");
            try writeJsonStringEscaped(writer, f.limitations);
            try writer.writeAll("}");
        }
        try writer.writeAll("]");

        try writer.writeAll(",\"operational_limitations\":");
        try writeJsonStringEscaped(writer, self.operational_limitations);
        try writer.writeAll("}\n");
    }

    pub fn toMarkdown(self: *const LocalExposureAuditResult, writer: anytype) !void {
        try writer.print("# WireScope Local Listening Service Exposure Audit\n\n", .{});
        try writer.print("**Policy:** `{s}`  \n", .{self.policy_id});
        try writer.print("**Observed Listeners:** {d} (Wildcard: {d}, Loopback: {d}, Specific: {d})  \n", .{
            self.total_listeners_observed,
            self.wildcard_listeners_count,
            self.loopback_listeners_count,
            self.specific_listeners_count,
        });

        if (self.is_permission_limited) {
            try writer.writeAll("> [!WARNING]\n> **Permission Notice:** Local process name and PID enumeration was restricted by operating system permissions. Lack of observable processes does not imply absence of risk.\n\n");
        }

        try writer.writeAll("## Local Listening Sockets\n\n");
        if (self.listeners.len == 0) {
            try writer.writeAll("No active listening sockets observed.\n\n");
        } else {
            try writer.writeAll("| Proto | Local Address | Port | Binding Type | PID | Process Name |\n");
            try writer.writeAll("| :--- | :--- | :---: | :--- | :---: | :--- |\n");
            for (self.listeners) |l| {
                var pid_buf: [16]u8 = undefined;
                const pid_str = if (l.pid) |p|
                    std.fmt.bufPrint(&pid_buf, "{d}", .{p}) catch "-"
                else
                    "-";
                const proc_str = l.process_name orelse "-";

                try writer.print("| `{s}` | `{s}` | {d} | `{s}` | {s} | `{s}` |\n", .{
                    l.transport,
                    l.local_address,
                    l.local_port,
                    l.binding_type.toSlice(),
                    pid_str,
                    proc_str,
                });
            }
            try writer.writeAll("\n");
        }

        try writer.writeAll("## Exposure Findings\n\n");
        if (self.findings.len == 0) {
            try writer.writeAll("> [!NOTE]\n> No unexpected listener exposures or unapproved wildcard bindings detected. All active listening sockets conform to policy.\n\n");
        } else {
            for (self.findings) |f| {
                try writer.print("### {s} — {s}\n\n", .{ f.rule_id, f.title });
                try writer.print("- **Severity:** `{s}`\n", .{f.severity.toSlice()});
                try writer.print("- **Severity Rationale:** {s}\n", .{f.severity_rationale});
                try writer.print("- **Supporting Observations:** {s}\n", .{f.supporting_observations});
                try writer.print("- **Evidence:** `{s}`\n", .{f.evidence});
                try writer.print("- **Context Evaluation:** {s}\n", .{f.context_evaluation});
                try writer.print("- **Remediation:** {s}\n", .{f.remediation});
                try writer.print("- **False-Positive Caveat:** {s}\n", .{f.false_positive_caveat});
                try writer.print("- **Limitations:** {s}\n\n", .{f.limitations});
            }
        }

        try writer.writeAll("## Audit Boundaries & Safety Guarantee\n\n");
        try writer.print("> [!IMPORTANT]\n> {s}\n>\n> WireScope local exposure auditing is strictly **read-only**. It does not alter firewall configurations, modify registry keys, adjust routing tables, or change socket binding states. No listening port is labeled exploitable solely because it exists.\n", .{self.operational_limitations});
    }
};

fn writeJsonStringEscaped(writer: anytype, str: []const u8) !void {
    try writer.writeByte('"');
    for (str) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => try writer.writeByte(c),
        }
    }
    try writer.writeByte('"');
}

// -------------------------------------------------------------------------
// INSPECTOR INTERFACE (Dependency Injection for Hermetic Testing)
// -------------------------------------------------------------------------

pub const ListenerInspector = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        inspect: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator) anyerror!ListenerInspectionResult,
    };

    pub fn inspect(self: ListenerInspector, allocator: std.mem.Allocator) !ListenerInspectionResult {
        return self.vtable.inspect(self.ptr, allocator);
    }
};

/// Real OS listener inspector using platform adapters
pub const RealListenerInspector = struct {
    pub fn inspector() ListenerInspector {
        return .{
            .ptr = undefined,
            .vtable = &.{
                .inspect = realInspectImpl,
            },
        };
    }

    fn realInspectImpl(_: *anyopaque, allocator: std.mem.Allocator) anyerror!ListenerInspectionResult {
        return platform.inspectListeners(allocator);
    }
};

/// Mock listener inspector allowing synthetic test fixtures
pub const MockListenerInspector = struct {
    mock_listeners: []const ListenerEntry = &.{},
    mock_permission_limited: bool = false,

    pub fn inspector(self: *MockListenerInspector) ListenerInspector {
        return .{
            .ptr = self,
            .vtable = &.{
                .inspect = mockInspectImpl,
            },
        };
    }

    fn mockInspectImpl(ctx: *anyopaque, allocator: std.mem.Allocator) anyerror!ListenerInspectionResult {
        const self: *MockListenerInspector = @ptrCast(@alignCast(ctx));

        var cloned_list = try allocator.alloc(ListenerEntry, self.mock_listeners.len);
        errdefer {
            for (cloned_list) |*l| l.deinit(allocator);
            allocator.free(cloned_list);
        }
        for (self.mock_listeners, 0..) |l, i| {
            cloned_list[i] = try l.clone(allocator);
        }

        return ListenerInspectionResult{
            .listeners = cloned_list,
            .is_permission_limited = self.mock_permission_limited,
        };
    }
};

// -------------------------------------------------------------------------
// EXPOSURE AUDIT ENGINE
// -------------------------------------------------------------------------

/// Evaluates local listening services against expected policy and identifies exposure
pub fn auditLocalExposure(
    allocator: std.mem.Allocator,
    policy: LocalExposurePolicy,
    listener_inspector: ListenerInspector,
) !LocalExposureAuditResult {
    var inspection = try listener_inspector.inspect(allocator);
    defer inspection.deinit(allocator);

    var findings_list = std.ArrayList(LocalExposureFinding).init(allocator);
    errdefer {
        for (findings_list.items) |*f| f.deinit(allocator);
        findings_list.deinit();
    }

    var checks_total: u32 = 0;
    var checks_passed: u32 = 0;
    var wildcard_count: usize = 0;
    var loopback_count: usize = 0;
    var specific_count: usize = 0;

    // 1. Permission limitation verification
    if (inspection.is_permission_limited) {
        checks_total += 1;
        try findings_list.append(.{
            .rule_id = try allocator.dupe(u8, "WS-AUDIT-EXPOSURE-PERMISSION-LIMITED"),
            .title = try allocator.dupe(u8, "Process inspection restricted by OS permissions"),
            .description = try allocator.dupe(u8, "The current user account lacks elevation/administrative rights to map listening sockets to process names and PIDs."),
            .severity = .info,
            .severity_rationale = try allocator.dupe(u8, "Unprivileged execution limits process identity correlation without indicating an immediate vulnerability."),
            .confidence = .confirmed,
            .affected_target = try allocator.dupe(u8, "localhost (process enumeration)"),
            .evidence = try allocator.dupe(u8, "is_permission_limited = true reported by platform listener adapter."),
            .supporting_observations = try allocator.dupe(u8, "Running without administrator/root privileges."),
            .remediation = try allocator.dupe(u8, "Execute WireScope with elevated/administrative privileges if process name and PID verification is required."),
            .false_positive_caveat = try allocator.dupe(u8, "Standard unprivileged behavior on multi-user systems (Windows/Linux/macOS). Incomplete observations must NOT be assumed to mean zero exposure."),
            .limitations = try allocator.dupe(u8, "Process ownership correlation unavailable; socket ports and addresses remain accurately recorded."),
            .context_evaluation = try allocator.dupe(u8, "Permission boundaries enforce security isolation between OS users."),
        });
    }

    // 2. Classify listener bindings and evaluate against policy
    for (inspection.listeners) |l| {
        var pid_buf: [16]u8 = undefined;
        const pid_str = if (l.pid) |p|
            std.fmt.bufPrint(&pid_buf, "{d}", .{p}) catch "-"
        else
            "-";

        switch (l.binding_type) {
            .wildcard => wildcard_count += 1,
            .loopback_only => loopback_count += 1,
            .specific_interface => specific_count += 1,
        }

        // Find if port is in expected_services
        var maybe_expected: ?ExpectedServicePolicy = null;
        for (policy.expected_services) |exp| {
            if (exp.port == l.local_port and std.ascii.eqlIgnoreCase(exp.transport, l.transport)) {
                maybe_expected = exp;
                break;
            }
        }

        checks_total += 1;

        if (maybe_expected) |expected| {
            var listener_ok = true;

            // Check binding constraint
            if (l.binding_type == .wildcard and expected.allowed_binding == .loopback_only) {
                listener_ok = false;
                const is_sensitive_port = (l.local_port == 3306 or l.local_port == 5432 or l.local_port == 6379 or l.local_port == 27017 or l.local_port == 2375);
                const sev: Severity = if (is_sensitive_port) .high else .medium;

                var obs_buf: [256]u8 = undefined;
                const obs_str = std.fmt.bufPrint(
                    &obs_buf,
                    "Proto: {s}, Addr: {s}, Port: {d}, Binding: {s}, PID: {s}, Process: {s}",
                    .{
                        l.transport,
                        l.local_address,
                        l.local_port,
                        l.binding_type.toSlice(),
                        pid_str,
                        l.process_name orelse "-",
                    },
                ) catch "details unavailable";

                try findings_list.append(.{
                    .rule_id = try allocator.dupe(u8, "WS-AUDIT-EXPOSURE-WILDCARD-BINDING"),
                    .title = try std.fmt.allocPrint(allocator, "Service on port {d} exposed on wildcard interface (0.0.0.0 or ::)", .{l.local_port}),
                    .description = try allocator.dupe(u8, "Service is configured with a wildcard binding, exposing it to all network interfaces (Ethernet, Wi-Fi, VPN) instead of loopback."),
                    .severity = sev,
                    .severity_rationale = try allocator.dupe(u8, "Wildcard binding allows external hosts on adjacent networks to reach the service if host firewalls allow ingress."),
                    .confidence = .confirmed,
                    .affected_target = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ l.local_address, l.local_port }),
                    .evidence = try std.fmt.allocPrint(allocator, "Socket bound to {s}:{d} ({s})", .{ l.local_address, l.local_port, l.binding_type.toSlice() }),
                    .supporting_observations = try allocator.dupe(u8, obs_str),
                    .remediation = try std.fmt.allocPrint(allocator, "Reconfigure service to bind explicitly to 127.0.0.1 (localhost) if only local access is required.", .{}),
                    .false_positive_caveat = try allocator.dupe(u8, "Wildcard binding is intentional for public servers (e.g. web/mail servers). Host firewalls (Windows Defender Firewall / iptables) or cloud security groups may independently restrict ingress."),
                    .limitations = try allocator.dupe(u8, "WireScope inspects local socket binding table; does not probe firewall rules or external network barriers."),
                    .context_evaluation = try allocator.dupe(u8, "Expected service policy requires loopback_only, but wildcard observed."),
                });
            }

            // Check process name if specified in policy
            if (expected.expected_process) |exp_proc| {
                if (l.process_name) |proc_name| {
                    if (std.ascii.indexOfIgnoreCase(proc_name, exp_proc) == null) {
                        listener_ok = false;
                        try findings_list.append(.{
                            .rule_id = try allocator.dupe(u8, "WS-AUDIT-EXPOSURE-PROCESS-MISMATCH"),
                            .title = try std.fmt.allocPrint(allocator, "Process mismatch on listening port {d}", .{l.local_port}),
                            .description = try allocator.dupe(u8, "The active process holding the listening port does not match the process name designated in the expected policy."),
                            .severity = .medium,
                            .severity_rationale = try allocator.dupe(u8, "Unexpected processes occupying well-known or service ports may indicate port hijacking, shadow services, or configuration errors."),
                            .confidence = .confirmed,
                            .affected_target = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ l.local_address, l.local_port }),
                            .evidence = try std.fmt.allocPrint(allocator, "Observed process '{s}', expected '{s}'", .{ proc_name, exp_proc }),
                            .supporting_observations = try std.fmt.allocPrint(allocator, "Port {d} owned by PID {s} ({s})", .{ l.local_port, pid_str, proc_name }),
                            .remediation = try allocator.dupe(u8, "Investigate active process and ensure unauthorized applications are terminated."),
                            .false_positive_caveat = try allocator.dupe(u8, "Service wrappers, container forwarders, or alternative server binaries frequently legitimate substitute processes."),
                            .limitations = try allocator.dupe(u8, "Process name matched by substring against self-reported OS process list."),
                            .context_evaluation = try allocator.dupe(u8, "Process name discrepancy detected."),
                        });
                    }
                }
            }

            if (listener_ok) {
                checks_passed += 1;
            }
        } else {
            // Unlisted listener
            if (l.binding_type == .loopback_only and policy.allow_unknown_loopback) {
                // Benign loopback service
                checks_passed += 1;
            } else if (l.binding_type == .wildcard and !policy.allow_unlisted_wildcards) {
                // Unexpected wildcard listener
                const is_sensitive = (l.local_port == 3306 or l.local_port == 5432 or l.local_port == 6379 or l.local_port == 27017 or l.local_port == 2375);
                const sev: Severity = if (is_sensitive) .high else .medium;

                try findings_list.append(.{
                    .rule_id = try allocator.dupe(u8, "WS-AUDIT-EXPOSURE-UNEXPECTED-LISTENER"),
                    .title = try std.fmt.allocPrint(allocator, "Unlisted listening service on wildcard port {d}", .{l.local_port}),
                    .description = try allocator.dupe(u8, "A listening service was detected on a wildcard address that is not documented in the expected services policy."),
                    .severity = sev,
                    .severity_rationale = try allocator.dupe(u8, "Unlisted wildcard listeners expand host attack surface without administrator documentation."),
                    .confidence = .confirmed,
                    .affected_target = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ l.local_address, l.local_port }),
                    .evidence = try std.fmt.allocPrint(allocator, "Unlisted {s} socket on {s}:{d}", .{ l.transport, l.local_address, l.local_port }),
                    .supporting_observations = try std.fmt.allocPrint(allocator, "Address: {s}, Port: {d}, Process: {s}, PID: {s}", .{
                        l.local_address,
                        l.local_port,
                        l.process_name orelse "-",
                        pid_str,
                    }),
                    .remediation = try allocator.dupe(u8, "Verify whether the service is legitimate and add it to expected services policy, or terminate unauthorized listening daemon."),
                    .false_positive_caveat = try allocator.dupe(u8, "No listener is called exploitable solely because it exists. Ephemeral services or newly installed utilities may legitimately listen."),
                    .limitations = try allocator.dupe(u8, "Purely observational socket binding audit; no remote connection or exploit attempts were performed."),
                    .context_evaluation = try allocator.dupe(u8, "Unlisted wildcard listener detected."),
                });
            } else {
                // Unexpected specific interface listener
                try findings_list.append(.{
                    .rule_id = try allocator.dupe(u8, "WS-AUDIT-EXPOSURE-UNEXPECTED-LISTENER"),
                    .title = try std.fmt.allocPrint(allocator, "Unlisted listening service on port {d}", .{l.local_port}),
                    .description = try allocator.dupe(u8, "A listening service was detected on an address that is not documented in the expected services policy."),
                    .severity = .low,
                    .severity_rationale = try allocator.dupe(u8, "Undocumented services increase system complexity and configuration drift."),
                    .confidence = .confirmed,
                    .affected_target = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ l.local_address, l.local_port }),
                    .evidence = try std.fmt.allocPrint(allocator, "Unlisted {s} socket on {s}:{d}", .{ l.transport, l.local_address, l.local_port }),
                    .supporting_observations = try std.fmt.allocPrint(allocator, "Address: {s}, Port: {d}, Process: {s}", .{
                        l.local_address,
                        l.local_port,
                        l.process_name orelse "-",
                    }),
                    .remediation = try allocator.dupe(u8, "Add service to baseline expected policy if required, or disable unneeded background listener."),
                    .false_positive_caveat = try allocator.dupe(u8, "Transient development tools and background OS tasks open listeners that are safe on non-routable interfaces."),
                    .limitations = try allocator.dupe(u8, "Read-only inspection of socket tables."),
                    .context_evaluation = try allocator.dupe(u8, "Listener not present in expected policy."),
                });
            }
        }
    }

    // 3. Check for missing expected services
    for (policy.expected_services) |exp| {
        var found = false;
        for (inspection.listeners) |l| {
            if (l.local_port == exp.port and std.ascii.eqlIgnoreCase(l.transport, exp.transport)) {
                found = true;
                break;
            }
        }

        if (!found) {
            checks_total += 1;
            try findings_list.append(.{
                .rule_id = try allocator.dupe(u8, "WS-AUDIT-EXPOSURE-MISSING-SERVICE"),
                .title = try std.fmt.allocPrint(allocator, "Expected service on port {d} is not running", .{exp.port}),
                .description = try allocator.dupe(u8, "An expected service defined in the local exposure policy was not detected in active listening state."),
                .severity = .info,
                .severity_rationale = try allocator.dupe(u8, "Expected service absence indicates service downtime, delayed daemon startup, or misconfiguration."),
                .confidence = .confirmed,
                .affected_target = try std.fmt.allocPrint(allocator, "port {d}/{s}", .{ exp.port, exp.transport }),
                .evidence = try std.fmt.allocPrint(allocator, "No active listener observed on {s} port {d}", .{ exp.transport, exp.port }),
                .supporting_observations = try allocator.dupe(u8, "Expected service declared in policy missing from listener table."),
                .remediation = try allocator.dupe(u8, "Check service status or start the expected daemon."),
                .false_positive_caveat = try allocator.dupe(u8, "Services using socket activation (e.g. systemd socket activation or on-demand listeners) do not listen until invoked."),
                .limitations = try allocator.dupe(u8, "Snapshot audit at moment of inspection."),
                .context_evaluation = try allocator.dupe(u8, "Expected service missing from socket table."),
            });
        }
    }

    // Clone listeners for result
    var cloned_listeners = try allocator.alloc(ListenerEntry, inspection.listeners.len);
    errdefer {
        for (cloned_listeners) |*l| l.deinit(allocator);
        allocator.free(cloned_listeners);
    }
    for (inspection.listeners, 0..) |l, i| {
        cloned_listeners[i] = try l.clone(allocator);
    }

    const limitations_str = if (inspection.is_permission_limited)
        try allocator.dupe(u8, "Audit is read-only. Process names and PIDs were partially restricted by OS user permissions. Socket binding table inspected without system modifications.")
    else
        try allocator.dupe(u8, "Audit is read-only. Full listener inspection performed without modifying firewall or system settings. No listener is called exploitable solely because it exists.");

    return LocalExposureAuditResult{
        .policy_id = try allocator.dupe(u8, policy.policy_id),
        .is_permission_limited = inspection.is_permission_limited,
        .total_listeners_observed = inspection.listeners.len,
        .wildcard_listeners_count = wildcard_count,
        .loopback_listeners_count = loopback_count,
        .specific_listeners_count = specific_count,
        .listeners = cloned_listeners,
        .findings = try findings_list.toOwnedSlice(),
        .checks_total = checks_total,
        .checks_passed = checks_passed,
        .operational_limitations = limitations_str,
        .elapsed_ns = 1_500_000,
    };
}

// -------------------------------------------------------------------------
// UNIT & CONTROLLED INTEGRATION TESTS
// -------------------------------------------------------------------------

test "exposure audit: controlled listeners conforming to expected policy have zero unexpected findings" {
    const allocator = testing.allocator;

    // Expected policy: 80 and 443 with wildcard, 22 on specific interface
    var exp_services = try allocator.alloc(ExpectedServicePolicy, 3);
    exp_services[0] = .{ .port = 80, .transport = try allocator.dupe(u8, "tcp"), .allowed_binding = .wildcard_allowed };
    exp_services[1] = .{ .port = 443, .transport = try allocator.dupe(u8, "tcp"), .allowed_binding = .wildcard_allowed };
    exp_services[2] = .{ .port = 22, .transport = try allocator.dupe(u8, "tcp"), .allowed_binding = .specific_only };

    var policy = LocalExposurePolicy{
        .policy_id = "test-compliant-policy",
        .allow_unknown_loopback = true,
        .allow_unlisted_wildcards = false,
        .expected_services = exp_services,
    };
    defer policy.deinit(allocator);

    // Mock listeners conforming exactly to policy
    var mock_listeners = try allocator.alloc(ListenerEntry, 3);
    mock_listeners[0] = .{
        .transport = try allocator.dupe(u8, "tcp"),
        .local_address = try allocator.dupe(u8, "0.0.0.0"),
        .local_port = 80,
        .binding_type = .wildcard,
        .pid = 100,
        .process_name = try allocator.dupe(u8, "nginx"),
    };
    mock_listeners[1] = .{
        .transport = try allocator.dupe(u8, "tcp"),
        .local_address = try allocator.dupe(u8, "0.0.0.0"),
        .local_port = 443,
        .binding_type = .wildcard,
        .pid = 100,
        .process_name = try allocator.dupe(u8, "nginx"),
    };
    mock_listeners[2] = .{
        .transport = try allocator.dupe(u8, "tcp"),
        .local_address = try allocator.dupe(u8, "192.168.1.50"),
        .local_port = 22,
        .binding_type = .specific_interface,
        .pid = 200,
        .process_name = try allocator.dupe(u8, "sshd"),
    };
    defer {
        for (mock_listeners) |*l| l.deinit(allocator);
        allocator.free(mock_listeners);
    }

    var mock_inspector = MockListenerInspector{
        .mock_listeners = mock_listeners,
        .mock_permission_limited = false,
    };

    var result = try auditLocalExposure(allocator, policy, mock_inspector.inspector());
    defer result.deinit(allocator);

    try testing.expectEqual(@as(usize, 3), result.total_listeners_observed);
    try testing.expectEqual(@as(usize, 2), result.wildcard_listeners_count);
    try testing.expectEqual(@as(usize, 1), result.specific_listeners_count);
    try testing.expectEqual(@as(usize, 0), result.findings.len);
    try testing.expect(!result.hasHighOrCriticalFindings());
}

test "exposure audit: unexpected wildcard listener includes supporting observations and caveat" {
    const allocator = testing.allocator;

    const policy = LocalExposurePolicy{
        .policy_id = "strict-no-wildcards",
        .allow_unknown_loopback = true,
        .allow_unlisted_wildcards = false,
        .expected_services = &.{},
    };

    var mock_listeners = try allocator.alloc(ListenerEntry, 1);
    mock_listeners[0] = .{
        .transport = try allocator.dupe(u8, "tcp"),
        .local_address = try allocator.dupe(u8, "0.0.0.0"),
        .local_port = 6379,
        .binding_type = .wildcard,
        .pid = 5432,
        .process_name = try allocator.dupe(u8, "redis-server.exe"),
    };
    defer {
        for (mock_listeners) |*l| l.deinit(allocator);
        allocator.free(mock_listeners);
    }

    var mock_inspector = MockListenerInspector{
        .mock_listeners = mock_listeners,
        .mock_permission_limited = false,
    };

    var result = try auditLocalExposure(allocator, policy, mock_inspector.inspector());
    defer result.deinit(allocator);

    try testing.expectEqual(@as(usize, 1), result.findings.len);
    const f = result.findings[0];

    try testing.expectEqualStrings("WS-AUDIT-EXPOSURE-UNEXPECTED-LISTENER", f.rule_id);
    try testing.expectEqual(Severity.high, f.severity); // Sensitive database port 6379
    try testing.expect(std.mem.indexOf(u8, f.supporting_observations, "redis-server.exe") != null);
    try testing.expect(std.mem.indexOf(u8, f.supporting_observations, "5432") != null);
    try testing.expect(std.mem.indexOf(u8, f.false_positive_caveat, "No listener is called exploitable solely because it exists") != null);
}

test "exposure audit: permission limitation is visible and reported" {
    const allocator = testing.allocator;

    const policy = LocalExposurePolicy{
        .policy_id = "permission-test",
    };

    var mock_inspector = MockListenerInspector{
        .mock_listeners = &.{},
        .mock_permission_limited = true,
    };

    var result = try auditLocalExposure(allocator, policy, mock_inspector.inspector());
    defer result.deinit(allocator);

    try testing.expect(result.is_permission_limited);
    try testing.expect(result.findings.len > 0);

    var found_perm = false;
    for (result.findings) |f| {
        if (std.mem.eql(u8, f.rule_id, "WS-AUDIT-EXPOSURE-PERMISSION-LIMITED")) {
            found_perm = true;
            try testing.expectEqual(Severity.info, f.severity);
            try testing.expect(std.mem.indexOf(u8, f.false_positive_caveat, "must NOT be assumed to mean zero exposure") != null);
        }
    }
    try testing.expect(found_perm);
}

test "exposure audit: policy port parser builds ExpectedServicePolicy cleanly" {
    const allocator = testing.allocator;

    var policy = try LocalExposurePolicy.fromExpectedPorts(allocator, "22, 80, 443, 8080");
    defer policy.deinit(allocator);

    try testing.expectEqual(@as(usize, 4), policy.expected_services.len);
    try testing.expectEqual(@as(u16, 22), policy.expected_services[0].port);
    try testing.expectEqual(@as(u16, 80), policy.expected_services[1].port);
    try testing.expectEqual(@as(u16, 443), policy.expected_services[2].port);
    try testing.expectEqual(@as(u16, 8080), policy.expected_services[3].port);
}

test "exposure audit: output rendering formats (terminal, json, markdown)" {
    const allocator = testing.allocator;

    const policy = LocalExposurePolicy{
        .policy_id = "test-format-policy",
    };

    var mock_listeners = try allocator.alloc(ListenerEntry, 1);
    mock_listeners[0] = .{
        .transport = try allocator.dupe(u8, "tcp"),
        .local_address = try allocator.dupe(u8, "127.0.0.1"),
        .local_port = 9000,
        .binding_type = .loopback_only,
        .pid = 1111,
        .process_name = try allocator.dupe(u8, "dev-server"),
    };
    defer {
        for (mock_listeners) |*l| l.deinit(allocator);
        allocator.free(mock_listeners);
    }

    var mock_inspector = MockListenerInspector{
        .mock_listeners = mock_listeners,
        .mock_permission_limited = false,
    };

    var result = try auditLocalExposure(allocator, policy, mock_inspector.inspector());
    defer result.deinit(allocator);

    // Terminal
    var term_buf = std.ArrayList(u8).init(allocator);
    defer term_buf.deinit();
    try result.toTerminal(term_buf.writer());
    try testing.expect(std.mem.indexOf(u8, term_buf.items, "WIRESCOPE LOCAL EXPOSURE AUDIT") != null);
    try testing.expect(std.mem.indexOf(u8, term_buf.items, "LOCAL LISTENING SOCKETS INVENTORY") != null);

    // JSON
    var json_buf = std.ArrayList(u8).init(allocator);
    defer json_buf.deinit();
    try result.toJson(json_buf.writer());
    try testing.expect(std.mem.indexOf(u8, json_buf.items, "\"audit_type\":\"local_exposure_audit\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_buf.items, "\"policy_id\":\"test-format-policy\"") != null);

    // Markdown
    var md_buf = std.ArrayList(u8).init(allocator);
    defer md_buf.deinit();
    try result.toMarkdown(md_buf.writer());
    try testing.expect(std.mem.indexOf(u8, md_buf.items, "# WireScope Local Listening Service Exposure Audit") != null);
    try testing.expect(std.mem.indexOf(u8, md_buf.items, "## Local Listening Sockets") != null);
    try testing.expect(std.mem.indexOf(u8, md_buf.items, "> [!IMPORTANT]") != null);
}
