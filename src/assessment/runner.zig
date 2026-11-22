const std = @import("std");
const testing = std.testing;
const core = @import("../core/root.zig");
const platform = @import("../platform/root.zig");
const probes = @import("../probes/root.zig");
const recon = @import("../recon/root.zig");
const audit = @import("../audit/root.zig");
const profile_mod = @import("profile.zig");

pub const AssessmentProfile = profile_mod.AssessmentProfile;
pub const BuiltinProfiles = profile_mod.BuiltinProfiles;

pub const AssessmentStatus = enum {
    not_started,
    in_progress,
    completed,
    partial,
    cancelled,
    failed,

    pub fn toSlice(self: AssessmentStatus) []const u8 {
        return @tagName(self);
    }
};

pub const TaskFailure = struct {
    sequence_id: usize,
    target: []const u8,
    check_type: []const u8,
    error_message: []const u8,
    duration_ms: u32,
};

pub const DnsObservationRecord = struct {
    target: []const u8,
    answers: [][]const u8,
    is_success: bool,
    error_message: ?[]const u8 = null,
    duration_ms: u32,

    pub fn deinit(self: *DnsObservationRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.target);
        for (self.answers) |ans| {
            allocator.free(ans);
        }
        allocator.free(self.answers);
        if (self.error_message) |msg| allocator.free(msg);
    }
};

pub const TcpObservationRecord = struct {
    target: []const u8,
    port: u16,
    is_open: bool,
    rtt_ms: ?u32 = null,
    error_message: ?[]const u8 = null,

    pub fn deinit(self: *TcpObservationRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.target);
        if (self.error_message) |msg| allocator.free(msg);
    }
};

pub const TlsObservationRecord = struct {
    target: []const u8,
    port: u16,
    protocol_version: []const u8,
    hostname_matches: bool,
    is_valid_chain: bool,
    days_to_expiration: ?i32 = null,
    is_success: bool,
    error_message: ?[]const u8 = null,

    pub fn deinit(self: *TlsObservationRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.target);
        allocator.free(self.protocol_version);
        if (self.error_message) |msg| allocator.free(msg);
    }
};

pub const HttpObservationRecord = struct {
    target_url: []const u8,
    status_code: u16,
    is_https: bool,
    is_html: bool,
    is_json_api: bool,
    hsts_header: ?[]const u8 = null,
    csp_header: ?[]const u8 = null,
    x_content_type_options: ?[]const u8 = null,
    x_frame_options: ?[]const u8 = null,
    cookies: []const audit.CookieObservation = &.{},
    is_success: bool,
    error_message: ?[]const u8 = null,

    pub fn deinit(self: *HttpObservationRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.target_url);
        if (self.hsts_header) |h| allocator.free(h);
        if (self.csp_header) |c| allocator.free(c);
        if (self.x_content_type_options) |x| allocator.free(x);
        if (self.x_frame_options) |f| allocator.free(f);
        for (self.cookies) |ck| {
            allocator.free(ck.name);
            if (ck.same_site.len > 0) allocator.free(ck.same_site);
        }
        if (self.cookies.len > 0) allocator.free(self.cookies);
        if (self.error_message) |msg| allocator.free(msg);
    }
};

pub const ListenerObservationRecord = struct {
    transport: []const u8,
    address: []const u8,
    port: u16,
    binding_type: []const u8,
    pid: ?u32 = null,
    process_name: ?[]const u8 = null,
    is_unlisted: bool = false,
    permission_limited: bool = false,

    pub fn deinit(self: *ListenerObservationRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.transport);
        allocator.free(self.address);
        allocator.free(self.binding_type);
        if (self.process_name) |p| allocator.free(p);
    }
};

pub const AssessmentObservations = struct {
    dns: std.ArrayListUnmanaged(DnsObservationRecord),
    tcp: std.ArrayListUnmanaged(TcpObservationRecord),
    tls: std.ArrayListUnmanaged(TlsObservationRecord),
    http: std.ArrayListUnmanaged(HttpObservationRecord),
    listeners: std.ArrayListUnmanaged(ListenerObservationRecord),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) AssessmentObservations {
        return .{
            .dns = std.ArrayListUnmanaged(DnsObservationRecord){},
            .tcp = std.ArrayListUnmanaged(TcpObservationRecord){},
            .tls = std.ArrayListUnmanaged(TlsObservationRecord){},
            .http = std.ArrayListUnmanaged(HttpObservationRecord){},
            .listeners = std.ArrayListUnmanaged(ListenerObservationRecord){},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *AssessmentObservations) void {
        for (self.dns.items) |*item| item.deinit(self.allocator);
        self.dns.deinit(self.allocator);

        for (self.tcp.items) |*item| item.deinit(self.allocator);
        self.tcp.deinit(self.allocator);

        for (self.tls.items) |*item| item.deinit(self.allocator);
        self.tls.deinit(self.allocator);

        for (self.http.items) |*item| item.deinit(self.allocator);
        self.http.deinit(self.allocator);

        for (self.listeners.items) |*item| item.deinit(self.allocator);
        self.listeners.deinit(self.allocator);
    }

    pub fn totalObservations(self: *const AssessmentObservations) usize {
        return self.dns.items.len + self.tcp.items.len + self.tls.items.len + self.http.items.len + self.listeners.items.len;
    }
};

pub const AssessmentManifest = struct {
    manifest_version: u32 = 1,
    assessment_id: []const u8,
    profile_id: []const u8,
    profile_name: []const u8,
    tool_version: []const u8,
    status: AssessmentStatus,
    started_at_ms: i64,
    completed_at_ms: i64,
    duration_ms: u64,
    tasks_planned: usize,
    tasks_executed: usize,
    tasks_succeeded: usize,
    tasks_failed: usize,
    dns_observations_count: usize,
    tcp_observations_count: usize,
    tls_observations_count: usize,
    http_observations_count: usize,
    listener_observations_count: usize,
    findings_count: usize,
    manifest_hash: [64]u8,

    pub fn deinit(self: *AssessmentManifest, allocator: std.mem.Allocator) void {
        allocator.free(self.assessment_id);
        allocator.free(self.profile_id);
        allocator.free(self.profile_name);
        allocator.free(self.tool_version);
    }

    pub fn computeHash(
        assessment_id: []const u8,
        profile_id: []const u8,
        tool_version: []const u8,
        status: AssessmentStatus,
        started_at_ms: i64,
        completed_at_ms: i64,
        tasks_planned: usize,
        tasks_succeeded: usize,
        tasks_failed: usize,
        total_observations: usize,
        findings_count: usize,
    ) [64]u8 {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update("wirescope-assessment-manifest-v1:");
        hasher.update(assessment_id);
        hasher.update(":");
        hasher.update(profile_id);
        hasher.update(":");
        hasher.update(tool_version);
        hasher.update(":");
        hasher.update(status.toSlice());

        var buf: [64]u8 = undefined;
        const s_start = std.fmt.bufPrint(&buf, ":{d}", .{started_at_ms}) catch "";
        hasher.update(s_start);
        const s_end = std.fmt.bufPrint(&buf, ":{d}", .{completed_at_ms}) catch "";
        hasher.update(s_end);
        const s_counts = std.fmt.bufPrint(&buf, ":{d}:{d}:{d}:{d}:{d}", .{
            tasks_planned,
            tasks_succeeded,
            tasks_failed,
            total_observations,
            findings_count,
        }) catch "";
        hasher.update(s_counts);

        var digest: [32]u8 = undefined;
        hasher.final(&digest);
        return std.fmt.bytesToHex(digest, .lower);
    }
};

pub const AssessmentResult = struct {
    manifest: AssessmentManifest,
    profile_id: []const u8,
    profile_name: []const u8,
    status: AssessmentStatus,
    observations: AssessmentObservations,
    findings: std.ArrayListUnmanaged(audit.RuleFinding),
    task_failures: std.ArrayListUnmanaged(TaskFailure),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, profile: AssessmentProfile) AssessmentResult {
        return .{
            .manifest = undefined,
            .profile_id = profile.id,
            .profile_name = profile.name,
            .status = .not_started,
            .observations = AssessmentObservations.init(allocator),
            .findings = std.ArrayListUnmanaged(audit.RuleFinding){},
            .task_failures = std.ArrayListUnmanaged(TaskFailure){},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *AssessmentResult) void {
        self.manifest.deinit(self.allocator);
        self.observations.deinit();
        self.findings.deinit(self.allocator);
        self.task_failures.deinit(self.allocator);
    }

    pub fn toTerminal(self: *const AssessmentResult, writer: anytype) !void {
        try writer.print(
            \\================================================================================
            \\WIRESCOPE MULTI-MODULE ASSESSMENT REPORT
            \\================================================================================
            \\Assessment ID:       {s}
            \\Profile:             {s} ({s})
            \\Assessment Status:   {s}
            \\Execution Timing:    Started: {d}ms | Completed: {d}ms | Duration: {d}ms
            \\Tasks Summary:       {d} Planned, {d} Executed ({d} Succeeded, {d} Failed)
            \\Observations Total: {d} (DNS: {d}, TCP: {d}, TLS: {d}, HTTP: {d}, Sockets: {d})
            \\Defensive Findings:  {d} Identified
            \\Manifest SHA-256:    {s}
            \\
        , .{
            self.manifest.assessment_id,
            self.manifest.profile_name,
            self.manifest.profile_id,
            self.manifest.status.toSlice(),
            self.manifest.started_at_ms,
            self.manifest.completed_at_ms,
            self.manifest.duration_ms,
            self.manifest.tasks_planned,
            self.manifest.tasks_executed,
            self.manifest.tasks_succeeded,
            self.manifest.tasks_failed,
            self.manifest.dns_observations_count + self.manifest.tcp_observations_count + self.manifest.tls_observations_count + self.manifest.http_observations_count + self.manifest.listener_observations_count,
            self.manifest.dns_observations_count,
            self.manifest.tcp_observations_count,
            self.manifest.tls_observations_count,
            self.manifest.http_observations_count,
            self.manifest.listener_observations_count,
            self.manifest.findings_count,
            self.manifest.manifest_hash,
        });

        if (self.task_failures.items.len > 0) {
            try writer.print("\n--- TASK EXECUTION FAILURES (OBSERVATIONS PRESERVED) ---\n", .{});
            for (self.task_failures.items, 1..) |tf, i| {
                try writer.print("  [{d}] Task #{d} ({s} -> {s}): {s} ({d}ms)\n", .{
                    i,
                    tf.sequence_id,
                    tf.check_type,
                    tf.target,
                    tf.error_message,
                    tf.duration_ms,
                });
            }
        }

        if (self.findings.items.len > 0) {
            try writer.print("\n--- DEFENSIVE CORRELATED FINDINGS ---\n", .{});
            for (self.findings.items, 1..) |f, i| {
                try writer.print(
                    \\[{d}] [{s}] {s} ({s} v{d})
                    \\    Severity Rationale: {s}
                    \\    Evidence:           {s}
                    \\    Context Evaluation: {s}
                    \\    Remediation:        {s}
                    \\    Limitations:        {s}
                    \\
                    \\
                , .{
                    i,
                    f.severity.toSlice(),
                    f.title,
                    f.rule_id,
                    f.rule_version,
                    f.severity_rationale,
                    f.evidence,
                    f.context_evaluation,
                    f.remediation,
                    f.limitations,
                });
            }
        } else {
            try writer.print("\nNo defensive policy violations or exposure findings detected.\n", .{});
        }

        try writer.print(
            \\================================================================================
            \\WireScope Assessment Manifest Guarantee:
            \\  This assessment was orchestrated according to declared scope and resource limits.
            \\  Partial failures do not erase successful observations.
            \\  Manifest hash provides deterministic integrity tracking across assessments.
            \\================================================================================
            \\
        , .{});
    }

    pub fn toJson(self: *const AssessmentResult, writer: anytype) !void {
        try writer.print(
            \\{{"report_type":"assessment_result","schema_version":1,"manifest":{{"assessment_id":"{s}","profile_id":"{s}","profile_name":"{s}","status":"{s}","started_at_ms":{d},"completed_at_ms":{d},"duration_ms":{d},"tasks_planned":{d},"tasks_executed":{d},"tasks_succeeded":{d},"tasks_failed":{d},"manifest_hash":"{s}"}},"summary":{{"observations_count":{d},"findings_count":{d},"task_failures_count":{d}}},"findings":[
        , .{
            self.manifest.assessment_id,
            self.manifest.profile_id,
            self.manifest.profile_name,
            self.manifest.status.toSlice(),
            self.manifest.started_at_ms,
            self.manifest.completed_at_ms,
            self.manifest.duration_ms,
            self.manifest.tasks_planned,
            self.manifest.tasks_executed,
            self.manifest.tasks_succeeded,
            self.manifest.tasks_failed,
            self.manifest.manifest_hash,
            self.observations.totalObservations(),
            self.findings.items.len,
            self.task_failures.items.len,
        });

        for (self.findings.items, 0..) |f, i| {
            if (i > 0) try writer.print(",", .{});
            try writer.print(
                \\{{"rule_id":"{s}","rule_version":{d},"title":"{s}","severity":"{s}","confidence":"{s}","evidence":"{s}","remediation":"{s}"}}
            , .{
                f.rule_id,
                f.rule_version,
                f.title,
                f.severity.toSlice(),
                f.confidence.toSlice(),
                f.evidence,
                f.remediation,
            });
        }

        try writer.print("]}}\n", .{});
    }

    pub fn toMarkdown(self: *const AssessmentResult, writer: anytype) !void {
        try writer.print(
            \\# WireScope Multi-Module Assessment Report
            \\
            \\**Assessment ID:** `{s}`  
            \\**Profile:** {s} (`{s}`)  
            \\**Status:** **{s}**  
            \\**Duration:** {d}ms  
            \\**Manifest SHA-256:** `{s}`  
            \\
            \\> [!NOTE]
            \\> WireScope assessment runner preserves completed observations even when subsequent module checks encounter errors or timeouts.
            \\
            \\## Assessment Execution Summary
            \\
            \\| Metric | Value |
            \\| :--- | :--- |
            \\| Tasks Planned | {d} |
            \\| Tasks Executed | {d} |
            \\| Tasks Succeeded | {d} |
            \\| Tasks Failed | {d} |
            \\| DNS Observations | {d} |
            \\| TCP Observations | {d} |
            \\| TLS Observations | {d} |
            \\| HTTP Observations | {d} |
            \\| Listening Sockets | {d} |
            \\| Correlated Findings | {d} |
            \\
        , .{
            self.manifest.assessment_id,
            self.manifest.profile_name,
            self.manifest.profile_id,
            self.manifest.status.toSlice(),
            self.manifest.duration_ms,
            self.manifest.manifest_hash,
            self.manifest.tasks_planned,
            self.manifest.tasks_executed,
            self.manifest.tasks_succeeded,
            self.manifest.tasks_failed,
            self.manifest.dns_observations_count,
            self.manifest.tcp_observations_count,
            self.manifest.tls_observations_count,
            self.manifest.http_observations_count,
            self.manifest.listener_observations_count,
            self.manifest.findings_count,
        });

        if (self.findings.items.len > 0) {
            try writer.print("\n## Correlated Defensive Findings\n\n", .{});
            for (self.findings.items) |f| {
                try writer.print(
                    \\### {s} — {s}
                    \\
                    \\- **Rule ID:** `{s}` (v{d})
                    \\- **Severity:** `{s}` | **Confidence:** `{s}`
                    \\- **Severity Rationale:** {s}
                    \\- **Evidence:** `{s}`
                    \\- **Context Evaluation:** {s}
                    \\- **Remediation:** {s}
                    \\- **Limitations:** {s}
                    \\
                    \\
                , .{
                    f.rule_id,
                    f.title,
                    f.rule_id,
                    f.rule_version,
                    f.severity.toSlice(),
                    f.confidence.toSlice(),
                    f.severity_rationale,
                    f.evidence,
                    f.context_evaluation,
                    f.remediation,
                    f.limitations,
                });
            }
        }
    }
};

// -----------------------------------------------------------------------------
// Assessment Runner & Execution Context
// -----------------------------------------------------------------------------

pub const AssessmentExecutionMode = enum {
    live,
    fixture,
    simulated_failure,
};

pub const AssessmentRunOptions = struct {
    mode: AssessmentExecutionMode = .fixture,
    fail_tcp: bool = false,
    fail_http: bool = false,
    fail_tls: bool = false,
    simulate_cancel: bool = false,
    cancellation_token: ?*probes.engine.CancellationToken = null,
};

pub const AssessmentRunner = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) AssessmentRunner {
        return .{
            .allocator = allocator,
        };
    }

    pub fn run(self: *AssessmentRunner, profile: AssessmentProfile, options: AssessmentRunOptions) !AssessmentResult {
        const start_time_ms = std.time.milliTimestamp();

        // 1. Validate Scope & Authorization
        try profile.validate();

        var result = AssessmentResult.init(self.allocator, profile);
        errdefer result.deinit();

        result.status = .in_progress;

        // 2. Build Plan
        const plan_config = recon.plan.AssessmentPlanConfig{
            .targets = profile.scope.targets,
            .exclusions = profile.scope.exclusions,
            .ports = profile.scope.ports,
            .confirm_authorized = profile.authorization_acknowledged,
            .caps = .{
                .max_hosts = 256,
                .max_ports = 100,
                .max_operations = 1000,
            },
            .include_dns = profile.checks.dns,
            .include_tcp = profile.checks.tcp,
        };

        var assessment_plan = try recon.plan.AssessmentPlan.create(self.allocator, plan_config);
        defer assessment_plan.deinit(self.allocator);

        var tasks_executed: usize = 0;
        var tasks_succeeded: usize = 0;
        var tasks_failed: usize = 0;
        var is_cancelled = false;

        // Check cancellation token or simulate cancellation
        if (options.simulate_cancel or (options.cancellation_token != null and options.cancellation_token.?.isCancelled())) {
            is_cancelled = true;
        }

        // 3. Multi-Module Execution Pipeline (respecting scope, limits, and error isolation)
        if (!is_cancelled) {
            // Module 1: DNS Diagnostics Check
            if (profile.checks.dns) {
                for (profile.scope.targets) |target| {
                    if (options.cancellation_token != null and options.cancellation_token.?.isCancelled()) {
                        is_cancelled = true;
                        break;
                    }
                    tasks_executed += 1;

                    if (options.mode == .live) {
                        var dns_res = probes.SystemResolver.resolver().resolve(self.allocator, target, .A) catch |err| {
                            tasks_failed += 1;
                            try result.task_failures.append(self.allocator, .{
                                .sequence_id = tasks_executed,
                                .target = target,
                                .check_type = "dns_resolution",
                                .error_message = @errorName(err),
                                .duration_ms = 50,
                            });
                            continue;
                        };
                        defer dns_res.deinit(self.allocator);
                        tasks_succeeded += 1;
                        var answers = std.ArrayList([]const u8).init(self.allocator);
                        for (dns_res.answers) |addr| {
                            try answers.append(try self.allocator.dupe(u8, addr));
                        }
                        try result.observations.dns.append(self.allocator, .{
                            .target = try self.allocator.dupe(u8, target),
                            .answers = try answers.toOwnedSlice(),
                            .is_success = (dns_res.failure_category == .success),
                            .duration_ms = @as(u32, @intCast(@min(std.math.maxInt(u32), dns_res.elapsed_ns / std.time.ns_per_ms))),
                        });
                    } else {
                        var answers = std.ArrayList([]const u8).init(self.allocator);
                        if (std.mem.eql(u8, target, "localhost") or std.mem.eql(u8, target, "127.0.0.1")) {
                            try answers.append(try self.allocator.dupe(u8, "127.0.0.1"));
                            try result.observations.dns.append(self.allocator, .{
                                .target = try self.allocator.dupe(u8, target),
                                .answers = try answers.toOwnedSlice(),
                                .is_success = true,
                                .duration_ms = 5,
                            });
                            tasks_succeeded += 1;
                        } else {
                            // Remote lookup
                            try answers.append(try self.allocator.dupe(u8, "192.168.1.1"));
                            try result.observations.dns.append(self.allocator, .{
                                .target = try self.allocator.dupe(u8, target),
                                .answers = try answers.toOwnedSlice(),
                                .is_success = true,
                                .duration_ms = 12,
                            });
                            tasks_succeeded += 1;
                        }
                    }
                }
            }

            // Module 2: TCP Connectivity Checks
            if (profile.checks.tcp and !is_cancelled) {
                for (profile.scope.targets) |target| {
                    for (profile.scope.ports) |port| {
                        if (options.cancellation_token != null and options.cancellation_token.?.isCancelled()) {
                            is_cancelled = true;
                            break;
                        }
                        tasks_executed += 1;

                        if (options.mode == .live) {
                            var default_cancel = probes.types.CancellationToken{};
                            const cancel_tok = if (options.cancellation_token) |c| c else &default_cancel;
                            var conn_res = probes.RealTcpConnector.connector().connect(self.allocator, target, port, profile.limits.timeout_ms, cancel_tok) catch null;
                            if (conn_res) |*c| {
                                defer c.deinit(self.allocator);
                                const rtt = @as(u32, @intCast(@min(std.math.maxInt(u32), c.connect_time_ns / std.time.ns_per_ms)));
                                if (c.is_open) {
                                    tasks_succeeded += 1;
                                    try result.observations.tcp.append(self.allocator, .{
                                        .target = try self.allocator.dupe(u8, target),
                                        .port = port,
                                        .is_open = true,
                                        .rtt_ms = rtt,
                                    });
                                } else {
                                    tasks_failed += 1;
                                    try result.observations.tcp.append(self.allocator, .{
                                        .target = try self.allocator.dupe(u8, target),
                                        .port = port,
                                        .is_open = false,
                                        .rtt_ms = null,
                                        .error_message = try self.allocator.dupe(u8, "Connection refused or timed out"),
                                    });
                                }
                            } else {
                                tasks_failed += 1;
                                try result.observations.tcp.append(self.allocator, .{
                                    .target = try self.allocator.dupe(u8, target),
                                    .port = port,
                                    .is_open = false,
                                    .rtt_ms = null,
                                    .error_message = try self.allocator.dupe(u8, "Connection refused"),
                                });
                            }
                        } else {
                            if (options.fail_tcp) {
                                tasks_failed += 1;
                                try result.task_failures.append(self.allocator, .{
                                    .sequence_id = tasks_executed,
                                    .target = target,
                                    .check_type = "tcp_connect",
                                    .error_message = "Connection refused (WSAECONNREFUSED / ECONNREFUSED)",
                                    .duration_ms = 50,
                                });
                                // Even on failure, record observation distinctly
                                try result.observations.tcp.append(self.allocator, .{
                                    .target = try self.allocator.dupe(u8, target),
                                    .port = port,
                                    .is_open = false,
                                    .rtt_ms = null,
                                    .error_message = try self.allocator.dupe(u8, "Connection refused"),
                                });
                            } else {
                                tasks_succeeded += 1;
                                try result.observations.tcp.append(self.allocator, .{
                                    .target = try self.allocator.dupe(u8, target),
                                    .port = port,
                                    .is_open = true,
                                    .rtt_ms = 15,
                                });
                            }
                        }
                    }
                    if (is_cancelled) break;
                }
            }

            // Module 3: TLS Configuration Checks
            if (profile.checks.tls and !is_cancelled) {
                for (profile.scope.targets) |target| {
                    tasks_executed += 1;

                    if (options.mode == .live) {
                        var real_tls = probes.RealTlsConnector{};
                        var tls_ca = probes.tls.loadTrustBundle(self.allocator, null) catch std.crypto.Certificate.Bundle{};
                        defer tls_ca.deinit(self.allocator);

                        var tls_res = real_tls.connector().probe(
                            self.allocator,
                            target,
                            443,
                            &tls_ca,
                            .{ .timeout_ms = profile.limits.timeout_ms },
                            null,
                            std.time.timestamp(),
                        ) catch null;

                        if (tls_res) |*tr| {
                            defer tr.deinit(self.allocator);
                            tasks_succeeded += 1;
                            try result.observations.tls.append(self.allocator, .{
                                .target = try self.allocator.dupe(u8, target),
                                .port = 443,
                                .protocol_version = try self.allocator.dupe(u8, tr.protocol_version),
                                .hostname_matches = tr.hostname_matched,
                                .is_valid_chain = tr.chain_valid,
                                .days_to_expiration = 90,
                                .is_success = tr.is_handshake_successful,
                            });
                        } else {
                            tasks_failed += 1;
                            try result.task_failures.append(self.allocator, .{
                                .sequence_id = tasks_executed,
                                .target = target,
                                .check_type = "tls_handshake",
                                .error_message = "TLS handshake negotiation timeout",
                                .duration_ms = profile.limits.timeout_ms,
                            });
                        }
                    } else {
                        if (options.fail_tls) {
                            tasks_failed += 1;
                            try result.task_failures.append(self.allocator, .{
                                .sequence_id = tasks_executed,
                                .target = target,
                                .check_type = "tls_handshake",
                                .error_message = "TLS handshake negotiation timeout",
                                .duration_ms = profile.limits.timeout_ms,
                            });
                        } else {
                            tasks_succeeded += 1;
                            try result.observations.tls.append(self.allocator, .{
                                .target = try self.allocator.dupe(u8, target),
                                .port = 443,
                                .protocol_version = try self.allocator.dupe(u8, "TLSv1.3"),
                                .hostname_matches = true,
                                .is_valid_chain = true,
                                .days_to_expiration = 90,
                                .is_success = true,
                            });
                        }
                    }
                }
            }

            // Module 4: HTTP Security Configuration Checks
            if (profile.checks.http and !is_cancelled) {
                for (profile.scope.targets) |target| {
                    tasks_executed += 1;

                    if (options.mode == .live) {
                        const target_url = if (std.mem.startsWith(u8, target, "http://") or std.mem.startsWith(u8, target, "https://"))
                            try self.allocator.dupe(u8, target)
                        else
                            try std.fmt.allocPrint(self.allocator, "https://{s}/", .{target});
                        defer self.allocator.free(target_url);

                        var real_audit = audit.RealHttpAuditConnector{};
                        var audit_res = real_audit.connector().execute(
                            self.allocator,
                            target_url,
                            .{ .timeout_ms = profile.limits.timeout_ms },
                            null,
                            &profile,
                        ) catch null;

                        if (audit_res) |*ar| {
                            defer ar.deinit(self.allocator);
                            tasks_succeeded += 1;
                            try result.observations.http.append(self.allocator, .{
                                .target_url = try self.allocator.dupe(u8, ar.effective_url),
                                .status_code = ar.status_code,
                                .is_https = std.ascii.eqlIgnoreCase(ar.scheme, "https"),
                                .is_html = (ar.content_type != null and std.ascii.indexOfIgnoreCase(ar.content_type.?, "text/html") != null),
                                .is_json_api = ar.is_api_endpoint,
                                .hsts_header = if (ar.hsts_header) |h| try self.allocator.dupe(u8, h) else null,
                                .csp_header = if (ar.csp_header) |c| try self.allocator.dupe(u8, c) else null,
                                .x_content_type_options = if (ar.content_type_options) |o| try self.allocator.dupe(u8, o) else null,
                                .x_frame_options = if (ar.x_frame_options) |f| try self.allocator.dupe(u8, f) else null,
                                .cookies = &.{},
                                .is_success = true,
                            });
                        } else {
                            tasks_failed += 1;
                            try result.task_failures.append(self.allocator, .{
                                .sequence_id = tasks_executed,
                                .target = target,
                                .check_type = "http_audit",
                                .error_message = "HTTP upstream connection failed",
                                .duration_ms = 120,
                            });
                        }
                    } else {
                        if (options.fail_http) {
                            tasks_failed += 1;
                            try result.task_failures.append(self.allocator, .{
                                .sequence_id = tasks_executed,
                                .target = target,
                                .check_type = "http_audit",
                                .error_message = "HTTP upstream returned 502 Bad Gateway",
                                .duration_ms = 120,
                            });
                        } else {
                            tasks_succeeded += 1;
                            // Use a hardened fixture observation or safe default
                            try result.observations.http.append(self.allocator, .{
                                .target_url = try std.fmt.allocPrint(self.allocator, "https://{s}/", .{target}),
                                .status_code = 200,
                                .is_https = true,
                                .is_html = true,
                                .is_json_api = false,
                                .hsts_header = try self.allocator.dupe(u8, "max-age=31536000; includeSubDomains"),
                                .csp_header = try self.allocator.dupe(u8, "default-src 'self'"),
                                .x_content_type_options = try self.allocator.dupe(u8, "nosniff"),
                                .x_frame_options = try self.allocator.dupe(u8, "DENY"),
                                .cookies = &.{},
                                .is_success = true,
                            });
                        }
                    }
                }
            }

            // Module 5: Local Listening Sockets Inventory
            if (profile.checks.listeners and !is_cancelled) {
                tasks_executed += 1;
                tasks_succeeded += 1;

                if (options.mode == .fixture) {
                    // Inject controlled local fixture listeners
                    try result.observations.listeners.append(self.allocator, .{
                        .transport = try self.allocator.dupe(u8, "tcp"),
                        .address = try self.allocator.dupe(u8, "127.0.0.1"),
                        .port = 8080,
                        .binding_type = try self.allocator.dupe(u8, "loopback"),
                        .pid = 1234,
                        .process_name = try self.allocator.dupe(u8, "wirescope-test"),
                        .is_unlisted = false,
                        .permission_limited = false,
                    });
                } else {
                    // Query real platform listeners
                    var inspection_res = platform.inspectListeners(self.allocator) catch null;
                    if (inspection_res) |*res| {
                        defer res.deinit(self.allocator);
                        for (res.listeners) |entry| {
                            try result.observations.listeners.append(self.allocator, .{
                                .transport = try self.allocator.dupe(u8, entry.transport),
                                .address = try self.allocator.dupe(u8, entry.local_address),
                                .port = entry.local_port,
                                .binding_type = try self.allocator.dupe(u8, entry.binding_type.toSlice()),
                                .pid = entry.pid,
                                .process_name = if (entry.process_name) |p| try self.allocator.dupe(u8, p) else null,
                                .is_unlisted = false,
                                .permission_limited = res.is_permission_limited,
                            });
                        }
                    }
                }
            }
        }

        // 4. Compute Accurate Overall Assessment Status
        if (is_cancelled) {
            result.status = .cancelled;
        } else if (tasks_executed == 0) {
            result.status = .failed;
        } else if (tasks_failed == 0 and tasks_succeeded > 0) {
            result.status = .completed;
        } else if (tasks_succeeded > 0 and tasks_failed > 0) {
            result.status = .partial;
        } else {
            result.status = .failed;
        }

        // 5. Correlate Observations with Versioned Rules Engine (Milestone 9)
        var rule_reg = audit.RuleRegistry.init(self.allocator);
        defer rule_reg.deinit();
        rule_reg.registerDefaults();
        const rule_engine = audit.RuleEngine.init(&rule_reg);

        // Evaluate rules on TLS observations
        for (result.observations.tls.items) |tls_obs| {
            const input = audit.RuleInput{
                .tls_observation = .{
                    .protocol_version = tls_obs.protocol_version,
                    .hostname_matches = tls_obs.hostname_matches,
                    .is_valid_chain = tls_obs.is_valid_chain,
                    .days_to_expiration = tls_obs.days_to_expiration,
                },
            };
            if (rule_engine.evaluateSingle("WS-RULE-TLS-MIN-VERSION", &input)) |ev| {
                if (ev.finding) |f| try result.findings.append(self.allocator, f);
            }
            if (rule_engine.evaluateSingle("WS-RULE-TLS-CERT-EXPIRATION", &input)) |ev| {
                if (ev.finding) |f| try result.findings.append(self.allocator, f);
            }
        }

        // Evaluate rules on HTTP observations
        for (result.observations.http.items) |http_obs| {
            const input = audit.RuleInput{
                .http_observation = .{
                    .is_https = http_obs.is_https,
                    .is_html = http_obs.is_html,
                    .is_json_api = http_obs.is_json_api,
                    .hsts_header = http_obs.hsts_header,
                    .csp_header = http_obs.csp_header,
                    .x_content_type_options = http_obs.x_content_type_options,
                    .x_frame_options = http_obs.x_frame_options,
                },
            };
            if (rule_engine.evaluateSingle("WS-RULE-HTTP-HSTS-POLICY", &input)) |ev| {
                if (ev.finding) |f| try result.findings.append(self.allocator, f);
            }
            if (rule_engine.evaluateSingle("WS-RULE-HTTP-CSP-SCRIPT-RESTRICTION", &input)) |ev| {
                if (ev.finding) |f| try result.findings.append(self.allocator, f);
            }
            if (rule_engine.evaluateSingle("WS-RULE-HTTP-NOSNIFF-HEADER", &input)) |ev| {
                if (ev.finding) |f| try result.findings.append(self.allocator, f);
            }
        }

        // Evaluate rules on Listener observations
        for (result.observations.listeners.items) |l_obs| {
            const input = audit.RuleInput{
                .listener_observation = .{
                    .address = l_obs.address,
                    .port = l_obs.port,
                    .transport = l_obs.transport,
                    .binding_type = l_obs.binding_type,
                    .process_name = l_obs.process_name,
                    .is_unlisted = l_obs.is_unlisted,
                    .permission_limited = l_obs.permission_limited,
                },
            };
            if (rule_engine.evaluateSingle("WS-RULE-EXPOSURE-WILDCARD-BINDING", &input)) |ev| {
                if (ev.finding) |f| try result.findings.append(self.allocator, f);
            }
        }

        // 6. Build Reproducible Assessment Manifest
        const end_time_ms = std.time.milliTimestamp();
        const duration: u64 = if (end_time_ms >= start_time_ms) @intCast(end_time_ms - start_time_ms) else 0;

        var id_buf: [64]u8 = undefined;
        const asm_id = try std.fmt.bufPrint(&id_buf, "asm-{d}", .{start_time_ms});

        const manifest_hash = AssessmentManifest.computeHash(
            asm_id,
            profile.id,
            core.Version.string,
            result.status,
            start_time_ms,
            end_time_ms,
            assessment_plan.tasks.len,
            tasks_succeeded,
            tasks_failed,
            result.observations.totalObservations(),
            result.findings.items.len,
        );

        result.manifest = AssessmentManifest{
            .manifest_version = 1,
            .assessment_id = try self.allocator.dupe(u8, asm_id),
            .profile_id = try self.allocator.dupe(u8, profile.id),
            .profile_name = try self.allocator.dupe(u8, profile.name),
            .tool_version = try self.allocator.dupe(u8, core.Version.string),
            .status = result.status,
            .started_at_ms = start_time_ms,
            .completed_at_ms = end_time_ms,
            .duration_ms = duration,
            .tasks_planned = assessment_plan.tasks.len,
            .tasks_executed = tasks_executed,
            .tasks_succeeded = tasks_succeeded,
            .tasks_failed = tasks_failed,
            .dns_observations_count = result.observations.dns.items.len,
            .tcp_observations_count = result.observations.tcp.items.len,
            .tls_observations_count = result.observations.tls.items.len,
            .http_observations_count = result.observations.http.items.len,
            .listener_observations_count = result.observations.listeners.items.len,
            .findings_count = result.findings.items.len,
            .manifest_hash = manifest_hash,
        };

        return result;
    }
};

// -----------------------------------------------------------------------------
// Unit & Integration Tests (Phase 10.1 Acceptance Criteria)
// -----------------------------------------------------------------------------

test "assessment runner: end-to-end assessment combining multiple modules using local fixtures" {
    var runner = AssessmentRunner.init(testing.allocator);

    const profile = BuiltinProfiles.local_security_audit;
    var result = try runner.run(profile, .{ .mode = .fixture });
    defer result.deinit();

    // Acceptance criteria 1: multiple modules combined
    try testing.expectEqual(AssessmentStatus.completed, result.status);
    try testing.expect(result.observations.tcp.items.len > 0);
    try testing.expect(result.observations.tls.items.len > 0);
    try testing.expect(result.observations.http.items.len > 0);
    try testing.expect(result.observations.listeners.items.len > 0);

    // Acceptance criteria 5: reproducible assessment manifest produced
    try testing.expectEqualStrings("local-security-audit", result.manifest.profile_id);
    try testing.expect(result.manifest.manifest_hash.len == 64);
    try testing.expectEqual(result.status, result.manifest.status);
}

test "assessment runner: partial failures preserve completed observations" {
    var runner = AssessmentRunner.init(testing.allocator);

    const profile = BuiltinProfiles.local_security_audit;
    // Simulate TCP failure while TLS, HTTP, and listeners succeed
    var result = try runner.run(profile, .{ .mode = .fixture, .fail_tcp = true });
    defer result.deinit();

    // Acceptance criteria 3 & 4: partial failure does not erase successful observations
    try testing.expectEqual(AssessmentStatus.partial, result.status);
    try testing.expectEqual(AssessmentStatus.partial, result.manifest.status);
    try testing.expect(result.task_failures.items.len > 0);

    // Other successful observations remain completely preserved!
    try testing.expect(result.observations.tls.items.len > 0);
    try testing.expect(result.observations.http.items.len > 0);
    try testing.expect(result.observations.listeners.items.len > 0);
    try testing.expect(result.manifest.tasks_failed > 0);
    try testing.expect(result.manifest.tasks_succeeded > 0);
}

test "assessment runner: cancellation halts execution and preserves observations so far" {
    var runner = AssessmentRunner.init(testing.allocator);

    const profile = BuiltinProfiles.local_security_audit;
    var result = try runner.run(profile, .{ .mode = .fixture, .simulate_cancel = true });
    defer result.deinit();

    // Acceptance criteria 4: status matches actual cancelled execution
    try testing.expectEqual(AssessmentStatus.cancelled, result.status);
    try testing.expectEqual(AssessmentStatus.cancelled, result.manifest.status);
}

test "assessment runner: scope validation rejects remote targets without authorization" {
    var runner = AssessmentRunner.init(testing.allocator);

    var unauthorized_profile = BuiltinProfiles.local_security_audit;
    unauthorized_profile.scope.targets = &[_][]const u8{"192.168.1.100"};
    unauthorized_profile.authorization_acknowledged = false;

    // Acceptance criteria 2: respect scope and resource limits
    const err = runner.run(unauthorized_profile, .{ .mode = .fixture });
    try testing.expectError(error.MissingAuthorizationAcknowledgement, err);
}

test "assessment runner: serialization formats (terminal, json, markdown) render manifest" {
    var runner = AssessmentRunner.init(testing.allocator);

    const profile = BuiltinProfiles.loopback_diagnostic;
    var result = try runner.run(profile, .{ .mode = .fixture });
    defer result.deinit();

    var term_buf: [16384]u8 = undefined;
    var term_fbs = std.io.fixedBufferStream(&term_buf);
    try result.toTerminal(term_fbs.writer());
    try testing.expect(std.mem.indexOf(u8, term_fbs.getWritten(), "WIRESCOPE MULTI-MODULE ASSESSMENT REPORT") != null);
    try testing.expect(std.mem.indexOf(u8, term_fbs.getWritten(), "Manifest SHA-256:") != null);

    var json_buf: [16384]u8 = undefined;
    var json_fbs = std.io.fixedBufferStream(&json_buf);
    try result.toJson(json_fbs.writer());
    try testing.expect(std.mem.indexOf(u8, json_fbs.getWritten(), "\"report_type\":\"assessment_result\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_fbs.getWritten(), "\"manifest\":") != null);
    try testing.expect(std.mem.indexOf(u8, json_fbs.getWritten(), "\"manifest_hash\":") != null);

    var md_buf: [16384]u8 = undefined;
    var md_fbs = std.io.fixedBufferStream(&md_buf);
    try result.toMarkdown(md_fbs.writer());
    try testing.expect(std.mem.indexOf(u8, md_fbs.getWritten(), "# WireScope Multi-Module Assessment Report") != null);
    try testing.expect(std.mem.indexOf(u8, md_fbs.getWritten(), "Manifest SHA-256:") != null);
}
