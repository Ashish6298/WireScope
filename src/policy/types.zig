const std = @import("std");
const core_models = @import("../core/models.zig");
pub const Severity = core_models.Severity;

/// 4-state policy outcome (Acceptance criteria: pass, fail, inconclusive, not-applicable)
pub const PolicyOutcome = enum {
    pass,
    fail,
    inconclusive,
    not_applicable,

    pub fn toSlice(self: PolicyOutcome) []const u8 {
        return @tagName(self);
    }
};

/// Expected services and ports policy
pub const ExpectedServicesPolicy = struct {
    policy_id: []const u8 = "WS-POL-SERVICES",
    version: u32 = 1,
    allowed_ports: []const u16 = &.{},
    disallow_unlisted_ports: bool = true,
    require_tls_on_ports: []const u16 = &.{ 443, 8443 },
};

/// TLS configuration requirements policy
pub const TlsPolicyRequirements = struct {
    policy_id: []const u8 = "WS-POL-TLS",
    version: u32 = 1,
    min_version: []const u8 = "TLSv1.2",
    require_valid_chain: bool = true,
    require_hostname_match: bool = true,
    min_days_to_expiration: u32 = 14,
};

/// HTTP security configuration requirements policy
pub const HttpPolicyRequirements = struct {
    policy_id: []const u8 = "WS-POL-HTTP",
    version: u32 = 1,
    require_https: bool = true,
    require_hsts: bool = true,
    min_hsts_max_age: u32 = 15552000, // 180 days
    require_csp: bool = true,
    disallow_unsafe_csp: bool = true,
    require_nosniff: bool = true,
    require_frame_options: bool = true,
};

/// Local listening service exposure policy
pub const ExposurePolicyRequirements = struct {
    policy_id: []const u8 = "WS-POL-EXPOSURE",
    version: u32 = 1,
    disallow_wildcards: bool = true,
    allowed_listener_ports: []const u16 = &.{},
    require_loopback_only: bool = false,
};

/// Versioned composite defensive security policy definition
pub const PolicyDefinition = struct {
    policy_id: []const u8 = "WS-POL-DEFENSIVE-DEFAULT",
    version: u32 = 1,
    schema_version: u32 = 1,
    name: []const u8 = "Default Defensive Security Policy",
    description: []const u8 = "Baseline requirements for TLS, HTTP headers, expected services, and listener exposure.",
    strict_mode: bool = true,
    expected_services: ?ExpectedServicesPolicy = null,
    tls: ?TlsPolicyRequirements = null,
    http: ?HttpPolicyRequirements = null,
    exposure: ?ExposurePolicyRequirements = null,
};

/// Result of evaluating an individual policy rule against a stored observation
pub const PolicyRuleEvaluation = struct {
    rule_id: []const u8,
    rule_version: u32,
    domain: []const u8,
    target: []const u8,
    requirement: []const u8,
    outcome: PolicyOutcome,
    severity: Severity,
    observed: []const u8,
    expected: []const u8,
    explanation: []const u8,

    pub fn deinit(self: *PolicyRuleEvaluation, allocator: std.mem.Allocator) void {
        allocator.free(self.rule_id);
        allocator.free(self.domain);
        allocator.free(self.target);
        allocator.free(self.requirement);
        allocator.free(self.observed);
        allocator.free(self.expected);
        allocator.free(self.explanation);
    }
};

/// Composite report produced by evaluating policies against stored observations
pub const PolicyEvaluationReport = struct {
    allocator: std.mem.Allocator,
    policy_id: []const u8,
    policy_version: u32,
    evaluated_at_ms: i64,
    is_offline: bool = true,
    total_evaluated: usize = 0,
    passed_count: usize = 0,
    failed_count: usize = 0,
    inconclusive_count: usize = 0,
    not_applicable_count: usize = 0,
    evaluations: std.ArrayListUnmanaged(PolicyRuleEvaluation) = .{},

    pub fn deinit(self: *PolicyEvaluationReport) void {
        self.allocator.free(self.policy_id);
        for (self.evaluations.items) |*ev| {
            ev.deinit(self.allocator);
        }
        self.evaluations.deinit(self.allocator);
    }

    /// Evaluates overall compliance. Inconclusive checks do not silently pass!
    pub fn isCompliant(self: *const PolicyEvaluationReport) bool {
        return self.failed_count == 0 and self.inconclusive_count == 0;
    }

    /// Maps policy outcome to documented CLI exit codes:
    /// - 0: Success (all checks passed or not applicable)
    /// - 1: Findings or violations detected (one or more failed or inconclusive checks)
    pub fn toExitCode(self: *const PolicyEvaluationReport) u8 {
        if (self.isCompliant()) {
            return 0; // ExitCodes.success
        }
        return 1; // ExitCodes.findings_or_violations
    }

    pub fn toTerminal(self: *const PolicyEvaluationReport, writer: anytype) !void {
        try writer.print(
            \\================================================================================
            \\WIRESCOPE OFFLINE POLICY EVALUATION REPORT
            \\================================================================================
            \\Policy ID:            {s} (v{d})
            \\Evaluation Mode:      Offline (Stored Observations, Zero Network Calls)
            \\Overall Compliance:   {s}
            \\Exit Code:            {d}
            \\
            \\Summary Metrics:
            \\  Total Evaluated:    {d}
            \\  Passed:             {d}
            \\  Failed:             {d}
            \\  Inconclusive:       {d}
            \\  Not Applicable:     {d}
            \\
            \\Rule Evaluations:
            \\  Outcome    Severity  Domain     Rule ID                 Target
            \\  --------------------------------------------------------------------------------
            \\
        , .{
            self.policy_id,
            self.policy_version,
            if (self.isCompliant()) "COMPLIANT" else "NON-COMPLIANT",
            self.toExitCode(),
            self.total_evaluated,
            self.passed_count,
            self.failed_count,
            self.inconclusive_count,
            self.not_applicable_count,
        });

        for (self.evaluations.items) |ev| {
            const out_str = switch (ev.outcome) {
                .pass => "PASS",
                .fail => "FAIL",
                .inconclusive => "INCONCL",
                .not_applicable => "N/A",
            };

            try writer.print("  {s:<10} {s:<9} {s:<10} {s:<23} {s}\n", .{
                out_str,
                ev.severity.toSlice(),
                ev.domain,
                ev.rule_id,
                ev.target,
            });
            try writer.print("             Expected: {s}\n", .{ev.expected});
            try writer.print("             Observed: {s}\n", .{ev.observed});
            if (ev.outcome != .pass) {
                try writer.print("             Detail:   {s}\n", .{ev.explanation});
            }
        }

        try writer.print(
            \\================================================================================
            \\Offline Evaluation Invariant:
            \\  Policy evaluation executes entirely offline over stored observations.
            \\  Inconclusive checks do NOT silently count as pass.
            \\================================================================================
            \\
        , .{});
    }

    pub fn toJson(self: *const PolicyEvaluationReport, writer: anytype) !void {
        try writer.print(
            \\{{"report_type":"policy_evaluation","schema_version":1,"policy_id":"{s}","policy_version":{d},"evaluated_at_ms":{d},"is_offline":true,"is_compliant":{s},"exit_code":{d},"summary":{{"total":{d},"passed":{d},"failed":{d},"inconclusive":{d},"not_applicable":{d}}},"evaluations":[
        , .{
            self.policy_id,
            self.policy_version,
            self.evaluated_at_ms,
            if (self.isCompliant()) "true" else "false",
            self.toExitCode(),
            self.total_evaluated,
            self.passed_count,
            self.failed_count,
            self.inconclusive_count,
            self.not_applicable_count,
        });

        for (self.evaluations.items, 0..) |ev, idx| {
            if (idx > 0) try writer.print(",", .{});
            try writer.print(
                \\{{"rule_id":"{s}","rule_version":{d},"domain":"{s}","target":"{s}","requirement":"{s}","outcome":"{s}","severity":"{s}","observed":"{s}","expected":"{s}","explanation":"{s}"}}
            , .{
                ev.rule_id,
                ev.rule_version,
                ev.domain,
                ev.target,
                ev.requirement,
                ev.outcome.toSlice(),
                ev.severity.toSlice(),
                ev.observed,
                ev.expected,
                ev.explanation,
            });
        }

        try writer.print("]}}\n", .{});
    }

    pub fn toMarkdown(self: *const PolicyEvaluationReport, writer: anytype) !void {
        try writer.print(
            \\# WireScope Offline Policy Evaluation Report
            \\
            \\**Policy:** `{s}` (v{d})  
            \\**Status:** {s}  
            \\**Mode:** Offline (Zero Network Activity)  
            \\**Exit Code:** `{d}`  
            \\
            \\> [!NOTE]
            \\> Evaluated offline against stored observations. Inconclusive checks do not silently pass.
            \\
            \\| Metric | Count |
            \\| :--- | :---: |
            \\| **Total Evaluated** | {d} |
            \\| **Passed** | {d} |
            \\| **Failed** | {d} |
            \\| **Inconclusive** | {d} |
            \\| **Not Applicable** | {d} |
            \\
            \\## Rule Evaluations
            \\
            \\| Outcome | Severity | Domain | Rule ID | Target | Details |
            \\| :--- | :--- | :--- | :--- | :--- | :--- |
            \\
        , .{
            self.policy_id,
            self.policy_version,
            if (self.isCompliant()) "**COMPLIANT**" else "**NON-COMPLIANT**",
            self.toExitCode(),
            self.total_evaluated,
            self.passed_count,
            self.failed_count,
            self.inconclusive_count,
            self.not_applicable_count,
        });

        for (self.evaluations.items) |ev| {
            try writer.print("| `{s}` | `{s}` | {s} | `{s}` | {s} | {s} |\n", .{
                ev.outcome.toSlice(),
                ev.severity.toSlice(),
                ev.domain,
                ev.rule_id,
                ev.target,
                ev.explanation,
            });
        }
    }
};

/// Built-in versioned policy presets
pub const BuiltinPolicies = struct {
    pub const local_hardened = PolicyDefinition{
        .policy_id = "WS-POL-LOCAL-HARDENED",
        .version = 1,
        .schema_version = 1,
        .name = "Local Hardened Defensive Policy",
        .description = "Strict defensive baseline: TLS 1.2+, HSTS, CSP, nosniff, frame protection, and no wildcards.",
        .strict_mode = true,
        .expected_services = .{
            .policy_id = "WS-POL-EXP-SERVICES",
            .version = 1,
            .allowed_ports = &.{ 80, 443, 8080, 8443 },
            .disallow_unlisted_ports = true,
            .require_tls_on_ports = &.{ 443, 8443 },
        },
        .tls = .{
            .policy_id = "WS-POL-TLS",
            .version = 1,
            .min_version = "TLSv1.2",
            .require_valid_chain = true,
            .require_hostname_match = true,
            .min_days_to_expiration = 14,
        },
        .http = .{
            .policy_id = "WS-POL-HTTP",
            .version = 1,
            .require_https = true,
            .require_hsts = true,
            .min_hsts_max_age = 15552000,
            .require_csp = true,
            .disallow_unsafe_csp = true,
            .require_nosniff = true,
            .require_frame_options = true,
        },
        .exposure = .{
            .policy_id = "WS-POL-EXPOSURE",
            .version = 1,
            .disallow_wildcards = true,
            .allowed_listener_ports = &.{ 80, 443, 8080, 8443 },
            .require_loopback_only = false,
        },
    };

    pub const loopback_diagnostic = PolicyDefinition{
        .policy_id = "WS-POL-LOOPBACK-DIAG",
        .version = 1,
        .schema_version = 1,
        .name = "Loopback Diagnostic Policy",
        .description = "Permissive local loopback verification policy.",
        .strict_mode = false,
        .exposure = .{
            .policy_id = "WS-POL-LOOPBACK-EXP",
            .version = 1,
            .disallow_wildcards = true,
            .allowed_listener_ports = &.{ 80, 443, 8080, 8443 },
            .require_loopback_only = true,
        },
    };
};
