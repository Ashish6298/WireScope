const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const runner = @import("../assessment/runner.zig");
const baseline_mod = @import("../assessment/baseline.zig");
const core_models = @import("../core/models.zig");

pub const PolicyOutcome = types.PolicyOutcome;
pub const PolicyDefinition = types.PolicyDefinition;
pub const PolicyEvaluationReport = types.PolicyEvaluationReport;
pub const PolicyRuleEvaluation = types.PolicyRuleEvaluation;
pub const BuiltinPolicies = types.BuiltinPolicies;

/// Offline Policy Evaluator: Evaluates stored observations or baselines
/// against versioned defensive policies with ZERO network activity.
pub const OfflinePolicyEvaluator = struct {
    allocator: std.mem.Allocator,
    policy: PolicyDefinition,

    pub fn init(allocator: std.mem.Allocator, policy: PolicyDefinition) OfflinePolicyEvaluator {
        return .{
            .allocator = allocator,
            .policy = policy,
        };
    }

    /// Evaluates stored assessment observations completely offline
    pub fn evaluateObservations(
        self: *OfflinePolicyEvaluator,
        observations: *const runner.AssessmentObservations,
        target_context: ?[]const u8,
    ) !PolicyEvaluationReport {
        const default_target = target_context orelse "stored-observations";
        var report = PolicyEvaluationReport{
            .allocator = self.allocator,
            .policy_id = try self.allocator.dupe(u8, self.policy.policy_id),
            .policy_version = self.policy.version,
            .evaluated_at_ms = std.time.milliTimestamp(),
            .is_offline = true,
        };
        errdefer report.deinit();

        // 1. Evaluate Expected Services & Ports Policy
        if (self.policy.expected_services) |svc_pol| {
            if (observations.tcp.items.len == 0) {
                // Inconclusive: Required check has no observation data
                try self.appendEvaluation(&report, .{
                    .rule_id = "WS-RULE-POLICY-EXPECTED-PORTS",
                    .rule_version = svc_pol.version,
                    .domain = "services",
                    .target = default_target,
                    .requirement = "Verify reachable ports conform to expected services policy",
                    .outcome = .inconclusive,
                    .severity = .medium,
                    .observed = "No stored TCP port observations available",
                    .expected = "Stored TCP reachability observations",
                    .explanation = "No stored TCP port observations found for target. Inconclusive checks do not silently pass.",
                });
            } else {
                for (observations.tcp.items) |tcp_obs| {
                    if (tcp_obs.is_open) {
                        var is_allowed = false;
                        for (svc_pol.allowed_ports) |p| {
                            if (p == tcp_obs.port) {
                                is_allowed = true;
                                break;
                            }
                        }

                        if (is_allowed or svc_pol.allowed_ports.len == 0) {
                            var buf: [64]u8 = undefined;
                            const obs_str = std.fmt.bufPrint(&buf, "Port {d}/tcp open (allowed)", .{tcp_obs.port}) catch "open";
                            try self.appendEvaluation(&report, .{
                                .rule_id = "WS-RULE-POLICY-EXPECTED-PORTS",
                                .rule_version = svc_pol.version,
                                .domain = "services",
                                .target = tcp_obs.target,
                                .requirement = "Verify reachable ports are documented in approved service policy",
                                .outcome = .pass,
                                .severity = .info,
                                .observed = obs_str,
                                .expected = "Approved open port in policy",
                                .explanation = "Observed open port matches expected service policy.",
                            });
                        } else if (svc_pol.disallow_unlisted_ports) {
                            var buf: [64]u8 = undefined;
                            const obs_str = std.fmt.bufPrint(&buf, "Port {d}/tcp open (unapproved)", .{tcp_obs.port}) catch "unapproved";
                            try self.appendEvaluation(&report, .{
                                .rule_id = "WS-RULE-POLICY-EXPECTED-PORTS",
                                .rule_version = svc_pol.version,
                                .domain = "services",
                                .target = tcp_obs.target,
                                .requirement = "Disallow unexpected or unapproved open ports",
                                .outcome = .fail,
                                .severity = .high,
                                .observed = obs_str,
                                .expected = "Port present in approved services policy",
                                .explanation = "Active open port is not declared in expected services policy.",
                            });
                        }
                    }
                }
            }
        }

        // 2. Evaluate TLS Policy Requirements
        if (self.policy.tls) |tls_pol| {
            if (observations.tls.items.len == 0) {
                try self.appendEvaluation(&report, .{
                    .rule_id = "WS-RULE-TLS-MIN-VERSION",
                    .rule_version = tls_pol.version,
                    .domain = "tls",
                    .target = default_target,
                    .requirement = "Enforce modern TLS protocol (TLS 1.2+)",
                    .outcome = .inconclusive,
                    .severity = .high,
                    .observed = "No stored TLS observation available",
                    .expected = "Negotiated TLS handshake observation",
                    .explanation = "No stored TLS handshake observation found. Inconclusive checks do not silently pass.",
                });
            } else {
                for (observations.tls.items) |tls_obs| {
                    // Protocol Version Check
                    const is_tls_12_or_13 = std.mem.eql(u8, tls_obs.protocol_version, "TLSv1.2") or
                        std.mem.eql(u8, tls_obs.protocol_version, "TLSv1.3");
                    if (is_tls_12_or_13) {
                        try self.appendEvaluation(&report, .{
                            .rule_id = "WS-RULE-TLS-MIN-VERSION",
                            .rule_version = tls_pol.version,
                            .domain = "tls",
                            .target = tls_obs.target,
                            .requirement = "Enforce TLS 1.2 or TLS 1.3 protocol version",
                            .outcome = .pass,
                            .severity = .high,
                            .observed = tls_obs.protocol_version,
                            .expected = tls_pol.min_version,
                            .explanation = "Endpoint negotiates modern approved TLS protocol version.",
                        });
                    } else {
                        try self.appendEvaluation(&report, .{
                            .rule_id = "WS-RULE-TLS-MIN-VERSION",
                            .rule_version = tls_pol.version,
                            .domain = "tls",
                            .target = tls_obs.target,
                            .requirement = "Enforce TLS 1.2 or TLS 1.3 protocol version",
                            .outcome = .fail,
                            .severity = .high,
                            .observed = tls_obs.protocol_version,
                            .expected = tls_pol.min_version,
                            .explanation = "Deprecated TLS protocol negotiated; vulnerable to downgrade attacks.",
                        });
                    }

                    // Certificate Chain Validity Check
                    if (tls_pol.require_valid_chain) {
                        if (tls_obs.is_valid_chain) {
                            try self.appendEvaluation(&report, .{
                                .rule_id = "WS-RULE-TLS-CHAIN-VALIDATION",
                                .rule_version = tls_pol.version,
                                .domain = "tls",
                                .target = tls_obs.target,
                                .requirement = "Require valid trusted certificate chain",
                                .outcome = .pass,
                                .severity = .high,
                                .observed = "Valid trusted chain",
                                .expected = "Trusted CA root path",
                                .explanation = "Certificate chain verified to recognized trust anchor.",
                            });
                        } else {
                            try self.appendEvaluation(&report, .{
                                .rule_id = "WS-RULE-TLS-CHAIN-VALIDATION",
                                .rule_version = tls_pol.version,
                                .domain = "tls",
                                .target = tls_obs.target,
                                .requirement = "Require valid trusted certificate chain",
                                .outcome = .fail,
                                .severity = .high,
                                .observed = "Untrusted or invalid chain",
                                .expected = "Valid trusted certificate chain",
                                .explanation = "Certificate chain validation failed or untrusted root.",
                            });
                        }
                    }

                    // Hostname Match Check
                    if (tls_pol.require_hostname_match) {
                        if (tls_obs.hostname_matches) {
                            try self.appendEvaluation(&report, .{
                                .rule_id = "WS-RULE-TLS-HOSTNAME-MATCH",
                                .rule_version = tls_pol.version,
                                .domain = "tls",
                                .target = tls_obs.target,
                                .requirement = "Require certificate SAN matches requested hostname",
                                .outcome = .pass,
                                .severity = .high,
                                .observed = "Hostname matches SAN/CN",
                                .expected = "Target hostname in certificate SAN",
                                .explanation = "Presented certificate matches target hostname.",
                            });
                        } else {
                            try self.appendEvaluation(&report, .{
                                .rule_id = "WS-RULE-TLS-HOSTNAME-MATCH",
                                .rule_version = tls_pol.version,
                                .domain = "tls",
                                .target = tls_obs.target,
                                .requirement = "Require certificate SAN matches requested hostname",
                                .outcome = .fail,
                                .severity = .high,
                                .observed = "Hostname mismatch",
                                .expected = "Target hostname in certificate SAN",
                                .explanation = "Presented certificate does not cover requested hostname.",
                            });
                        }
                    }

                    // Expiration Window Check
                    if (tls_obs.days_to_expiration) |days| {
                        if (days < @as(i32, @intCast(tls_pol.min_days_to_expiration))) {
                            var buf: [64]u8 = undefined;
                            const obs_str = std.fmt.bufPrint(&buf, "{d} days remaining", .{days}) catch "expiring";
                            var exp_buf: [64]u8 = undefined;
                            const exp_str = std.fmt.bufPrint(&exp_buf, ">= {d} days remaining", .{tls_pol.min_days_to_expiration}) catch "valid";
                            try self.appendEvaluation(&report, .{
                                .rule_id = "WS-RULE-TLS-CERT-EXPIRATION",
                                .rule_version = tls_pol.version,
                                .domain = "tls",
                                .target = tls_obs.target,
                                .requirement = "Require certificate validity buffer before expiration",
                                .outcome = .fail,
                                .severity = .medium,
                                .observed = obs_str,
                                .expected = exp_str,
                                .explanation = "Certificate is expired or near expiration threshold.",
                            });
                        } else {
                            var buf: [64]u8 = undefined;
                            const obs_str = std.fmt.bufPrint(&buf, "{d} days remaining", .{days}) catch "valid";
                            try self.appendEvaluation(&report, .{
                                .rule_id = "WS-RULE-TLS-CERT-EXPIRATION",
                                .rule_version = tls_pol.version,
                                .domain = "tls",
                                .target = tls_obs.target,
                                .requirement = "Require certificate validity buffer before expiration",
                                .outcome = .pass,
                                .severity = .medium,
                                .observed = obs_str,
                                .expected = "Certificate validity buffer satisfied",
                                .explanation = "Certificate validity window exceeds policy threshold.",
                            });
                        }
                    } else {
                        try self.appendEvaluation(&report, .{
                            .rule_id = "WS-RULE-TLS-CERT-EXPIRATION",
                            .rule_version = tls_pol.version,
                            .domain = "tls",
                            .target = tls_obs.target,
                            .requirement = "Require certificate validity buffer before expiration",
                            .outcome = .inconclusive,
                            .severity = .medium,
                            .observed = "Certificate expiration date not available",
                            .expected = "Valid expiration timestamp",
                            .explanation = "Unable to determine certificate expiration offline. Inconclusive checks do not silently pass.",
                        });
                    }
                }
            }
        }

        // 3. Evaluate HTTP Policy Requirements
        if (self.policy.http) |http_pol| {
            if (observations.http.items.len == 0) {
                try self.appendEvaluation(&report, .{
                    .rule_id = "WS-RULE-HTTP-HSTS-POLICY",
                    .rule_version = http_pol.version,
                    .domain = "http",
                    .target = default_target,
                    .requirement = "Enforce HTTP security header policy offline",
                    .outcome = .inconclusive,
                    .severity = .high,
                    .observed = "No stored HTTP observation available",
                    .expected = "Stored HTTP response headers",
                    .explanation = "No stored HTTP observation found. Inconclusive checks do not silently pass.",
                });
            } else {
                for (observations.http.items) |http_obs| {
                    if (!http_obs.is_success) {
                        try self.appendEvaluation(&report, .{
                            .rule_id = "WS-RULE-HTTP-HSTS-POLICY",
                            .rule_version = http_pol.version,
                            .domain = "http",
                            .target = http_obs.target_url,
                            .requirement = "Inspect HTTP security configuration",
                            .outcome = .inconclusive,
                            .severity = .medium,
                            .observed = "Stored HTTP probe was unsuccessful",
                            .expected = "Successful HTTP 2xx/3xx response headers",
                            .explanation = "HTTP probe failed or encountered upstream error; unable to verify headers offline.",
                        });
                        continue;
                    }

                    // HTTPS Enforcement
                    if (http_pol.require_https) {
                        if (http_obs.is_https) {
                            try self.appendEvaluation(&report, .{
                                .rule_id = "WS-RULE-HTTP-HTTPS-REQUIRED",
                                .rule_version = http_pol.version,
                                .domain = "http",
                                .target = http_obs.target_url,
                                .requirement = "Require HTTPS transport",
                                .outcome = .pass,
                                .severity = .high,
                                .observed = "HTTPS transport scheme",
                                .expected = "https:// scheme",
                                .explanation = "Service uses encrypted HTTPS transport.",
                            });
                        } else {
                            try self.appendEvaluation(&report, .{
                                .rule_id = "WS-RULE-HTTP-HTTPS-REQUIRED",
                                .rule_version = http_pol.version,
                                .domain = "http",
                                .target = http_obs.target_url,
                                .requirement = "Require HTTPS transport",
                                .outcome = .fail,
                                .severity = .high,
                                .observed = "Plain unencrypted HTTP scheme",
                                .expected = "https:// scheme",
                                .explanation = "Unencrypted HTTP exposes traffic to interception.",
                            });
                        }
                    }

                    // HSTS Policy Check
                    if (http_pol.require_hsts) {
                        if (!http_obs.is_https) {
                            try self.appendEvaluation(&report, .{
                                .rule_id = "WS-RULE-HTTP-HSTS-POLICY",
                                .rule_version = http_pol.version,
                                .domain = "http",
                                .target = http_obs.target_url,
                                .requirement = "Enforce Strict-Transport-Security on HTTPS",
                                .outcome = .not_applicable,
                                .severity = .info,
                                .observed = "Plain HTTP endpoint",
                                .expected = "RFC 6797 applies only to HTTPS",
                                .explanation = "HSTS header is only applicable on HTTPS responses.",
                            });
                        } else if (http_obs.hsts_header) |hsts| {
                            var passes_max_age = false;
                            if (std.mem.indexOf(u8, hsts, "max-age=")) |idx| {
                                const sub = hsts[idx + 8 ..];
                                var end: usize = 0;
                                while (end < sub.len and sub[end] >= '0' and sub[end] <= '9') : (end += 1) {}
                                if (end > 0) {
                                    const val = std.fmt.parseInt(u32, sub[0..end], 10) catch 0;
                                    if (val >= http_pol.min_hsts_max_age) passes_max_age = true;
                                }
                            }

                            if (passes_max_age) {
                                try self.appendEvaluation(&report, .{
                                    .rule_id = "WS-RULE-HTTP-HSTS-POLICY",
                                    .rule_version = http_pol.version,
                                    .domain = "http",
                                    .target = http_obs.target_url,
                                    .requirement = "Enforce Strict-Transport-Security header",
                                    .outcome = .pass,
                                    .severity = .high,
                                    .observed = hsts,
                                    .expected = "max-age >= policy minimum",
                                    .explanation = "HSTS header is present with sufficient max-age.",
                                });
                            } else {
                                try self.appendEvaluation(&report, .{
                                    .rule_id = "WS-RULE-HTTP-HSTS-POLICY",
                                    .rule_version = http_pol.version,
                                    .domain = "http",
                                    .target = http_obs.target_url,
                                    .requirement = "Enforce Strict-Transport-Security header",
                                    .outcome = .fail,
                                    .severity = .medium,
                                    .observed = hsts,
                                    .expected = "max-age >= policy minimum",
                                    .explanation = "HSTS max-age is shorter than policy threshold.",
                                });
                            }
                        } else {
                            try self.appendEvaluation(&report, .{
                                .rule_id = "WS-RULE-HTTP-HSTS-POLICY",
                                .rule_version = http_pol.version,
                                .domain = "http",
                                .target = http_obs.target_url,
                                .requirement = "Enforce Strict-Transport-Security header",
                                .outcome = .fail,
                                .severity = .high,
                                .observed = "HSTS header missing",
                                .expected = "Strict-Transport-Security header configured",
                                .explanation = "Missing HSTS allows potential downgrade attacks.",
                            });
                        }
                    }

                    // Content-Security-Policy Check
                    if (http_pol.require_csp) {
                        if (!http_obs.is_html) {
                            try self.appendEvaluation(&report, .{
                                .rule_id = "WS-RULE-HTTP-CSP-SCRIPT-RESTRICTION",
                                .rule_version = http_pol.version,
                                .domain = "http",
                                .target = http_obs.target_url,
                                .requirement = "Require Content-Security-Policy on HTML documents",
                                .outcome = .not_applicable,
                                .severity = .info,
                                .observed = "Non-HTML API endpoint",
                                .expected = "Applies only to HTML document responses",
                                .explanation = "JSON API endpoint does not render HTML DOM.",
                            });
                        } else if (http_obs.csp_header) |csp| {
                            const has_unsafe = std.mem.indexOf(u8, csp, "'unsafe-inline'") != null or
                                std.mem.indexOf(u8, csp, "'unsafe-eval'") != null;
                            if (http_pol.disallow_unsafe_csp and has_unsafe) {
                                try self.appendEvaluation(&report, .{
                                    .rule_id = "WS-RULE-HTTP-CSP-SCRIPT-RESTRICTION",
                                    .rule_version = http_pol.version,
                                    .domain = "http",
                                    .target = http_obs.target_url,
                                    .requirement = "Disallow unsafe-inline and unsafe-eval in CSP",
                                    .outcome = .fail,
                                    .severity = .high,
                                    .observed = csp,
                                    .expected = "CSP without unsafe keywords",
                                    .explanation = "CSP permits inline scripts or dynamic code evaluation.",
                                });
                            } else {
                                try self.appendEvaluation(&report, .{
                                    .rule_id = "WS-RULE-HTTP-CSP-SCRIPT-RESTRICTION",
                                    .rule_version = http_pol.version,
                                    .domain = "http",
                                    .target = http_obs.target_url,
                                    .requirement = "Require Content-Security-Policy on HTML documents",
                                    .outcome = .pass,
                                    .severity = .high,
                                    .observed = csp,
                                    .expected = "Configured Content-Security-Policy",
                                    .explanation = "Content-Security-Policy conforms to policy requirements.",
                                });
                            }
                        } else {
                            try self.appendEvaluation(&report, .{
                                .rule_id = "WS-RULE-HTTP-CSP-SCRIPT-RESTRICTION",
                                .rule_version = http_pol.version,
                                .domain = "http",
                                .target = http_obs.target_url,
                                .requirement = "Require Content-Security-Policy on HTML documents",
                                .outcome = .fail,
                                .severity = .high,
                                .observed = "CSP header missing",
                                .expected = "Content-Security-Policy configured",
                                .explanation = "HTML document response lacks CSP restrictions.",
                            });
                        }
                    }

                    // nosniff Check
                    if (http_pol.require_nosniff) {
                        if (http_obs.x_content_type_options) |nosniff| {
                            if (std.mem.eql(u8, nosniff, "nosniff")) {
                                try self.appendEvaluation(&report, .{
                                    .rule_id = "WS-RULE-HTTP-NOSNIFF-HEADER",
                                    .rule_version = http_pol.version,
                                    .domain = "http",
                                    .target = http_obs.target_url,
                                    .requirement = "Enforce X-Content-Type-Options: nosniff",
                                    .outcome = .pass,
                                    .severity = .low,
                                    .observed = "nosniff",
                                    .expected = "X-Content-Type-Options: nosniff",
                                    .explanation = "MIME sniffing protection enabled.",
                                });
                            } else {
                                try self.appendEvaluation(&report, .{
                                    .rule_id = "WS-RULE-HTTP-NOSNIFF-HEADER",
                                    .rule_version = http_pol.version,
                                    .domain = "http",
                                    .target = http_obs.target_url,
                                    .requirement = "Enforce X-Content-Type-Options: nosniff",
                                    .outcome = .fail,
                                    .severity = .low,
                                    .observed = nosniff,
                                    .expected = "nosniff",
                                    .explanation = "Header present but value is not 'nosniff'.",
                                });
                            }
                        } else {
                            try self.appendEvaluation(&report, .{
                                .rule_id = "WS-RULE-HTTP-NOSNIFF-HEADER",
                                .rule_version = http_pol.version,
                                .domain = "http",
                                .target = http_obs.target_url,
                                .requirement = "Enforce X-Content-Type-Options: nosniff",
                                .outcome = .fail,
                                .severity = .low,
                                .observed = "Header missing",
                                .expected = "X-Content-Type-Options: nosniff",
                                .explanation = "Missing MIME sniffing protection header.",
                            });
                        }
                    }

                    // Frame Protection Check
                    if (http_pol.require_frame_options) {
                        if (http_obs.x_frame_options != null or
                            (http_obs.csp_header != null and std.mem.indexOf(u8, http_obs.csp_header.?, "frame-ancestors") != null))
                        {
                            try self.appendEvaluation(&report, .{
                                .rule_id = "WS-RULE-HTTP-FRAME-OPTIONS",
                                .rule_version = http_pol.version,
                                .domain = "http",
                                .target = http_obs.target_url,
                                .requirement = "Require framing/clickjacking protection",
                                .outcome = .pass,
                                .severity = .medium,
                                .observed = http_obs.x_frame_options orelse "CSP frame-ancestors",
                                .expected = "X-Frame-Options or CSP frame-ancestors",
                                .explanation = "Framing restriction configured.",
                            });
                        } else {
                            try self.appendEvaluation(&report, .{
                                .rule_id = "WS-RULE-HTTP-FRAME-OPTIONS",
                                .rule_version = http_pol.version,
                                .domain = "http",
                                .target = http_obs.target_url,
                                .requirement = "Require framing/clickjacking protection",
                                .outcome = .fail,
                                .severity = .medium,
                                .observed = "No framing protection headers",
                                .expected = "X-Frame-Options: DENY|SAMEORIGIN or CSP frame-ancestors",
                                .explanation = "Endpoint missing framing protection; vulnerable to clickjacking.",
                            });
                        }
                    }
                }
            }
        }

        // 4. Evaluate Listener Exposure Policy Requirements
        if (self.policy.exposure) |exp_pol| {
            if (observations.listeners.items.len == 0) {
                try self.appendEvaluation(&report, .{
                    .rule_id = "WS-RULE-EXPOSURE-WILDCARD-BINDING",
                    .rule_version = exp_pol.version,
                    .domain = "exposure",
                    .target = default_target,
                    .requirement = "Audit local listening sockets for unexpected exposure",
                    .outcome = .inconclusive,
                    .severity = .medium,
                    .observed = "No stored listener observations available",
                    .expected = "Socket inventory observations",
                    .explanation = "No stored listener observations found. Inconclusive checks do not silently pass.",
                });
            } else {
                for (observations.listeners.items) |l_obs| {
                    if (l_obs.permission_limited) {
                        try self.appendEvaluation(&report, .{
                            .rule_id = "WS-RULE-EXPOSURE-WILDCARD-BINDING",
                            .rule_version = exp_pol.version,
                            .domain = "exposure",
                            .target = l_obs.address,
                            .requirement = "Audit listening socket bindings",
                            .outcome = .inconclusive,
                            .severity = .medium,
                            .observed = "Permission-limited listener observation",
                            .expected = "Unrestricted socket binding inspection",
                            .explanation = "Process lacked privileges to inspect socket tables; cannot assert absence of exposure offline.",
                        });
                        continue;
                    }

                    // Wildcard Check
                    if (exp_pol.disallow_wildcards) {
                        if (std.mem.eql(u8, l_obs.binding_type, "wildcard")) {
                            var buf: [64]u8 = undefined;
                            const obs_str = std.fmt.bufPrint(&buf, "{s}:{d} (wildcard)", .{ l_obs.address, l_obs.port }) catch "wildcard";
                            try self.appendEvaluation(&report, .{
                                .rule_id = "WS-RULE-EXPOSURE-WILDCARD-BINDING",
                                .rule_version = exp_pol.version,
                                .domain = "exposure",
                                .target = l_obs.address,
                                .requirement = "Disallow wildcard (0.0.0.0 / [::]) listener bindings",
                                .outcome = .fail,
                                .severity = .high,
                                .observed = obs_str,
                                .expected = "Loopback or specific interface binding",
                                .explanation = "Service listens on all network interfaces, exposing service externally.",
                            });
                        } else {
                            try self.appendEvaluation(&report, .{
                                .rule_id = "WS-RULE-EXPOSURE-WILDCARD-BINDING",
                                .rule_version = exp_pol.version,
                                .domain = "exposure",
                                .target = l_obs.address,
                                .requirement = "Disallow wildcard listener bindings",
                                .outcome = .pass,
                                .severity = .high,
                                .observed = l_obs.binding_type,
                                .expected = "Non-wildcard binding",
                                .explanation = "Listener is bound to specific interface or loopback.",
                            });
                        }
                    }

                    // Loopback Only Check
                    if (exp_pol.require_loopback_only) {
                        if (std.mem.eql(u8, l_obs.binding_type, "loopback")) {
                            try self.appendEvaluation(&report, .{
                                .rule_id = "WS-RULE-EXPOSURE-LOOPBACK-ONLY",
                                .rule_version = exp_pol.version,
                                .domain = "exposure",
                                .target = l_obs.address,
                                .requirement = "Require listener restricted strictly to loopback",
                                .outcome = .pass,
                                .severity = .medium,
                                .observed = "loopback interface binding",
                                .expected = "127.0.0.1 or ::1",
                                .explanation = "Service restricted to local loopback interface.",
                            });
                        } else {
                            try self.appendEvaluation(&report, .{
                                .rule_id = "WS-RULE-EXPOSURE-LOOPBACK-ONLY",
                                .rule_version = exp_pol.version,
                                .domain = "exposure",
                                .target = l_obs.address,
                                .requirement = "Require listener restricted strictly to loopback",
                                .outcome = .fail,
                                .severity = .medium,
                                .observed = l_obs.binding_type,
                                .expected = "loopback",
                                .explanation = "Service is not restricted to local host loopback.",
                            });
                        }
                    }
                }
            }
        }

        return report;
    }

    /// Evaluates an assessment result offline
    pub fn evaluateAssessment(self: *OfflinePolicyEvaluator, result: *const runner.AssessmentResult) !PolicyEvaluationReport {
        return try self.evaluateObservations(&result.observations, result.profile_id);
    }

    /// Evaluates a stored BaselineSnapshot completely offline
    pub fn evaluateBaseline(self: *OfflinePolicyEvaluator, snapshot: *const baseline_mod.BaselineSnapshot) !PolicyEvaluationReport {
        var report = PolicyEvaluationReport{
            .allocator = self.allocator,
            .policy_id = try self.allocator.dupe(u8, self.policy.policy_id),
            .policy_version = self.policy.version,
            .evaluated_at_ms = std.time.milliTimestamp(),
            .is_offline = true,
        };
        errdefer report.deinit();

        for (snapshot.items) |item| {
            switch (item.item_type) {
                .listener => {
                    if (self.policy.exposure) |exp_pol| {
                        if (exp_pol.disallow_wildcards and std.mem.indexOf(u8, item.details, "binding=wildcard") != null) {
                            try self.appendEvaluation(&report, .{
                                .rule_id = "WS-RULE-EXPOSURE-WILDCARD-BINDING",
                                .rule_version = exp_pol.version,
                                .domain = "exposure",
                                .target = item.key,
                                .requirement = "Disallow wildcard bindings in baseline",
                                .outcome = .fail,
                                .severity = .high,
                                .observed = "Wildcard listener in baseline",
                                .expected = "Loopback or specific binding",
                                .explanation = "Stored baseline contains an unapproved wildcard listener.",
                            });
                        } else {
                            try self.appendEvaluation(&report, .{
                                .rule_id = "WS-RULE-EXPOSURE-WILDCARD-BINDING",
                                .rule_version = exp_pol.version,
                                .domain = "exposure",
                                .target = item.key,
                                .requirement = "Disallow wildcard bindings in baseline",
                                .outcome = .pass,
                                .severity = .high,
                                .observed = "Non-wildcard baseline item",
                                .expected = "Non-wildcard binding",
                                .explanation = "Baseline item conforms to exposure policy.",
                            });
                        }
                    }
                },
                .tls_config => {
                    if (self.policy.tls) |tls_pol| {
                        if (std.mem.indexOf(u8, item.details, "proto=TLSv1.0") != null or
                            std.mem.indexOf(u8, item.details, "proto=TLSv1.1") != null)
                        {
                            try self.appendEvaluation(&report, .{
                                .rule_id = "WS-RULE-TLS-MIN-VERSION",
                                .rule_version = tls_pol.version,
                                .domain = "tls",
                                .target = item.key,
                                .requirement = "Enforce TLS 1.2+ in baseline",
                                .outcome = .fail,
                                .severity = .high,
                                .observed = item.details,
                                .expected = tls_pol.min_version,
                                .explanation = "Stored baseline contains deprecated TLS protocol.",
                            });
                        } else {
                            try self.appendEvaluation(&report, .{
                                .rule_id = "WS-RULE-TLS-MIN-VERSION",
                                .rule_version = tls_pol.version,
                                .domain = "tls",
                                .target = item.key,
                                .requirement = "Enforce TLS 1.2+ in baseline",
                                .outcome = .pass,
                                .severity = .high,
                                .observed = item.details,
                                .expected = tls_pol.min_version,
                                .explanation = "Baseline TLS protocol conforms to modern standards.",
                            });
                        }
                    }
                },
                .http_config => {
                    if (self.policy.http) |http_pol| {
                        if (http_pol.require_hsts and std.mem.indexOf(u8, item.details, "hsts=MISSING") != null) {
                            try self.appendEvaluation(&report, .{
                                .rule_id = "WS-RULE-HTTP-HSTS-POLICY",
                                .rule_version = http_pol.version,
                                .domain = "http",
                                .target = item.key,
                                .requirement = "Require HSTS in baseline",
                                .outcome = .fail,
                                .severity = .high,
                                .observed = "hsts=MISSING",
                                .expected = "Strict-Transport-Security configured",
                                .explanation = "Stored baseline endpoint lacks HSTS header.",
                            });
                        } else {
                            try self.appendEvaluation(&report, .{
                                .rule_id = "WS-RULE-HTTP-HSTS-POLICY",
                                .rule_version = http_pol.version,
                                .domain = "http",
                                .target = item.key,
                                .requirement = "Require HSTS in baseline",
                                .outcome = .pass,
                                .severity = .high,
                                .observed = "HSTS present",
                                .expected = "HSTS configured",
                                .explanation = "Baseline endpoint configures HSTS.",
                            });
                        }
                    }
                },
                .tcp_service => {
                    if (self.policy.expected_services) |svc_pol| {
                        try self.appendEvaluation(&report, .{
                            .rule_id = "WS-RULE-POLICY-EXPECTED-PORTS",
                            .rule_version = svc_pol.version,
                            .domain = "services",
                            .target = item.key,
                            .requirement = "Audit baseline services against expected policy",
                            .outcome = .pass,
                            .severity = .info,
                            .observed = item.details,
                            .expected = "Baseline documented port",
                            .explanation = "Service entry present in baseline.",
                        });
                    }
                },
                .dns => {},
            }
        }

        return report;
    }

    fn appendEvaluation(
        self: *OfflinePolicyEvaluator,
        report: *PolicyEvaluationReport,
        ev: struct {
            rule_id: []const u8,
            rule_version: u32,
            domain: []const u8,
            target: []const u8,
            requirement: []const u8,
            outcome: PolicyOutcome,
            severity: core_models.Severity,
            observed: []const u8,
            expected: []const u8,
            explanation: []const u8,
        },
    ) !void {
        const item = PolicyRuleEvaluation{
            .rule_id = try self.allocator.dupe(u8, ev.rule_id),
            .rule_version = ev.rule_version,
            .domain = try self.allocator.dupe(u8, ev.domain),
            .target = try self.allocator.dupe(u8, ev.target),
            .requirement = try self.allocator.dupe(u8, ev.requirement),
            .outcome = ev.outcome,
            .severity = ev.severity,
            .observed = try self.allocator.dupe(u8, ev.observed),
            .expected = try self.allocator.dupe(u8, ev.expected),
            .explanation = try self.allocator.dupe(u8, ev.explanation),
        };

        try report.evaluations.append(self.allocator, item);
        report.total_evaluated += 1;

        switch (ev.outcome) {
            .pass => report.passed_count += 1,
            .fail => report.failed_count += 1,
            .inconclusive => report.inconclusive_count += 1,
            .not_applicable => report.not_applicable_count += 1,
        }
    }
};

// -----------------------------------------------------------------------------
// Unit & Integration Tests (Phase 10.4 Acceptance Criteria)
// -----------------------------------------------------------------------------

test "offline policy evaluation: fully compliant stored observations pass with exit code 0" {
    const allocator = testing.allocator;

    var evaluator = OfflinePolicyEvaluator.init(allocator, BuiltinPolicies.local_hardened);

    var obs = runner.AssessmentObservations.init(allocator);
    defer obs.deinit();

    // Allowed TCP port observation (port 443)
    try obs.tcp.append(allocator, .{
        .target = try allocator.dupe(u8, "localhost"),
        .port = 443,
        .is_open = true,
        .rtt_ms = 1,
    });

    // Hardened TLS observation
    try obs.tls.append(allocator, .{
        .target = try allocator.dupe(u8, "localhost"),
        .port = 443,
        .protocol_version = try allocator.dupe(u8, "TLSv1.3"),
        .hostname_matches = true,
        .is_valid_chain = true,
        .days_to_expiration = 120,
        .is_success = true,
    });

    // Hardened HTTP observation
    try obs.http.append(allocator, .{
        .target_url = try allocator.dupe(u8, "https://localhost:443/"),
        .status_code = 200,
        .is_https = true,
        .is_html = true,
        .is_json_api = false,
        .hsts_header = try allocator.dupe(u8, "max-age=31536000; includeSubDomains"),
        .csp_header = try allocator.dupe(u8, "default-src 'self'"),
        .x_content_type_options = try allocator.dupe(u8, "nosniff"),
        .x_frame_options = try allocator.dupe(u8, "DENY"),
        .cookies = &.{},
        .is_success = true,
    });

    // Hardened loopback listener
    try obs.listeners.append(allocator, .{
        .transport = try allocator.dupe(u8, "tcp"),
        .address = try allocator.dupe(u8, "127.0.0.1"),
        .port = 443,
        .binding_type = try allocator.dupe(u8, "loopback"),
        .pid = 500,
        .process_name = try allocator.dupe(u8, "test-server"),
        .is_unlisted = false,
        .permission_limited = false,
    });

    var report = try evaluator.evaluateObservations(&obs, "localhost");
    defer report.deinit();

    // Acceptance criteria 1 & 3: Works offline and deterministic
    try testing.expect(report.is_offline);
    try testing.expect(report.isCompliant());
    try testing.expectEqual(@as(usize, 0), report.failed_count);
    try testing.expectEqual(@as(usize, 0), report.inconclusive_count);
    try testing.expect(report.passed_count >= 6);

    // Acceptance criteria 4: Exit code matches documentation (0 for success)
    try testing.expectEqual(@as(u8, 0), report.toExitCode());
}

test "offline policy evaluation: policy failures detect violations and return exit code 1" {
    const allocator = testing.allocator;

    var evaluator = OfflinePolicyEvaluator.init(allocator, BuiltinPolicies.local_hardened);

    var obs = runner.AssessmentObservations.init(allocator);
    defer obs.deinit();

    // Allowed TCP port observation (port 443)
    try obs.tcp.append(allocator, .{
        .target = try allocator.dupe(u8, "localhost"),
        .port = 443,
        .is_open = true,
        .rtt_ms = 1,
    });

    // Deprecated TLS 1.0 observation
    try obs.tls.append(allocator, .{
        .target = try allocator.dupe(u8, "legacy.lan"),
        .port = 443,
        .protocol_version = try allocator.dupe(u8, "TLSv1.0"),
        .hostname_matches = true,
        .is_valid_chain = true,
        .days_to_expiration = 60,
        .is_success = true,
    });

    // HTTP observation missing HSTS and with unsafe CSP
    try obs.http.append(allocator, .{
        .target_url = try allocator.dupe(u8, "https://legacy.lan/"),
        .status_code = 200,
        .is_https = true,
        .is_html = true,
        .is_json_api = false,
        .hsts_header = null, // Missing!
        .csp_header = try allocator.dupe(u8, "script-src 'unsafe-inline'"), // Unsafe!
        .x_content_type_options = null, // Missing!
        .x_frame_options = null, // Missing!
        .cookies = &.{},
        .is_success = true,
    });

    // Wildcard listener
    try obs.listeners.append(allocator, .{
        .transport = try allocator.dupe(u8, "tcp"),
        .address = try allocator.dupe(u8, "0.0.0.0"),
        .port = 8080,
        .binding_type = try allocator.dupe(u8, "wildcard"),
        .pid = 900,
        .process_name = try allocator.dupe(u8, "unapproved-daemon"),
        .is_unlisted = true,
        .permission_limited = false,
    });

    var report = try evaluator.evaluateObservations(&obs, "legacy.lan");
    defer report.deinit();

    try testing.expect(!report.isCompliant());
    try testing.expect(report.failed_count >= 4);

    // Acceptance criteria 4: Exit code matches documentation (1 for findings/violations)
    try testing.expectEqual(@as(u8, 1), report.toExitCode());
}

test "offline policy evaluation: inconclusive checks do NOT silently pass" {
    const allocator = testing.allocator;

    var evaluator = OfflinePolicyEvaluator.init(allocator, BuiltinPolicies.local_hardened);

    // Completely empty stored observations
    var obs = runner.AssessmentObservations.init(allocator);
    defer obs.deinit();

    var report = try evaluator.evaluateObservations(&obs, "unknown-target");
    defer report.deinit();

    // Acceptance criteria 2: Inconclusive checks do NOT silently count as pass!
    try testing.expect(!report.isCompliant());
    try testing.expect(report.inconclusive_count > 0);
    try testing.expectEqual(@as(usize, 0), report.passed_count);

    // Non-compliant status maps to exit code 1
    try testing.expectEqual(@as(u8, 1), report.toExitCode());
}

test "offline policy evaluation: permission-limited listener observation is marked inconclusive" {
    const allocator = testing.allocator;

    var evaluator = OfflinePolicyEvaluator.init(allocator, BuiltinPolicies.local_hardened);

    var obs = runner.AssessmentObservations.init(allocator);
    defer obs.deinit();

    // Allowed TCP port observation (port 443)
    try obs.tcp.append(allocator, .{
        .target = try allocator.dupe(u8, "localhost"),
        .port = 443,
        .is_open = true,
        .rtt_ms = 1,
    });

    // Permission-limited listener observation
    try obs.listeners.append(allocator, .{
        .transport = try allocator.dupe(u8, "tcp"),
        .address = try allocator.dupe(u8, "0.0.0.0"),
        .port = 80,
        .binding_type = try allocator.dupe(u8, "wildcard"),
        .pid = 1,
        .process_name = null,
        .is_unlisted = false,
        .permission_limited = true, // Permission limited!
    });

    var report = try evaluator.evaluateObservations(&obs, "limited-host");
    defer report.deinit();

    try testing.expect(!report.isCompliant());
    try testing.expect(report.inconclusive_count > 0);
    try testing.expectEqual(@as(u8, 1), report.toExitCode());
}

test "offline policy evaluation: baseline snapshot evaluation works offline" {
    const allocator = testing.allocator;

    var evaluator = OfflinePolicyEvaluator.init(allocator, BuiltinPolicies.local_hardened);

    var items = [_]baseline_mod.NormalizedBaselineItem{
        .{
            .key = "listener:tcp:127.0.0.1:443",
            .item_type = .listener,
            .summary = "TCP 127.0.0.1:443 (loopback)",
            .details = "proto=tcp;addr=127.0.0.1;port=443;binding=loopback;proc=wirescope",
        },
        .{
            .key = "tls:localhost:443",
            .item_type = .tls_config,
            .summary = "TLS localhost:443 (TLSv1.3)",
            .details = "proto=TLSv1.3;valid_chain=true;hostname_matches=true",
        },
        .{
            .key = "http:https://localhost:443/",
            .item_type = .http_config,
            .summary = "HTTP https://localhost:443/",
            .details = "status=200;hsts=max-age=31536000;csp=default-src 'self'",
        },
    };

    const snapshot = baseline_mod.BaselineSnapshot{
        .name = "prod-baseline",
        .version = 1,
        .created_at_ms = 1710000000000,
        .assessment_id = "asm-baseline-1",
        .profile_id = "local-security-audit",
        .items = &items,
        .snapshot_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".*,
    };

    var report = try evaluator.evaluateBaseline(&snapshot);
    defer report.deinit();

    try testing.expect(report.is_offline);
    try testing.expect(report.isCompliant());
    try testing.expectEqual(@as(u8, 0), report.toExitCode());
}
