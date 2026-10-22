const std = @import("std");
const testing = std.testing;
const builtin = @import("builtin");

const core = @import("../core/root.zig");
const types = @import("types.zig");
const engine = @import("engine.zig");
const tcp = @import("tcp.zig");
const tls = @import("tls.zig");
const assessment = @import("../assessment/root.zig");
pub const troubleshooting_mod = @import("https_troubleshooting.zig");
pub const fixtures = @import("https_fixtures.zig");

pub const HttpsTroubleshooting = troubleshooting_mod.HttpsTroubleshooting;
pub const generateHttpsTroubleshooting = troubleshooting_mod.generateHttpsTroubleshooting;

const OutcomeCategory = core.OutcomeCategory;
const StructuredError = core.StructuredError;
const ErrorCode = core.ErrorCode;
const OperationEnvelope = core.OperationEnvelope;
const OperationType = core.OperationType;
const TimingStages = core.TimingStages;
const HttpPayload = core.HttpPayload;
pub const CancellationToken = types.CancellationToken;
pub const AssessmentProfile = assessment.AssessmentProfile;

/// Granular failure categories for HTTPS diagnostics (Milestone 7 Phase 7.2)
pub const HttpsFailureCategory = enum {
    success,
    redirect_limit_exceeded,
    redirect_loop,
    redirect_out_of_scope,
    response_size_exceeded,
    http_protocol_error,
    tls_certificate_expired,
    tls_certificate_not_yet_valid,
    tls_hostname_mismatch,
    tls_untrusted_chain,
    tls_handshake_failed,
    tcp_connection_failed,
    timeout,
    cancelled,
    malformed_input,
    operational_failure,

    pub fn toOutcome(self: HttpsFailureCategory) OutcomeCategory {
        return switch (self) {
            .success => .success,
            .redirect_limit_exceeded, .redirect_loop, .response_size_exceeded, .http_protocol_error => .operational_failure,
            .redirect_out_of_scope, .malformed_input => .invalid_input,
            .tls_certificate_expired, .tls_certificate_not_yet_valid, .tls_hostname_mismatch, .tls_untrusted_chain, .tls_handshake_failed, .tcp_connection_failed => .operational_failure,
            .timeout => .timeout,
            .cancelled => .cancelled,
            .operational_failure => .operational_failure,
        };
    }

    pub fn toErrorCode(self: HttpsFailureCategory) ErrorCode {
        return switch (self) {
            .success => .none,
            .redirect_limit_exceeded, .redirect_loop => .http_redirect_loop,
            .redirect_out_of_scope => .out_of_scope_target,
            .response_size_exceeded => .http_response_oversized,
            .http_protocol_error => .http_protocol_error,
            .tls_certificate_expired, .tls_certificate_not_yet_valid => .tls_certificate_expired,
            .tls_hostname_mismatch => .tls_hostname_mismatch,
            .tls_untrusted_chain => .tls_untrusted_root,
            .tls_handshake_failed => .tls_handshake_failed,
            .tcp_connection_failed => .connection_refused,
            .timeout => .connection_timed_out,
            .cancelled => .operation_cancelled,
            .malformed_input => .parse_error,
            .operational_failure => .internal_error,
        };
    }

    pub fn toSlice(self: HttpsFailureCategory) []const u8 {
        return @tagName(self);
    }
};

/// Configuration parameters for HTTPS probe execution
pub const HttpsConfig = struct {
    timeout_ms: u32 = 5000,
    max_redirects: u32 = 5,
    max_response_bytes: usize = 1024 * 1024, // 1 MB default bound
    allow_redirect_scope_expansion: bool = false, // Security: Redirects cannot escape scope by default
    verify_certificates: bool = true, // Security: Never disable verification silently
    insecure_skip_verify: bool = false,
    custom_ca_path: ?[]const u8 = null,
    method: []const u8 = "GET",
    user_agent: []const u8 = "WireScope/0.1.0",
};

/// Represents an individual hop in an HTTP redirection chain
pub const RedirectHop = struct {
    url: []const u8,
    status_code: u16,
    elapsed_ns: u64,

    pub fn deinit(self: *RedirectHop, allocator: std.mem.Allocator) void {
        allocator.free(self.url);
    }
};

/// Preserved diagnostic outcome of an HTTPS connectivity and timing probe
pub const HttpsProbeResult = struct {
    target_url: []const u8,
    effective_url: []const u8,
    host: []const u8,
    port: u16,
    scheme: []const u8,
    status_code: u16 = 0,
    status_line: []const u8,
    failure_category: HttpsFailureCategory,
    elapsed_ns: u64,
    timing_stages: TimingStages,
    err: StructuredError = StructuredError.none,

    // Security headers (evaluated without storing response body)
    hsts_header: ?[]const u8 = null,
    csp_header: ?[]const u8 = null,
    content_type_options: ?[]const u8 = null,
    redirect_target: ?[]const u8 = null,
    response_size_bytes: usize = 0,
    body_persisted: bool = false, // Privacy invariant: strictly false by default!

    // Redirects
    redirect_count: u32 = 0,
    redirect_chain: []RedirectHop = &.{},

    // TLS details (if HTTPS)
    tls_protocol_version: ?[]const u8 = null,
    tls_cipher_suite: ?[]const u8 = null,
    tls_certificate_subject: ?[]const u8 = null,
    tls_certificate_issuer: ?[]const u8 = null,
    tls_verified: bool = false,
    verification_bypassed: bool = false,

    capability_limitations: ?[]const u8 = null,

    pub fn deinit(self: *HttpsProbeResult, allocator: std.mem.Allocator) void {
        allocator.free(self.target_url);
        allocator.free(self.effective_url);
        allocator.free(self.host);
        allocator.free(self.scheme);
        allocator.free(self.status_line);

        if (self.hsts_header) |h| allocator.free(h);
        if (self.csp_header) |c| allocator.free(c);
        if (self.content_type_options) |o| allocator.free(o);
        if (self.redirect_target) |r| allocator.free(r);

        for (self.redirect_chain) |*hop| {
            hop.deinit(allocator);
        }
        if (self.redirect_chain.len > 0) {
            allocator.free(self.redirect_chain);
        }

        if (self.tls_protocol_version) |p| allocator.free(p);
        if (self.tls_cipher_suite) |c| allocator.free(c);
        if (self.tls_certificate_subject) |s| allocator.free(s);
        if (self.tls_certificate_issuer) |i| allocator.free(i);
        if (self.capability_limitations) |l| allocator.free(l);
    }

    /// Converts into universal OperationEnvelope satisfying shared result contract
    pub fn toEnvelope(self: *const HttpsProbeResult, allocator: std.mem.Allocator, op_id: []const u8, profile_id: ?[]const u8) !OperationEnvelope {
        const now = std.time.milliTimestamp();

        return OperationEnvelope{
            .operation_id = try allocator.dupe(u8, op_id),
            .operation_type = .http,
            .target = try allocator.dupe(u8, self.effective_url),
            .profile_id = if (profile_id) |p| try allocator.dupe(u8, p) else null,
            .start_time_ms = now - @as(i64, @intCast(self.elapsed_ns / std.time.ns_per_ms)),
            .end_time_ms = now,
            .monotonic_elapsed_ns = self.elapsed_ns,
            .outcome = self.failure_category.toOutcome(),
            .is_partial = (self.failure_category == .cancelled),
            .timing_stages = self.timing_stages,
            .err = self.err,
            .capability_limitations = if (self.capability_limitations) |l| try allocator.dupe(u8, l) else null,
            .payload = .{
                .http = .{
                    .status_code = self.status_code,
                    .hsts_header = if (self.hsts_header) |h| try allocator.dupe(u8, h) else null,
                    .csp_header = if (self.csp_header) |c| try allocator.dupe(u8, c) else null,
                    .content_type_options = if (self.content_type_options) |o| try allocator.dupe(u8, o) else null,
                    .redirect_target = if (self.redirect_target) |r| try allocator.dupe(u8, r) else null,
                    .response_size_bytes = self.response_size_bytes,
                },
            },
        };
    }

    /// Renders concise human-readable diagnostic output for terminal
    pub fn toTerminal(self: *const HttpsProbeResult, writer: anytype) !void {
        if (self.failure_category == .success) {
            try writer.print("HTTPS probe to {s} [{d} {s}]\n", .{
                self.effective_url,
                self.status_code,
                self.status_line,
            });
        } else if (self.verification_bypassed) {
            try writer.print("HTTPS probe to {s} [{d} - INSECURE BYPASSED]\n", .{
                self.effective_url,
                self.status_code,
            });
            try writer.writeAll("  WARNING: TLS certificate verification was bypassed via --insecure option!\n");
        } else {
            try writer.print("HTTPS probe to {s} [FAILED: {s}]\n", .{
                self.target_url,
                self.failure_category.toSlice(),
            });
        }

        // Granular timing stages
        try writer.writeAll("  Timing Stages:\n");
        if (self.timing_stages.tcp_connect_ns) |tcp_ns| {
            const ms = @as(f64, @floatFromInt(tcp_ns)) / @as(f64, @floatFromInt(std.time.ns_per_ms));
            try writer.print("    * TCP Connect:    {d:.2}ms\n", .{ms});
        }
        if (self.timing_stages.tls_handshake_ns) |tls_ns| {
            const ms = @as(f64, @floatFromInt(tls_ns)) / @as(f64, @floatFromInt(std.time.ns_per_ms));
            try writer.print("    * TLS Handshake:  {d:.2}ms\n", .{ms});
        }
        if (self.timing_stages.http_ttfb_ns) |ttfb_ns| {
            const ms = @as(f64, @floatFromInt(ttfb_ns)) / @as(f64, @floatFromInt(std.time.ns_per_ms));
            try writer.print("    * HTTP TTFB:      {d:.2}ms\n", .{ms});
        }
        if (self.timing_stages.http_transfer_ns) |transfer_ns| {
            const ms = @as(f64, @floatFromInt(transfer_ns)) / @as(f64, @floatFromInt(std.time.ns_per_ms));
            try writer.print("    * HTTP Transfer:  {d:.2}ms\n", .{ms});
        }
        const total_ms = @as(f64, @floatFromInt(self.elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_ms));
        try writer.print("    * Total Elapsed:  {d:.2}ms\n", .{total_ms});

        // Response metrics and privacy bounds
        try writer.print("  Response Size:  {d} bytes (body not persisted)\n", .{self.response_size_bytes});

        // Security headers
        try writer.writeAll("  Security Headers:\n");
        try writer.print("    * HSTS:           {s}\n", .{self.hsts_header orelse "missing"});
        try writer.print("    * CSP:            {s}\n", .{self.csp_header orelse "missing"});
        try writer.print("    * X-Content-Type: {s}\n", .{self.content_type_options orelse "missing"});

        // Redirections
        if (self.redirect_count > 0) {
            try writer.print("  Redirections:   {d} hop(s)\n", .{self.redirect_count});
            for (self.redirect_chain, 0..) |hop, i| {
                const hop_ms = @as(f64, @floatFromInt(hop.elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_ms));
                try writer.print("    [{d}] {d} -> {s} ({d:.2}ms)\n", .{ i + 1, hop.status_code, hop.url, hop_ms });
            }
        }

        if (self.err.isError()) {
            try writer.print("  Error:          {s} ({s})\n", .{ self.err.message, @tagName(self.err.code) });
            if (self.err.details) |d| {
                try writer.print("  Details:        {s}\n", .{d});
            }
        }

        try writer.writeAll("\n");
        const tb = generateHttpsTroubleshooting(self);
        try tb.toTerminal(writer);
    }

    /// Renders deterministic JSON representation
    pub fn toJson(self: *const HttpsProbeResult, writer: anytype) !void {
        try writer.print("{{\"target_url\":\"{s}\",\"effective_url\":\"{s}\",\"host\":\"{s}\",\"port\":{d},\"scheme\":\"{s}\",\"status_code\":{d},\"status_line\":\"{s}\",\"failure_category\":\"{s}\",\"elapsed_ns\":{d},\"timing_stages\":", .{
            self.target_url,
            self.effective_url,
            self.host,
            self.port,
            self.scheme,
            self.status_code,
            self.status_line,
            self.failure_category.toSlice(),
            self.elapsed_ns,
        });
        try self.timing_stages.toJson(writer);
        try writer.print(",\"response_size_bytes\":{d},\"body_persisted\":{s},\"hsts_header\":", .{
            self.response_size_bytes,
            if (self.body_persisted) "true" else "false",
        });
        if (self.hsts_header) |h| try writer.print("\"{s}\"", .{h}) else try writer.writeAll("null");
        try writer.writeAll(",\"csp_header\":");
        if (self.csp_header) |c| try writer.print("\"{s}\"", .{c}) else try writer.writeAll("null");
        try writer.writeAll(",\"content_type_options\":");
        if (self.content_type_options) |o| try writer.print("\"{s}\"", .{o}) else try writer.writeAll("null");
        try writer.writeAll(",\"redirect_target\":");
        if (self.redirect_target) |r| try writer.print("\"{s}\"", .{r}) else try writer.writeAll("null");
        try writer.print(",\"redirect_count\":{d},\"redirect_chain\":[", .{self.redirect_count});
        for (self.redirect_chain, 0..) |hop, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.print("{{\"url\":\"{s}\",\"status_code\":{d},\"elapsed_ns\":{d}}}", .{
                hop.url,
                hop.status_code,
                hop.elapsed_ns,
            });
        }
        try writer.writeAll("],\"verification_bypassed\":");
        try writer.writeAll(if (self.verification_bypassed) "true" else "false");
        try writer.writeAll(",\"err\":");
        try self.err.toJson(writer);
        try writer.writeAll(",\"troubleshooting\":");
        const tb = generateHttpsTroubleshooting(self);
        try tb.toJson(writer);
        try writer.writeAll("}");
    }
};

/// Target URL structure parsed from user input or redirection headers
pub const ParsedUrl = struct {
    scheme: []const u8,
    host: []const u8,
    port: u16,
    path: []const u8,

    pub fn deinit(self: *ParsedUrl, allocator: std.mem.Allocator) void {
        allocator.free(self.scheme);
        allocator.free(self.host);
        allocator.free(self.path);
    }
};

/// Parses raw URL string or bare host:port into structured ParsedUrl
pub fn parseUrl(allocator: std.mem.Allocator, raw: []const u8) !ParsedUrl {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return error.EmptyUrl;

    var scheme: []const u8 = "https";
    var rest = trimmed;

    if (std.mem.startsWith(u8, trimmed, "https://")) {
        scheme = "https";
        rest = trimmed["https://".len..];
    } else if (std.mem.startsWith(u8, trimmed, "http://")) {
        scheme = "http";
        rest = trimmed["http://".len..];
    }

    // Split host:port from path
    const slash_idx = std.mem.indexOfScalar(u8, rest, '/');
    const host_port_part = if (slash_idx) |idx| rest[0..idx] else rest;
    const path_part = if (slash_idx) |idx| rest[idx..] else "/";

    if (host_port_part.len == 0) return error.EmptyHostname;

    var host: []const u8 = host_port_part;
    var port: u16 = if (std.mem.eql(u8, scheme, "https")) 443 else 80;

    // Check for explicit port
    if (std.mem.lastIndexOfScalar(u8, host_port_part, ':')) |colon_idx| {
        // Bracketed IPv6 check
        if (std.mem.startsWith(u8, host_port_part, "[")) {
            if (std.mem.indexOfScalar(u8, host_port_part, ']')) |rb_idx| {
                if (colon_idx > rb_idx) {
                    host = host_port_part[1..rb_idx];
                    const p_str = host_port_part[colon_idx + 1 ..];
                    port = try tcp.validatePort(try std.fmt.parseInt(u32, p_str, 10));
                } else {
                    host = host_port_part[1..rb_idx];
                }
            }
        } else {
            host = host_port_part[0..colon_idx];
            const p_str = host_port_part[colon_idx + 1 ..];
            port = try tcp.validatePort(try std.fmt.parseInt(u32, p_str, 10));
        }
    }

    return ParsedUrl{
        .scheme = try allocator.dupe(u8, scheme),
        .host = try allocator.dupe(u8, host),
        .port = port,
        .path = try allocator.dupe(u8, path_part),
    };
}

/// Validates whether a redirect URL is permitted by the approved assessment scope
pub fn isRedirectPermitted(
    initial_host: []const u8,
    initial_port: u16,
    redirect_url: []const u8,
    allow_expansion: bool,
    maybe_profile: ?*const AssessmentProfile,
    allocator: std.mem.Allocator,
) bool {
    if (allow_expansion) return true;

    var parsed = parseUrl(allocator, redirect_url) catch return false;
    defer parsed.deinit(allocator);

    if (maybe_profile) |prof| {
        return prof.isScopePermitted(parsed.host, parsed.port);
    }

    // Default scope guard: must match initial host
    _ = initial_port;
    return std.ascii.eqlIgnoreCase(initial_host, parsed.host);
}

/// Abstract interface for executing HTTPS probe operations (enables hermetic integration testing)
pub const HttpsConnector = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        probe: *const fn (
            ctx: *anyopaque,
            allocator: std.mem.Allocator,
            target_url: []const u8,
            config: HttpsConfig,
            cancel_token: ?*const CancellationToken,
            maybe_profile: ?*const AssessmentProfile,
            now_sec: i64,
        ) anyerror!HttpsProbeResult,
    };

    pub fn probe(
        self: HttpsConnector,
        allocator: std.mem.Allocator,
        target_url: []const u8,
        config: HttpsConfig,
        cancel_token: ?*const CancellationToken,
        maybe_profile: ?*const AssessmentProfile,
        now_sec: i64,
    ) !HttpsProbeResult {
        return self.vtable.probe(self.ptr, allocator, target_url, config, cancel_token, maybe_profile, now_sec);
    }
};

/// Mock HTTPS connector supporting all synthetic fixtures and error paths hermetically
pub const MockHttpsConnector = struct {
    fixture_type: fixtures.FixtureType = .success_200,
    mock_status_code: u16 = 200,
    mock_hsts: ?[]const u8 = "max-age=31536000; includeSubDomains",
    mock_csp: ?[]const u8 = "default-src 'self'",
    mock_content_type_options: ?[]const u8 = "nosniff",
    mock_response_size: usize = 128,
    custom_latency_ns: u64 = 4_000_000,

    pub fn connector(self: *MockHttpsConnector) HttpsConnector {
        return .{
            .ptr = self,
            .vtable = &.{
                .probe = probeImpl,
            },
        };
    }

    fn probeImpl(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        target_url: []const u8,
        config: HttpsConfig,
        cancel_token: ?*const CancellationToken,
        maybe_profile: ?*const AssessmentProfile,
        now_sec: i64,
    ) anyerror!HttpsProbeResult {
        const self: *MockHttpsConnector = @ptrCast(@alignCast(ctx));
        _ = now_sec;

        var parsed = try parseUrl(allocator, target_url);
        defer parsed.deinit(allocator);

        if (cancel_token) |token| {
            if (token.isCancelled()) {
                return HttpsProbeResult{
                    .target_url = try allocator.dupe(u8, target_url),
                    .effective_url = try allocator.dupe(u8, target_url),
                    .host = try allocator.dupe(u8, parsed.host),
                    .port = parsed.port,
                    .scheme = try allocator.dupe(u8, parsed.scheme),
                    .status_code = 0,
                    .status_line = try allocator.dupe(u8, "none"),
                    .failure_category = .cancelled,
                    .elapsed_ns = 20_000,
                    .timing_stages = .{},
                    .err = .{ .code = .operation_cancelled, .message = "Operation cancelled before execution" },
                };
            }
        }

        switch (self.fixture_type) {
            .cancelled => {
                return HttpsProbeResult{
                    .target_url = try allocator.dupe(u8, target_url),
                    .effective_url = try allocator.dupe(u8, target_url),
                    .host = try allocator.dupe(u8, parsed.host),
                    .port = parsed.port,
                    .scheme = try allocator.dupe(u8, parsed.scheme),
                    .status_code = 0,
                    .status_line = try allocator.dupe(u8, "none"),
                    .failure_category = .cancelled,
                    .elapsed_ns = 50_000,
                    .timing_stages = .{},
                    .err = .{ .code = .operation_cancelled, .message = "Operation cancelled" },
                };
            },
            .timeout => {
                return HttpsProbeResult{
                    .target_url = try allocator.dupe(u8, target_url),
                    .effective_url = try allocator.dupe(u8, target_url),
                    .host = try allocator.dupe(u8, parsed.host),
                    .port = parsed.port,
                    .scheme = try allocator.dupe(u8, parsed.scheme),
                    .status_code = 0,
                    .status_line = try allocator.dupe(u8, "none"),
                    .failure_category = .timeout,
                    .elapsed_ns = @as(u64, @intCast(config.timeout_ms)) * std.time.ns_per_ms,
                    .timing_stages = .{
                        .tcp_connect_ns = 500_000,
                        .total_elapsed_ns = @as(u64, @intCast(config.timeout_ms)) * std.time.ns_per_ms,
                    },
                    .err = .{ .code = .connection_timed_out, .message = "Operation timed out waiting for HTTP response" },
                };
            },
            .invalid_certificate => {
                return HttpsProbeResult{
                    .target_url = try allocator.dupe(u8, target_url),
                    .effective_url = try allocator.dupe(u8, target_url),
                    .host = try allocator.dupe(u8, parsed.host),
                    .port = parsed.port,
                    .scheme = try allocator.dupe(u8, parsed.scheme),
                    .status_code = 0,
                    .status_line = try allocator.dupe(u8, "none"),
                    .failure_category = .tls_hostname_mismatch,
                    .elapsed_ns = 1_500_000,
                    .timing_stages = .{
                        .tcp_connect_ns = 500_000,
                        .tls_handshake_ns = 1_000_000,
                        .total_elapsed_ns = 1_500_000,
                    },
                    .tls_verified = false,
                    .err = .{ .code = .tls_hostname_mismatch, .message = "Server certificate does not match requested hostname" },
                };
            },
            .oversized_response => {
                return HttpsProbeResult{
                    .target_url = try allocator.dupe(u8, target_url),
                    .effective_url = try allocator.dupe(u8, target_url),
                    .host = try allocator.dupe(u8, parsed.host),
                    .port = parsed.port,
                    .scheme = try allocator.dupe(u8, parsed.scheme),
                    .status_code = 200,
                    .status_line = try allocator.dupe(u8, "HTTP/1.1 200 OK"),
                    .failure_category = .response_size_exceeded,
                    .elapsed_ns = 2_500_000,
                    .timing_stages = .{
                        .tcp_connect_ns = 500_000,
                        .tls_handshake_ns = 1_000_000,
                        .http_ttfb_ns = 800_000,
                        .http_transfer_ns = 200_000,
                        .total_elapsed_ns = 2_500_000,
                    },
                    .response_size_bytes = config.max_response_bytes + 1024,
                    .body_persisted = false,
                    .err = .{ .code = .http_response_oversized, .message = "HTTP response exceeded configured maximum response size" },
                };
            },
            .redirect_out_of_scope => {
                const redirect_dst = "https://unauthorized-evil.test/login";
                const is_allowed = isRedirectPermitted(parsed.host, parsed.port, redirect_dst, config.allow_redirect_scope_expansion, maybe_profile, allocator);

                if (!is_allowed) {
                    var chain = try allocator.alloc(RedirectHop, 1);
                    chain[0] = .{
                        .url = try allocator.dupe(u8, redirect_dst),
                        .status_code = 302,
                        .elapsed_ns = 1_200_000,
                    };

                    return HttpsProbeResult{
                        .target_url = try allocator.dupe(u8, target_url),
                        .effective_url = try allocator.dupe(u8, target_url),
                        .host = try allocator.dupe(u8, parsed.host),
                        .port = parsed.port,
                        .scheme = try allocator.dupe(u8, parsed.scheme),
                        .status_code = 302,
                        .status_line = try allocator.dupe(u8, "HTTP/1.1 302 Found"),
                        .failure_category = .redirect_out_of_scope,
                        .elapsed_ns = 1_200_000,
                        .timing_stages = .{
                            .tcp_connect_ns = 400_000,
                            .tls_handshake_ns = 600_000,
                            .http_ttfb_ns = 200_000,
                            .total_elapsed_ns = 1_200_000,
                        },
                        .redirect_target = try allocator.dupe(u8, redirect_dst),
                        .redirect_count = 1,
                        .redirect_chain = chain,
                        .err = .{ .code = .out_of_scope_target, .message = "Redirect destination escapes approved assessment scope", .details = redirect_dst },
                    };
                }

                // If allowed, fall through to 200 OK
                return HttpsProbeResult{
                    .target_url = try allocator.dupe(u8, target_url),
                    .effective_url = try allocator.dupe(u8, redirect_dst),
                    .host = try allocator.dupe(u8, "unauthorized-evil.test"),
                    .port = 443,
                    .scheme = try allocator.dupe(u8, "https"),
                    .status_code = 200,
                    .status_line = try allocator.dupe(u8, "HTTP/1.1 200 OK"),
                    .failure_category = .success,
                    .elapsed_ns = 2_500_000,
                    .timing_stages = .{
                        .tcp_connect_ns = 500_000,
                        .tls_handshake_ns = 1_000_000,
                        .http_ttfb_ns = 600_000,
                        .http_transfer_ns = 400_000,
                        .total_elapsed_ns = 2_500_000,
                    },
                    .redirect_count = 1,
                };
            },
            .redirect_loop => {
                var chain = try allocator.alloc(RedirectHop, 2);
                chain[0] = .{
                    .url = try allocator.dupe(u8, "https://localhost:443/loop-b"),
                    .status_code = 302,
                    .elapsed_ns = 800_000,
                };
                chain[1] = .{
                    .url = try allocator.dupe(u8, "https://localhost:443/loop-a"),
                    .status_code = 302,
                    .elapsed_ns = 1_600_000,
                };

                return HttpsProbeResult{
                    .target_url = try allocator.dupe(u8, target_url),
                    .effective_url = try allocator.dupe(u8, "https://localhost:443/loop-a"),
                    .host = try allocator.dupe(u8, parsed.host),
                    .port = parsed.port,
                    .scheme = try allocator.dupe(u8, parsed.scheme),
                    .status_code = 302,
                    .status_line = try allocator.dupe(u8, "HTTP/1.1 302 Found"),
                    .failure_category = .redirect_loop,
                    .elapsed_ns = 1_600_000,
                    .timing_stages = .{
                        .tcp_connect_ns = 400_000,
                        .tls_handshake_ns = 600_000,
                        .http_ttfb_ns = 300_000,
                        .http_transfer_ns = 300_000,
                        .total_elapsed_ns = 1_600_000,
                    },
                    .redirect_target = try allocator.dupe(u8, "https://localhost:443/loop-a"),
                    .redirect_count = 2,
                    .redirect_chain = chain,
                    .err = .{ .code = .http_redirect_loop, .message = "Circular redirect loop detected in HTTP redirection chain" },
                };
            },
            .redirect_limit_exceeded => {
                var chain = try allocator.alloc(RedirectHop, config.max_redirects);
                var idx: usize = 0;
                while (idx < config.max_redirects) : (idx += 1) {
                    const hop_url = try std.fmt.allocPrint(allocator, "https://localhost:443/hop-{d}", .{idx + 1});
                    chain[idx] = .{
                        .url = hop_url,
                        .status_code = 302,
                        .elapsed_ns = @as(u64, @intCast(idx + 1)) * 500_000,
                    };
                }

                return HttpsProbeResult{
                    .target_url = try allocator.dupe(u8, target_url),
                    .effective_url = try allocator.dupe(u8, chain[chain.len - 1].url),
                    .host = try allocator.dupe(u8, parsed.host),
                    .port = parsed.port,
                    .scheme = try allocator.dupe(u8, parsed.scheme),
                    .status_code = 302,
                    .status_line = try allocator.dupe(u8, "HTTP/1.1 302 Found"),
                    .failure_category = .redirect_limit_exceeded,
                    .elapsed_ns = @as(u64, @intCast(config.max_redirects)) * 500_000,
                    .timing_stages = .{
                        .total_elapsed_ns = @as(u64, @intCast(config.max_redirects)) * 500_000,
                    },
                    .redirect_count = config.max_redirects,
                    .redirect_chain = chain,
                    .err = .{ .code = .http_redirect_loop, .message = "HTTP redirection chain exceeded maximum configured limit" },
                };
            },
            .redirect_in_scope => {
                var chain = try allocator.alloc(RedirectHop, 1);
                chain[0] = .{
                    .url = try allocator.dupe(u8, "https://localhost:443/destination"),
                    .status_code = 301,
                    .elapsed_ns = 1_000_000,
                };

                return HttpsProbeResult{
                    .target_url = try allocator.dupe(u8, target_url),
                    .effective_url = try allocator.dupe(u8, "https://localhost:443/destination"),
                    .host = try allocator.dupe(u8, parsed.host),
                    .port = parsed.port,
                    .scheme = try allocator.dupe(u8, parsed.scheme),
                    .status_code = 200,
                    .status_line = try allocator.dupe(u8, "HTTP/1.1 200 OK"),
                    .failure_category = .success,
                    .elapsed_ns = 2_500_000,
                    .timing_stages = .{
                        .tcp_connect_ns = 600_000,
                        .tls_handshake_ns = 1_000_000,
                        .http_ttfb_ns = 500_000,
                        .http_transfer_ns = 400_000,
                        .total_elapsed_ns = 2_500_000,
                    },
                    .hsts_header = try allocator.dupe(u8, "max-age=31536000; includeSubDomains"),
                    .csp_header = try allocator.dupe(u8, "default-src 'self'"),
                    .content_type_options = try allocator.dupe(u8, "nosniff"),
                    .response_size_bytes = 120,
                    .body_persisted = false,
                    .redirect_count = 1,
                    .redirect_chain = chain,
                };
            },
            .success_200 => {
                return HttpsProbeResult{
                    .target_url = try allocator.dupe(u8, target_url),
                    .effective_url = try allocator.dupe(u8, target_url),
                    .host = try allocator.dupe(u8, parsed.host),
                    .port = parsed.port,
                    .scheme = try allocator.dupe(u8, parsed.scheme),
                    .status_code = self.mock_status_code,
                    .status_line = try allocator.dupe(u8, "HTTP/1.1 200 OK"),
                    .failure_category = .success,
                    .elapsed_ns = self.custom_latency_ns,
                    .timing_stages = .{
                        .tcp_connect_ns = 1_000_000,
                        .tls_handshake_ns = 1_800_000,
                        .http_ttfb_ns = 800_000,
                        .http_transfer_ns = 400_000,
                        .total_elapsed_ns = self.custom_latency_ns,
                    },
                    .hsts_header = if (self.mock_hsts) |h| try allocator.dupe(u8, h) else null,
                    .csp_header = if (self.mock_csp) |c| try allocator.dupe(u8, c) else null,
                    .content_type_options = if (self.mock_content_type_options) |o| try allocator.dupe(u8, o) else null,
                    .response_size_bytes = self.mock_response_size,
                    .body_persisted = false,
                    .redirect_count = 0,
                    .tls_protocol_version = try allocator.dupe(u8, "TLSv1.3"),
                    .tls_cipher_suite = try allocator.dupe(u8, "TLS_AES_128_GCM_SHA256"),
                    .tls_certificate_subject = try allocator.dupe(u8, parsed.host),
                    .tls_certificate_issuer = try allocator.dupe(u8, "WireScope Test Root CA"),
                    .tls_verified = !config.insecure_skip_verify,
                    .verification_bypassed = config.insecure_skip_verify,
                };
            },
        }
    }
};

/// High-level function to execute an HTTPS probe with timing stages, redirect limits, and response bounds
pub fn executeHttpsProbe(
    allocator: std.mem.Allocator,
    raw_target: []const u8,
    config: HttpsConfig,
    connector: HttpsConnector,
    cancel_token: ?*const CancellationToken,
    maybe_profile: ?*const AssessmentProfile,
    now_sec: i64,
) !HttpsProbeResult {
    // 1. Input syntax validation before network operations
    var parsed = parseUrl(allocator, raw_target) catch |err| {
        return HttpsProbeResult{
            .target_url = try allocator.dupe(u8, raw_target),
            .effective_url = try allocator.dupe(u8, raw_target),
            .host = try allocator.dupe(u8, "invalid"),
            .port = 0,
            .scheme = try allocator.dupe(u8, "none"),
            .status_code = 0,
            .status_line = try allocator.dupe(u8, "none"),
            .failure_category = .malformed_input,
            .elapsed_ns = 0,
            .timing_stages = .{},
            .err = .{
                .code = .parse_error,
                .message = "Invalid URL syntax or target specification",
                .details = @errorName(err),
            },
        };
    };
    defer parsed.deinit(allocator);

    // 2. Dispatch probe execution
    return try connector.probe(
        allocator,
        raw_target,
        config,
        cancel_token,
        maybe_profile,
        now_sec,
    );
}

// -------------------------------------------------------------------------
// UNIT & CONTROLLED INTEGRATION TESTS (Zero public network dependency)
// -------------------------------------------------------------------------

test "https probe: separate timing stages accurately measured and labeled" {
    var mock = MockHttpsConnector{ .fixture_type = .success_200 };
    const connector = mock.connector();

    var res = try executeHttpsProbe(
        testing.allocator,
        "https://localhost:443/",
        .{},
        connector,
        null,
        null,
        std.time.timestamp(),
    );
    defer res.deinit(testing.allocator);

    try testing.expectEqual(HttpsFailureCategory.success, res.failure_category);
    try testing.expect(res.timing_stages.tcp_connect_ns != null);
    try testing.expect(res.timing_stages.tls_handshake_ns != null);
    try testing.expect(res.timing_stages.http_ttfb_ns != null);
    try testing.expect(res.timing_stages.http_transfer_ns != null);
    try testing.expect(res.timing_stages.total_elapsed_ns > 0);

    // Verify stages are distinct
    try testing.expect(res.timing_stages.tcp_connect_ns.? != res.timing_stages.tls_handshake_ns.?);
    try testing.expect(res.timing_stages.http_ttfb_ns.? != res.timing_stages.http_transfer_ns.?);
}

test "https probe: response body is not persisted by default (privacy invariant)" {
    var mock = MockHttpsConnector{ .fixture_type = .success_200 };
    const connector = mock.connector();

    var res = try executeHttpsProbe(
        testing.allocator,
        "https://localhost:443/",
        .{},
        connector,
        null,
        null,
        std.time.timestamp(),
    );
    defer res.deinit(testing.allocator);

    try testing.expect(!res.body_persisted);
    try testing.expect(res.response_size_bytes > 0);
}

test "https probe: oversized response bound enforcement" {
    var mock = MockHttpsConnector{ .fixture_type = .oversized_response };
    const connector = mock.connector();

    var res = try executeHttpsProbe(
        testing.allocator,
        "https://localhost:443/huge-file",
        .{ .max_response_bytes = 1024 }, // Max 1KB
        connector,
        null,
        null,
        std.time.timestamp(),
    );
    defer res.deinit(testing.allocator);

    try testing.expectEqual(HttpsFailureCategory.response_size_exceeded, res.failure_category);
    try testing.expectEqual(ErrorCode.http_response_oversized, res.err.code);
    try testing.expectEqual(OutcomeCategory.operational_failure, res.failure_category.toOutcome());
}

test "https probe: redirect scope guard prevents escaping approved scope" {
    var mock = MockHttpsConnector{ .fixture_type = .redirect_out_of_scope };
    const connector = mock.connector();

    // Default configuration: allow_redirect_scope_expansion = false
    var res = try executeHttpsProbe(
        testing.allocator,
        "https://localhost:443/login",
        .{ .allow_redirect_scope_expansion = false },
        connector,
        null,
        null,
        std.time.timestamp(),
    );
    defer res.deinit(testing.allocator);

    // Must be blocked by scope guard!
    try testing.expectEqual(HttpsFailureCategory.redirect_out_of_scope, res.failure_category);
    try testing.expectEqual(ErrorCode.out_of_scope_target, res.err.code);
    try testing.expectEqual(OutcomeCategory.invalid_input, res.failure_category.toOutcome());
    try testing.expectEqualStrings("https://unauthorized-evil.test/login", res.redirect_target.?);
}

test "https probe: redirect loop detection" {
    var mock = MockHttpsConnector{ .fixture_type = .redirect_loop };
    const connector = mock.connector();

    var res = try executeHttpsProbe(
        testing.allocator,
        "https://localhost:443/loop-a",
        .{},
        connector,
        null,
        null,
        std.time.timestamp(),
    );
    defer res.deinit(testing.allocator);

    try testing.expectEqual(HttpsFailureCategory.redirect_loop, res.failure_category);
    try testing.expectEqual(ErrorCode.http_redirect_loop, res.err.code);
    try testing.expect(res.redirect_count >= 2);
}

test "https probe: redirect limit threshold enforcement" {
    var mock = MockHttpsConnector{ .fixture_type = .redirect_limit_exceeded };
    const connector = mock.connector();

    var res = try executeHttpsProbe(
        testing.allocator,
        "https://localhost:443/cascade",
        .{ .max_redirects = 3 },
        connector,
        null,
        null,
        std.time.timestamp(),
    );
    defer res.deinit(testing.allocator);

    try testing.expectEqual(HttpsFailureCategory.redirect_limit_exceeded, res.failure_category);
    try testing.expectEqual(@as(u32, 3), res.redirect_count);
}

test "https probe: in-scope redirect followed successfully" {
    var mock = MockHttpsConnector{ .fixture_type = .redirect_in_scope };
    const connector = mock.connector();

    var res = try executeHttpsProbe(
        testing.allocator,
        "https://localhost:443/old-page",
        .{},
        connector,
        null,
        null,
        std.time.timestamp(),
    );
    defer res.deinit(testing.allocator);

    try testing.expectEqual(HttpsFailureCategory.success, res.failure_category);
    try testing.expectEqual(@as(u16, 200), res.status_code);
    try testing.expectEqual(@as(u32, 1), res.redirect_count);
    try testing.expectEqualStrings("https://localhost:443/destination", res.effective_url);
}

test "https probe: invalid certificate aborts handshake" {
    var mock = MockHttpsConnector{ .fixture_type = .invalid_certificate };
    const connector = mock.connector();

    var res = try executeHttpsProbe(
        testing.allocator,
        "https://localhost:443/",
        .{},
        connector,
        null,
        null,
        std.time.timestamp(),
    );
    defer res.deinit(testing.allocator);

    try testing.expectEqual(HttpsFailureCategory.tls_hostname_mismatch, res.failure_category);
    try testing.expectEqual(ErrorCode.tls_hostname_mismatch, res.err.code);
    try testing.expect(!res.tls_verified);
}

test "https probe: timeout enforcement" {
    var mock = MockHttpsConnector{ .fixture_type = .timeout };
    const connector = mock.connector();

    var res = try executeHttpsProbe(
        testing.allocator,
        "https://localhost:443/",
        .{ .timeout_ms = 1500 },
        connector,
        null,
        null,
        std.time.timestamp(),
    );
    defer res.deinit(testing.allocator);

    try testing.expectEqual(HttpsFailureCategory.timeout, res.failure_category);
    try testing.expectEqual(ErrorCode.connection_timed_out, res.err.code);
    try testing.expectEqual(OutcomeCategory.timeout, res.failure_category.toOutcome());
}

test "https probe: cancellation stops work" {
    var mock = MockHttpsConnector{};
    const connector = mock.connector();

    var cancel_token = CancellationToken{};
    cancel_token.cancel();

    var res = try executeHttpsProbe(
        testing.allocator,
        "https://localhost:443/",
        .{},
        connector,
        &cancel_token,
        null,
        std.time.timestamp(),
    );
    defer res.deinit(testing.allocator);

    try testing.expectEqual(HttpsFailureCategory.cancelled, res.failure_category);
    try testing.expectEqual(OutcomeCategory.cancelled, res.failure_category.toOutcome());
}

test "https probe: serialization to envelope and json" {
    var mock = MockHttpsConnector{ .fixture_type = .success_200 };
    const connector = mock.connector();

    var res = try executeHttpsProbe(
        testing.allocator,
        "https://localhost:443/api/status",
        .{},
        connector,
        null,
        null,
        std.time.timestamp(),
    );
    defer res.deinit(testing.allocator);

    // Envelope
    var env = try res.toEnvelope(testing.allocator, "op_https_001", "prof_default");
    defer env.deinit(testing.allocator);

    try testing.expectEqual(OperationType.http, env.operation_type);
    try testing.expectEqualStrings("https://localhost:443/api/status", env.target);
    try testing.expectEqual(@as(u16, 200), env.payload.http.status_code);
    try testing.expectEqualStrings("max-age=31536000; includeSubDomains", env.payload.http.hsts_header.?);

    // JSON
    var json_buf = std.ArrayList(u8).init(testing.allocator);
    defer json_buf.deinit();
    try res.toJson(json_buf.writer());

    try testing.expect(std.mem.indexOf(u8, json_buf.items, "\"status_code\":200") != null);
    try testing.expect(std.mem.indexOf(u8, json_buf.items, "\"body_persisted\":false") != null);
    try testing.expect(std.mem.indexOf(u8, json_buf.items, "\"timing_stages\":{") != null);
    try testing.expect(std.mem.indexOf(u8, json_buf.items, "\"troubleshooting\":{") != null);

    // Terminal
    var term_buf = std.ArrayList(u8).init(testing.allocator);
    defer term_buf.deinit();
    try res.toTerminal(term_buf.writer());
    try testing.expect(std.mem.indexOf(u8, term_buf.items, "Timing Stages:") != null);
    try testing.expect(std.mem.indexOf(u8, term_buf.items, "TCP Connect:") != null);
    try testing.expect(std.mem.indexOf(u8, term_buf.items, "HTTP TTFB:") != null);
}
