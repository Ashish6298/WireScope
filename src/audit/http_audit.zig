const std = @import("std");
const testing = std.testing;

const core = @import("../core/root.zig");
const probes = @import("../probes/root.zig");
const assessment = @import("../assessment/root.zig");
const fixtures = @import("fixtures.zig");

pub const Severity = core.Severity;
pub const Confidence = core.Confidence;
pub const Finding = core.Finding;
pub const FindingStatus = core.FindingStatus;
pub const ParsedUrl = probes.ParsedUrl;
pub const parseUrl = probes.parseUrl;
pub const isRedirectPermitted = probes.isRedirectPermitted;
pub const CancellationToken = probes.CancellationToken;
pub const AssessmentProfile = assessment.AssessmentProfile;

/// Cookie SameSite policy attribute
pub const SameSitePolicy = enum {
    none,
    lax,
    strict,
    unspecified,

    pub fn toSlice(self: SameSitePolicy) []const u8 {
        return @tagName(self);
    }

    pub fn fromString(str: []const u8) SameSitePolicy {
        if (std.ascii.eqlIgnoreCase(str, "strict")) return .strict;
        if (std.ascii.eqlIgnoreCase(str, "lax")) return .lax;
        if (std.ascii.eqlIgnoreCase(str, "none")) return .none;
        return .unspecified;
    }
};

/// Parsed HTTP cookie with redacted value to enforce privacy invariants
pub const HttpCookie = struct {
    name: []const u8,
    value_redacted: []const u8, // Privacy invariant: values are always redacted!
    secure: bool = false,
    httponly: bool = false,
    samesite: SameSitePolicy = .unspecified,
    domain: ?[]const u8 = null,
    path: ?[]const u8 = null,
    raw_cookie: []const u8,

    pub fn deinit(self: *HttpCookie, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.value_redacted);
        if (self.domain) |d| allocator.free(d);
        if (self.path) |p| allocator.free(p);
        allocator.free(self.raw_cookie);
    }

    pub fn clone(self: *const HttpCookie, allocator: std.mem.Allocator) !HttpCookie {
        return HttpCookie{
            .name = try allocator.dupe(u8, self.name),
            .value_redacted = try allocator.dupe(u8, self.value_redacted),
            .secure = self.secure,
            .httponly = self.httponly,
            .samesite = self.samesite,
            .domain = if (self.domain) |d| try allocator.dupe(u8, d) else null,
            .path = if (self.path) |p| try allocator.dupe(u8, p) else null,
            .raw_cookie = try allocator.dupe(u8, self.raw_cookie),
        };
    }
};

/// Defensive HTTP security finding with explicit evidence, limitations, and false-positive caveats
pub const HttpAuditFinding = struct {
    rule_id: []const u8,
    rule_version: u32 = 1,
    title: []const u8,
    description: []const u8,
    severity: Severity,
    severity_rationale: []const u8,
    confidence: Confidence,
    affected_target: []const u8,
    evidence: []const u8,
    remediation: []const u8,
    false_positive_caveat: []const u8,
    limitations: []const u8,
    context_evaluation: []const u8,

    pub fn deinit(self: *HttpAuditFinding, allocator: std.mem.Allocator) void {
        allocator.free(self.rule_id);
        allocator.free(self.title);
        allocator.free(self.description);
        allocator.free(self.severity_rationale);
        allocator.free(self.affected_target);
        allocator.free(self.evidence);
        allocator.free(self.remediation);
        allocator.free(self.false_positive_caveat);
        allocator.free(self.limitations);
        allocator.free(self.context_evaluation);
    }

    pub fn clone(self: *const HttpAuditFinding, allocator: std.mem.Allocator) !HttpAuditFinding {
        return HttpAuditFinding{
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
            .false_positive_caveat = try allocator.dupe(u8, self.false_positive_caveat),
            .limitations = try allocator.dupe(u8, self.limitations),
            .context_evaluation = try allocator.dupe(u8, self.context_evaluation),
        };
    }

    pub fn toCoreFinding(self: *const HttpAuditFinding, allocator: std.mem.Allocator) !Finding {
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

/// Configuration options for HTTP security configuration audit
pub const HttpAuditConfig = struct {
    timeout_ms: u32 = 5000,
    max_redirects: u32 = 5,
    max_response_bytes: usize = 1024 * 1024, // 1 MB bound
    allow_redirect_scope_expansion: bool = false, // Security: Scope guard prevents unapproved redirect follow
    verify_certificates: bool = true,
    insecure_skip_verify: bool = false,
    custom_ca_path: ?[]const u8 = null,
};

/// Parsed HTTP response headers and structure
pub const ParsedHttpResponse = struct {
    status_code: u16 = 0,
    status_line: []const u8,
    content_type: ?[]const u8 = null,
    content_length: ?usize = null,
    hsts: ?[]const u8 = null,
    csp: ?[]const u8 = null,
    content_type_options: ?[]const u8 = null,
    x_frame_options: ?[]const u8 = null,
    referrer_policy: ?[]const u8 = null,
    server: ?[]const u8 = null,
    x_powered_by: ?[]const u8 = null,
    location: ?[]const u8 = null,
    cookies: []HttpCookie = &.{},
    raw_response_bytes: usize = 0,

    pub fn deinit(self: *ParsedHttpResponse, allocator: std.mem.Allocator) void {
        allocator.free(self.status_line);
        if (self.content_type) |c| allocator.free(c);
        if (self.hsts) |h| allocator.free(h);
        if (self.csp) |c| allocator.free(c);
        if (self.content_type_options) |o| allocator.free(o);
        if (self.x_frame_options) |f| allocator.free(f);
        if (self.referrer_policy) |r| allocator.free(r);
        if (self.server) |s| allocator.free(s);
        if (self.x_powered_by) |p| allocator.free(p);
        if (self.location) |l| allocator.free(l);

        for (self.cookies) |*c| {
            c.deinit(allocator);
        }
        if (self.cookies.len > 0) {
            allocator.free(self.cookies);
        }
    }
};

/// Parses raw HTTP response head into structured ParsedHttpResponse
pub fn parseHttpResponse(allocator: std.mem.Allocator, raw: []const u8) !ParsedHttpResponse {
    var result = ParsedHttpResponse{
        .status_line = try allocator.dupe(u8, "HTTP/1.1 0 None"),
        .raw_response_bytes = raw.len,
    };
    errdefer result.deinit(allocator);

    var cookie_list = std.ArrayList(HttpCookie).init(allocator);
    errdefer {
        for (cookie_list.items) |*c| c.deinit(allocator);
        cookie_list.deinit();
    }

    var lines = std.mem.splitScalar(u8, raw, '\n');
    var is_first_line = true;

    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \r\t");
        if (trimmed.len == 0) break; // End of HTTP headers

        if (is_first_line) {
            is_first_line = false;
            allocator.free(result.status_line);
            result.status_line = try allocator.dupe(u8, trimmed);

            // Parse status code: e.g. "HTTP/1.1 200 OK"
            var parts = std.mem.splitScalar(u8, trimmed, ' ');
            _ = parts.next(); // Skip "HTTP/1.1"
            if (parts.next()) |code_str| {
                result.status_code = std.fmt.parseInt(u16, code_str, 10) catch 0;
            }
            continue;
        }

        const colon_idx = std.mem.indexOfScalar(u8, trimmed, ':') orelse continue;
        const name = std.mem.trim(u8, trimmed[0..colon_idx], " \t");
        const val = std.mem.trim(u8, trimmed[colon_idx + 1 ..], " \t");

        if (std.ascii.eqlIgnoreCase(name, "Strict-Transport-Security")) {
            if (result.hsts == null) result.hsts = try allocator.dupe(u8, val);
        } else if (std.ascii.eqlIgnoreCase(name, "Content-Security-Policy")) {
            if (result.csp == null) result.csp = try allocator.dupe(u8, val);
        } else if (std.ascii.eqlIgnoreCase(name, "X-Content-Type-Options")) {
            if (result.content_type_options == null) result.content_type_options = try allocator.dupe(u8, val);
        } else if (std.ascii.eqlIgnoreCase(name, "X-Frame-Options")) {
            if (result.x_frame_options == null) result.x_frame_options = try allocator.dupe(u8, val);
        } else if (std.ascii.eqlIgnoreCase(name, "Referrer-Policy")) {
            if (result.referrer_policy == null) result.referrer_policy = try allocator.dupe(u8, val);
        } else if (std.ascii.eqlIgnoreCase(name, "Server")) {
            if (result.server == null) result.server = try allocator.dupe(u8, val);
        } else if (std.ascii.eqlIgnoreCase(name, "X-Powered-By")) {
            if (result.x_powered_by == null) result.x_powered_by = try allocator.dupe(u8, val);
        } else if (std.ascii.eqlIgnoreCase(name, "Location")) {
            if (result.location == null) result.location = try allocator.dupe(u8, val);
        } else if (std.ascii.eqlIgnoreCase(name, "Content-Type")) {
            if (result.content_type == null) result.content_type = try allocator.dupe(u8, val);
        } else if (std.ascii.eqlIgnoreCase(name, "Content-Length")) {
            result.content_length = std.fmt.parseInt(usize, val, 10) catch null;
        } else if (std.ascii.eqlIgnoreCase(name, "Set-Cookie")) {
            const parsed_cookie = try parseSingleCookie(allocator, val);
            try cookie_list.append(parsed_cookie);
        }
    }

    result.cookies = try cookie_list.toOwnedSlice();
    return result;
}

/// Parses a Set-Cookie header value into HttpCookie with redacted secret content
fn parseSingleCookie(allocator: std.mem.Allocator, cookie_str: []const u8) !HttpCookie {
    var name_str: []const u8 = "unknown";
    var secure: bool = false;
    var httponly: bool = false;
    var samesite: SameSitePolicy = .unspecified;
    var domain_str: ?[]const u8 = null;
    var path_str: ?[]const u8 = null;

    var parts = std.mem.splitScalar(u8, cookie_str, ';');
    var is_first = true;

    while (parts.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t");
        if (trimmed.len == 0) continue;

        if (is_first) {
            is_first = false;
            if (std.mem.indexOfScalar(u8, trimmed, '=')) |eq_idx| {
                name_str = trimmed[0..eq_idx];
            } else {
                name_str = trimmed;
            }
            continue;
        }

        if (std.ascii.eqlIgnoreCase(trimmed, "secure")) {
            secure = true;
        } else if (std.ascii.eqlIgnoreCase(trimmed, "httponly")) {
            httponly = true;
        } else if (std.ascii.startsWithIgnoreCase(trimmed, "samesite=")) {
            const s_val = std.mem.trim(u8, trimmed["samesite=".len..], " \t");
            samesite = SameSitePolicy.fromString(s_val);
        } else if (std.ascii.startsWithIgnoreCase(trimmed, "domain=")) {
            domain_str = std.mem.trim(u8, trimmed["domain=".len..], " \t");
        } else if (std.ascii.startsWithIgnoreCase(trimmed, "path=")) {
            path_str = std.mem.trim(u8, trimmed["path=".len..], " \t");
        }
    }

    return HttpCookie{
        .name = try allocator.dupe(u8, name_str),
        .value_redacted = try allocator.dupe(u8, "[REDACTED]"),
        .secure = secure,
        .httponly = httponly,
        .samesite = samesite,
        .domain = if (domain_str) |d| try allocator.dupe(u8, d) else null,
        .path = if (path_str) |p| try allocator.dupe(u8, p) else null,
        .raw_cookie = try allocator.dupe(u8, cookie_str),
    };
}

/// Comprehensive outcome of an HTTP security configuration audit
pub const HttpAuditResult = struct {
    target_url: []const u8,
    effective_url: []const u8,
    host: []const u8,
    port: u16,
    scheme: []const u8,
    status_code: u16,
    status_line: []const u8,
    response_size_bytes: usize,
    redirect_count: u32,
    redirect_chain: []probes.RedirectHop = &.{},
    redirect_scope_blocked: bool = false,
    out_of_scope_target: ?[]const u8 = null,
    is_api_endpoint: bool = false,
    content_type: ?[]const u8 = null,
    cookies: []HttpCookie = &.{},

    // Observed security headers
    hsts_header: ?[]const u8 = null,
    csp_header: ?[]const u8 = null,
    content_type_options: ?[]const u8 = null,
    x_frame_options: ?[]const u8 = null,
    referrer_policy: ?[]const u8 = null,
    server_header: ?[]const u8 = null,
    x_powered_by_header: ?[]const u8 = null,

    // Audit evaluations
    findings: []HttpAuditFinding = &.{},
    checks_total: u32 = 0,
    checks_passed: u32 = 0,
    operational_limitations: []const u8,
    elapsed_ns: u64 = 0,

    pub fn deinit(self: *HttpAuditResult, allocator: std.mem.Allocator) void {
        allocator.free(self.target_url);
        allocator.free(self.effective_url);
        allocator.free(self.host);
        allocator.free(self.scheme);
        allocator.free(self.status_line);
        if (self.content_type) |c| allocator.free(c);
        if (self.out_of_scope_target) |t| allocator.free(t);
        if (self.hsts_header) |h| allocator.free(h);
        if (self.csp_header) |c| allocator.free(c);
        if (self.content_type_options) |o| allocator.free(o);
        if (self.x_frame_options) |f| allocator.free(f);
        if (self.referrer_policy) |r| allocator.free(r);
        if (self.server_header) |s| allocator.free(s);
        if (self.x_powered_by_header) |p| allocator.free(p);
        allocator.free(self.operational_limitations);

        for (self.cookies) |*c| c.deinit(allocator);
        if (self.cookies.len > 0) allocator.free(self.cookies);

        for (self.redirect_chain) |*hop| hop.deinit(allocator);
        if (self.redirect_chain.len > 0) allocator.free(self.redirect_chain);

        for (self.findings) |*f| f.deinit(allocator);
        if (self.findings.len > 0) allocator.free(self.findings);
    }

    pub fn hasHighOrCriticalFindings(self: *const HttpAuditResult) bool {
        for (self.findings) |f| {
            if (f.severity == .high or f.severity == .critical) return true;
        }
        return false;
    }

    /// Renders human-readable defensive audit findings for terminal output
    pub fn toTerminal(self: *const HttpAuditResult, writer: anytype) !void {
        try writer.print("================================================================================\n", .{});
        try writer.print("WIRESCOPE DEFENSIVE HTTP SECURITY AUDIT\n", .{});
        try writer.print("================================================================================\n", .{});
        try writer.print("Target URL:      {s}\n", .{self.target_url});
        try writer.print("Effective URL:   {s}\n", .{self.effective_url});
        try writer.print("Response Status: {d} ({s})\n", .{ self.status_code, self.status_line });
        try writer.print("Endpoint Type:   {s} (Content-Type: {s})\n", .{
            if (self.is_api_endpoint) "API/Data" else "Web/Document",
            self.content_type orelse "unspecified",
        });
        try writer.print("Response Size:   {d} bytes (Body not retained in memory or disk)\n", .{self.response_size_bytes});
        if (self.redirect_count > 0) {
            try writer.print("Redirect Hops:   {d}\n", .{self.redirect_count});
            for (self.redirect_chain, 0..) |hop, i| {
                try writer.print("  [{d}] {d} -> {s}\n", .{ i + 1, hop.status_code, hop.url });
            }
        }
        if (self.redirect_scope_blocked) {
            try writer.print("SCOPE GUARD:     Redirect to '{s}' blocked (escapes approved scope)!\n", .{self.out_of_scope_target orelse "unknown"});
        }

        try writer.writeAll("\n--- SECURITY CONFIGURATION INVENTORY ---\n");
        try writer.print("  * HSTS:                 {s}\n", .{self.hsts_header orelse "MISSING"});
        try writer.print("  * CSP:                  {s}\n", .{self.csp_header orelse "MISSING"});
        try writer.print("  * X-Content-Type:       {s}\n", .{self.content_type_options orelse "MISSING"});
        try writer.print("  * X-Frame-Options:      {s}\n", .{self.x_frame_options orelse "MISSING"});
        try writer.print("  * Referrer-Policy:      {s}\n", .{self.referrer_policy orelse "MISSING"});
        try writer.print("  * Server:               {s}\n", .{self.server_header orelse "Not disclosed"});
        try writer.print("  * X-Powered-By:         {s}\n", .{self.x_powered_by_header orelse "Not disclosed"});

        if (self.cookies.len > 0) {
            try writer.print("\n--- COOKIE SECURITY ATTRIBUTES ({d} observed) ---\n", .{self.cookies.len});
            for (self.cookies, 0..) |c, i| {
                try writer.print("  [{d}] Cookie '{s}': Secure={s}, HttpOnly={s}, SameSite={s}\n", .{
                    i + 1,
                    c.name,
                    if (c.secure) "Yes" else "NO",
                    if (c.httponly) "Yes" else "NO",
                    c.samesite.toSlice(),
                });
            }
        }

        try writer.writeAll("\n--- DEFENSIVE AUDIT FINDINGS ---\n");
        if (self.findings.len == 0) {
            try writer.writeAll("No defensive security configuration issues detected. Endpoint conforms to baseline rules.\n");
        } else {
            for (self.findings, 0..) |f, i| {
                try writer.print("\n[{d}] [{s}] {s} ({s})\n", .{ i + 1, f.severity.toSlice(), f.title, f.rule_id });
                try writer.print("    Severity Rationale: {s}\n", .{f.severity_rationale});
                try writer.print("    Evidence:           {s}\n", .{f.evidence});
                try writer.print("    Context Evaluation: {s}\n", .{f.context_evaluation});
                try writer.print("    Remediation:        {s}\n", .{f.remediation});
                try writer.print("    Caveat:             {s}\n", .{f.false_positive_caveat});
                try writer.print("    Limitations:        {s}\n", .{f.limitations});
            }
        }

        try writer.writeAll("\n--- AUDIT SUMMARY ---\n");
        try writer.print("Checks evaluated: {d} | Compliant: {d} | Findings: {d}\n", .{
            self.checks_total,
            self.checks_passed,
            self.findings.len,
        });
        try writer.print("Operational limitations: {s}\n", .{self.operational_limitations});
        try writer.print("WireScope Disclaimer: Missing headers are evaluated defensively; absence does not automatically indicate an exploitable vulnerability. No exploit or bypass tests performed.\n", .{});
        try writer.print("================================================================================\n", .{});
    }

    /// Renders versioned, structured JSON output
    pub fn toJson(self: *const HttpAuditResult, writer: anytype) !void {
        try writer.print("{{\"audit_type\":\"http_security_configuration\",\"schema_version\":1,\"target_url\":\"{s}\",\"effective_url\":\"{s}\",\"host\":\"{s}\",\"port\":{d},\"scheme\":\"{s}\",\"status_code\":{d},\"status_line\":\"{s}\",\"response_size_bytes\":{d},\"is_api_endpoint\":{s},\"content_type\":", .{
            self.target_url,
            self.effective_url,
            self.host,
            self.port,
            self.scheme,
            self.status_code,
            self.status_line,
            self.response_size_bytes,
            if (self.is_api_endpoint) "true" else "false",
        });
        if (self.content_type) |c| try writer.print("\"{s}\"", .{c}) else try writer.writeAll("null");

        try writer.print(",\"redirect\":{{\"count\":{d},\"scope_blocked\":{s},\"out_of_scope_target\":", .{
            self.redirect_count,
            if (self.redirect_scope_blocked) "true" else "false",
        });
        if (self.out_of_scope_target) |t| try writer.print("\"{s}\"", .{t}) else try writer.writeAll("null");
        try writer.writeAll(",\"chain\":[");
        for (self.redirect_chain, 0..) |hop, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.print("{{\"url\":\"{s}\",\"status_code\":{d},\"elapsed_ns\":{d}}}", .{
                hop.url,
                hop.status_code,
                hop.elapsed_ns,
            });
        }
        try writer.writeAll("]}");

        try writer.writeAll(",\"headers\":{");
        try writeNullableJsonString(writer, "\"hsts\":", self.hsts_header);
        try writer.writeAll(",");
        try writeNullableJsonString(writer, "\"csp\":", self.csp_header);
        try writer.writeAll(",");
        try writeNullableJsonString(writer, "\"content_type_options\":", self.content_type_options);
        try writer.writeAll(",");
        try writeNullableJsonString(writer, "\"x_frame_options\":", self.x_frame_options);
        try writer.writeAll(",");
        try writeNullableJsonString(writer, "\"referrer_policy\":", self.referrer_policy);
        try writer.writeAll(",");
        try writeNullableJsonString(writer, "\"server\":", self.server_header);
        try writer.writeAll(",");
        try writeNullableJsonString(writer, "\"x_powered_by\":", self.x_powered_by_header);
        try writer.writeAll("}");

        try writer.writeAll(",\"cookies\":[");
        for (self.cookies, 0..) |c, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.print("{{\"name\":\"{s}\",\"value_redacted\":\"{s}\",\"secure\":{s},\"httponly\":{s},\"samesite\":\"{s}\"}}", .{
                c.name,
                c.value_redacted,
                if (c.secure) "true" else "false",
                if (c.httponly) "true" else "false",
                c.samesite.toSlice(),
            });
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

        try writer.print(",\"summary\":{{\"checks_total\":{d},\"checks_passed\":{d},\"findings_count\":{d},\"has_high_or_critical\":{s}}}", .{
            self.checks_total,
            self.checks_passed,
            self.findings.len,
            if (self.hasHighOrCriticalFindings()) "true" else "false",
        });
        try writer.writeAll(",\"limitations\":");
        try writeJsonStringEscaped(writer, self.operational_limitations);
        try writer.writeAll("}\n");
    }

    /// Renders GitHub Flavored Markdown report with callouts and tables
    pub fn toMarkdown(self: *const HttpAuditResult, writer: anytype) !void {
        try writer.print("# WireScope Defensive HTTP Security Audit Report\n\n", .{});
        try writer.print("**Target:** `{s}`  \n", .{self.target_url});
        try writer.print("**Effective URL:** `{s}`  \n", .{self.effective_url});
        try writer.print("**Response:** `{d} {s}`  \n", .{ self.status_code, self.status_line });
        try writer.print("**Response Size:** {d} bytes (response bodies are bounded and never retained)  \n\n", .{self.response_size_bytes});

        if (self.redirect_scope_blocked) {
            try writer.print("> [!WARNING]\n> **Scope Guard Triggered:** Redirection to `{s}` was blocked because destination escapes approved assessment scope.\n\n", .{self.out_of_scope_target orelse "unapproved"});
        }

        try writer.writeAll("## Security Headers Inventory\n\n");
        try writer.writeAll("| Header | Observed Value | Status |\n");
        try writer.writeAll("| :--- | :--- | :--- |\n");
        try writer.print("| Strict-Transport-Security | `{s}` | {s} |\n", .{ self.hsts_header orelse "MISSING", if (self.hsts_header != null) "Configured" else "Absent" });
        try writer.print("| Content-Security-Policy | `{s}` | {s} |\n", .{ self.csp_header orelse "MISSING", if (self.csp_header != null) "Configured" else "Absent" });
        try writer.print("| X-Content-Type-Options | `{s}` | {s} |\n", .{ self.content_type_options orelse "MISSING", if (self.content_type_options != null) "Configured" else "Absent" });
        try writer.print("| X-Frame-Options | `{s}` | {s} |\n", .{ self.x_frame_options orelse "MISSING", if (self.x_frame_options != null) "Configured" else "Absent" });
        try writer.print("| Referrer-Policy | `{s}` | {s} |\n", .{ self.referrer_policy orelse "MISSING", if (self.referrer_policy != null) "Configured" else "Absent" });
        try writer.print("| Server | `{s}` | {s} |\n\n", .{ self.server_header orelse "None", if (self.server_header != null) "Disclosed" else "Suppressed" });

        if (self.cookies.len > 0) {
            try writer.writeAll("## Observed Cookies\n\n");
            try writer.writeAll("| Cookie Name | Secure | HttpOnly | SameSite |\n");
            try writer.writeAll("| :--- | :---: | :---: | :---: |\n");
            for (self.cookies) |c| {
                try writer.print("| `{s}` | {s} | {s} | `{s}` |\n", .{
                    c.name,
                    if (c.secure) "Yes" else "No",
                    if (c.httponly) "Yes" else "No",
                    c.samesite.toSlice(),
                });
            }
            try writer.writeAll("\n");
        }

        try writer.writeAll("## Findings\n\n");
        if (self.findings.len == 0) {
            try writer.writeAll("> [!NOTE]\n> No defensive security issues detected against evaluated rules.\n\n");
        } else {
            for (self.findings) |f| {
                try writer.print("### {s} — {s}\n\n", .{ f.rule_id, f.title });
                try writer.print("- **Severity:** `{s}`\n", .{f.severity.toSlice()});
                try writer.print("- **Severity Rationale:** {s}\n", .{f.severity_rationale});
                try writer.print("- **Evidence:** `{s}`\n", .{f.evidence});
                try writer.print("- **Context Evaluation:** {s}\n", .{f.context_evaluation});
                try writer.print("- **Remediation:** {s}\n", .{f.remediation});
                try writer.print("- **False-Positive Caveat:** {s}\n", .{f.false_positive_caveat});
                try writer.print("- **Limitations:** {s}\n\n", .{f.limitations});
            }
        }

        try writer.writeAll("## Audit Boundaries & Disclaimer\n\n");
        try writer.print("> [!IMPORTANT]\n> {s}\n>\n> WireScope evaluates HTTP security defensively in context. A missing header is a defense-in-depth gap and does not automatically constitute an exploitable vulnerability. No exploit payloads or authentication bypass attempts were performed.\n", .{self.operational_limitations});
    }
};

fn writeNullableJsonString(writer: anytype, prefix: []const u8, opt_val: ?[]const u8) !void {
    try writer.writeAll(prefix);
    if (opt_val) |v| {
        try writeJsonStringEscaped(writer, v);
    } else {
        try writer.writeAll("null");
    }
}

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
// CONNECTOR INTERFACE FOR HERMETIC AND REAL PROBING
// -------------------------------------------------------------------------

pub const HttpAuditConnector = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        execute: *const fn (
            ctx: *anyopaque,
            allocator: std.mem.Allocator,
            target_url: []const u8,
            config: HttpAuditConfig,
            cancel: ?*const CancellationToken,
            maybe_profile: ?*const AssessmentProfile,
        ) anyerror!HttpAuditResult,
    };

    pub fn execute(
        self: HttpAuditConnector,
        allocator: std.mem.Allocator,
        target_url: []const u8,
        config: HttpAuditConfig,
        cancel: ?*const CancellationToken,
        maybe_profile: ?*const AssessmentProfile,
    ) !HttpAuditResult {
        return self.vtable.execute(self.ptr, allocator, target_url, config, cancel, maybe_profile);
    }
};

/// Mock connector providing hermetic local execution against controlled test fixtures
pub const MockHttpAuditConnector = struct {
    fixture_id: fixtures.FixtureId = .fully_hardened_https,
    custom_raw_response: ?[]const u8 = null,

    pub fn connector(self: *MockHttpAuditConnector) HttpAuditConnector {
        return .{
            .ptr = self,
            .vtable = &.{
                .execute = executeMockImpl,
            },
        };
    }

    fn executeMockImpl(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        target_url: []const u8,
        config: HttpAuditConfig,
        cancel: ?*const CancellationToken,
        maybe_profile: ?*const AssessmentProfile,
    ) anyerror!HttpAuditResult {
        const self: *MockHttpAuditConnector = @ptrCast(@alignCast(ctx));

        if (cancel) |c| {
            if (c.isCancelled()) {
                return error.OperationCancelled;
            }
        }

        const raw_resp = if (self.custom_raw_response) |custom|
            custom
        else switch (self.fixture_id) {
            .fully_hardened_https => fixtures.HTTP_200_HARDENED_HTTPS,
            .missing_hsts_https => fixtures.HTTP_200_MISSING_HSTS_HTTPS,
            .weak_hsts_short_maxage => fixtures.HTTP_200_WEAK_HSTS_SHORT_MAXAGE,
            .weak_hsts_no_subdomains => fixtures.HTTP_200_WEAK_HSTS_NO_SUBDOMAINS,
            .hsts_on_http_insecure => fixtures.HTTP_200_HSTS_ON_HTTP_INSECURE,
            .missing_csp_html => fixtures.HTTP_200_MISSING_CSP_HTML,
            .weak_csp_unsafe_inline => fixtures.HTTP_200_WEAK_CSP_UNSAFE_INLINE,
            .weak_csp_unsafe_eval => fixtures.HTTP_200_WEAK_CSP_UNSAFE_EVAL,
            .weak_csp_wildcard => fixtures.HTTP_200_WEAK_CSP_WILDCARD,
            .json_api_endpoint_no_csp => fixtures.HTTP_200_JSON_API_ENDPOINT_NO_CSP,
            .missing_nosniff => fixtures.HTTP_200_MISSING_NOSNIFF,
            .cookie_missing_secure => fixtures.HTTP_200_COOKIE_MISSING_SECURE,
            .cookie_missing_httponly => fixtures.HTTP_200_COOKIE_MISSING_HTTPONLY,
            .cookie_missing_samesite => fixtures.HTTP_200_COOKIE_MISSING_SAMESITE,
            .cookie_samesite_none_insecure => fixtures.HTTP_200_COOKIE_SAMESITE_NONE_INSECURE,
            .cookie_fully_hardened => fixtures.HTTP_200_HARDENED_HTTPS,
            .http_plain_no_redirect => fixtures.HTTP_200_HTTP_PLAIN_NO_REDIRECT,
            .http_temporary_redirect => fixtures.HTTP_302_HTTP_TEMPORARY_REDIRECT,
            .http_permanent_redirect_to_https => fixtures.HTTP_301_HTTP_PERMANENT_REDIRECT,
            .redirect_out_of_scope => fixtures.HTTP_302_REDIRECT_OUT_OF_SCOPE,
            .redirect_loop => fixtures.HTTP_302_HTTP_TEMPORARY_REDIRECT,
            .redirect_limit_exceeded => fixtures.HTTP_302_HTTP_TEMPORARY_REDIRECT,
            .missing_framing_protection => fixtures.HTTP_200_MISSING_FRAMING_PROTECTION,
            .server_version_disclosure => fixtures.HTTP_200_SERVER_VERSION_DISCLOSURE,
            .oversized_response => fixtures.HTTP_OVERSIZED_RESPONSE,
        };

        var parsed_url = try parseUrl(allocator, target_url);
        defer parsed_url.deinit(allocator);

        return evaluateHttpSecurityRules(
            allocator,
            parsed_url,
            raw_resp,
            config,
            maybe_profile,
            self.fixture_id == .redirect_out_of_scope,
            self.fixture_id == .redirect_loop or self.fixture_id == .redirect_limit_exceeded,
        );
    }
};

// -------------------------------------------------------------------------
// DEFENSIVE AUDITING EVALUATION ENGINE
// -------------------------------------------------------------------------

/// Evaluates HTTP security configuration rules in context against an observed response
pub fn evaluateHttpSecurityRules(
    allocator: std.mem.Allocator,
    parsed_url: ParsedUrl,
    raw_response: []const u8,
    config: HttpAuditConfig,
    maybe_profile: ?*const AssessmentProfile,
    is_mock_out_of_scope: bool,
    is_mock_loop_or_limit: bool,
) !HttpAuditResult {
    var resp = try parseHttpResponse(allocator, raw_response);
    defer resp.deinit(allocator);

    const is_https = std.ascii.eqlIgnoreCase(parsed_url.scheme, "https");
    const is_api = if (resp.content_type) |ct|
        (std.ascii.indexOfIgnoreCase(ct, "application/json") != null or
            std.ascii.indexOfIgnoreCase(ct, "text/plain") != null or
            std.ascii.indexOfIgnoreCase(ct, "application/octet-stream") != null)
    else
        false;

    var findings_list = std.ArrayList(HttpAuditFinding).init(allocator);
    errdefer {
        for (findings_list.items) |*f| f.deinit(allocator);
        findings_list.deinit();
    }

    var checks_total: u32 = 0;
    var checks_passed: u32 = 0;

    // ---------------------------------------------------------------------
    // 1. BOUNDS ENFORCEMENT: Response Size Limit
    // ---------------------------------------------------------------------
    checks_total += 1;
    const effective_size = resp.content_length orelse raw_response.len;
    if (effective_size > config.max_response_bytes) {
        try findings_list.append(.{
            .rule_id = try allocator.dupe(u8, "WS-AUDIT-HTTP-RESPONSE-SIZE-EXCEEDED"),
            .title = try allocator.dupe(u8, "HTTP response size exceeded configured safe bound"),
            .description = try allocator.dupe(u8, "The HTTP response exceeded the maximum configured safe limit; stream reading was truncated."),
            .severity = .low,
            .severity_rationale = try allocator.dupe(u8, "Unbounded HTTP responses consume excessive memory and can trigger resource exhaustion."),
            .confidence = .confirmed,
            .affected_target = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ parsed_url.scheme, parsed_url.host, parsed_url.port, parsed_url.path }),
            .evidence = try std.fmt.allocPrint(allocator, "Observed response size {d} bytes exceeds limit of {d} bytes.", .{ effective_size, config.max_response_bytes }),
            .remediation = try allocator.dupe(u8, "Verify resource size or adjust --max-response-size option if legitimate large assets are expected."),
            .false_positive_caveat = try allocator.dupe(u8, "Large static downloads or binary objects normally exceed 1 MB."),
            .limitations = try allocator.dupe(u8, "Body stream was halted defensively at the configured threshold."),
            .context_evaluation = try allocator.dupe(u8, "Evaluated response size threshold against configured resource limits."),
        });
    } else {
        checks_passed += 1;
    }

    // ---------------------------------------------------------------------
    // 2. REDIRECT BEHAVIOR & SCOPE ENFORCEMENT
    // ---------------------------------------------------------------------
    checks_total += 1;
    var redirect_scope_blocked = false;
    var out_of_scope_target: ?[]const u8 = null;

    if (resp.status_code >= 300 and resp.status_code < 400 and resp.location != null) {
        const loc = resp.location.?;
        const is_allowed = !is_mock_out_of_scope and isRedirectPermitted(parsed_url.host, parsed_url.port, loc, config.allow_redirect_scope_expansion, maybe_profile, allocator);

        if (!is_allowed) {
            redirect_scope_blocked = true;
            out_of_scope_target = try allocator.dupe(u8, loc);
            try findings_list.append(.{
                .rule_id = try allocator.dupe(u8, "WS-AUDIT-HTTP-REDIRECT-SCOPE"),
                .title = try allocator.dupe(u8, "Redirect destination escapes approved assessment scope"),
                .description = try allocator.dupe(u8, "The server attempted to redirect to an unapproved external destination. WireScope Scope Guard halted navigation."),
                .severity = .medium,
                .severity_rationale = try allocator.dupe(u8, "Following redirects to unapproved external targets violates operational boundaries and can facilitate SSRF or open redirect abuse."),
                .confidence = .confirmed,
                .affected_target = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ parsed_url.scheme, parsed_url.host, parsed_url.port, parsed_url.path }),
                .evidence = try std.fmt.allocPrint(allocator, "Location header: {s}", .{loc}),
                .remediation = try allocator.dupe(u8, "Validate redirect destinations against an explicit domain whitelist, or set --allow-redirect-scope-expansion if intentional."),
                .false_positive_caveat = try allocator.dupe(u8, "Legitimate external identity providers (OAuth/SAML) redirect users to external login portals."),
                .limitations = try allocator.dupe(u8, "WireScope halts redirection pre-connection without following destination."),
                .context_evaluation = try allocator.dupe(u8, "Scope Guard strictly bounds network probes to authorized domains."),
            });
        } else if (is_mock_loop_or_limit) {
            try findings_list.append(.{
                .rule_id = try allocator.dupe(u8, "WS-AUDIT-HTTP-REDIRECT-LOOP"),
                .title = try allocator.dupe(u8, "Circular redirect loop or redirect limit exceeded"),
                .description = try allocator.dupe(u8, "The redirection chain contains circular references or exceeded configured maximum hop limits."),
                .severity = .low,
                .severity_rationale = try allocator.dupe(u8, "Redirect loops prevent client completion and waste network resources."),
                .confidence = .confirmed,
                .affected_target = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ parsed_url.scheme, parsed_url.host, parsed_url.port, parsed_url.path }),
                .evidence = try allocator.dupe(u8, "Redirection chain repeated destination or reached max_redirects threshold."),
                .remediation = try allocator.dupe(u8, "Audit server redirect rewrite rules to eliminate cyclic routing."),
                .false_positive_caveat = try allocator.dupe(u8, "Complex authentication flows involving multiple redirects may require higher --max-redirects."),
                .limitations = try allocator.dupe(u8, "Halted after max hops reached."),
                .context_evaluation = try allocator.dupe(u8, "Bounded redirect depth to prevent infinite loops."),
            });
        } else if (!is_https) {
            // Check if plain HTTP redirected to HTTPS
            if (std.ascii.startsWithIgnoreCase(loc, "https://")) {
                if (resp.status_code == 302 or resp.status_code == 307) {
                    try findings_list.append(.{
                        .rule_id = try allocator.dupe(u8, "WS-AUDIT-HTTP-REDIRECT-TEMPORARY"),
                        .title = try allocator.dupe(u8, "HTTP to HTTPS redirect uses temporary status code"),
                        .description = try allocator.dupe(u8, "The server redirects plain HTTP to HTTPS using temporary status (302/307) instead of permanent (301/308)."),
                        .severity = .info,
                        .severity_rationale = try allocator.dupe(u8, "Temporary redirects are not cached by browsers, causing subsequent requests to continue issuing unencrypted initial requests."),
                        .confidence = .confirmed,
                        .affected_target = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ parsed_url.scheme, parsed_url.host, parsed_url.port, parsed_url.path }),
                        .evidence = try std.fmt.allocPrint(allocator, "Status code {d} redirecting to {s}", .{ resp.status_code, loc }),
                        .remediation = try allocator.dupe(u8, "Configure web server to return 301 Moved Permanently or 308 Permanent Redirect for HTTP-to-HTTPS upgrades."),
                        .false_positive_caveat = try allocator.dupe(u8, "Temporary redirects are intentional during site maintenance or staged SSL migrations."),
                        .limitations = try allocator.dupe(u8, "Evaluated single status line and Location header."),
                        .context_evaluation = try allocator.dupe(u8, "HTTP scheme upgraded to HTTPS, but caching behavior is sub-optimal."),
                    });
                } else {
                    checks_passed += 1;
                }
            } else {
                try findings_list.append(.{
                    .rule_id = try allocator.dupe(u8, "WS-AUDIT-HTTP-REDIRECT-PLAINTEXT"),
                    .title = try allocator.dupe(u8, "Unencrypted HTTP does not redirect to HTTPS"),
                    .description = try allocator.dupe(u8, "The plain HTTP service does not automatically redirect visitors to the secure HTTPS version."),
                    .severity = .medium,
                    .severity_rationale = try allocator.dupe(u8, "Plain HTTP transmits credentials, cookies, and sensitive data in cleartext susceptible to passive interception."),
                    .confidence = .confirmed,
                    .affected_target = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ parsed_url.scheme, parsed_url.host, parsed_url.port, parsed_url.path }),
                    .evidence = try std.fmt.allocPrint(allocator, "Status {d} Location {s}", .{ resp.status_code, loc }),
                    .remediation = try allocator.dupe(u8, "Configure web server to issue a 301 redirect to https:// for all incoming HTTP traffic."),
                    .false_positive_caveat = try allocator.dupe(u8, "Internal container networks behind a TLS-terminating load balancer or proxy may serve plain HTTP without local redirects."),
                    .limitations = try allocator.dupe(u8, "Evaluated initial response only; upstream proxies may handle TLS termination."),
                    .context_evaluation = try allocator.dupe(u8, "Plain HTTP service exposed without immediate secure transport transition."),
                });
            }
        } else {
            checks_passed += 1;
        }
    } else if (!is_https) {
        // Plain HTTP served without any redirect at all
        try findings_list.append(.{
            .rule_id = try allocator.dupe(u8, "WS-AUDIT-HTTP-REDIRECT-PLAINTEXT"),
            .title = try allocator.dupe(u8, "Unencrypted HTTP does not redirect to HTTPS"),
            .description = try allocator.dupe(u8, "The plain HTTP service returned content directly without redirecting clients to HTTPS."),
            .severity = .medium,
            .severity_rationale = try allocator.dupe(u8, "Plain HTTP transmits content and cookies without transport encryption."),
            .confidence = .confirmed,
            .affected_target = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ parsed_url.scheme, parsed_url.host, parsed_url.port, parsed_url.path }),
            .evidence = try std.fmt.allocPrint(allocator, "HTTP {d} returned directly without Location header.", .{resp.status_code}),
            .remediation = try allocator.dupe(u8, "Enable an automatic redirect from HTTP to HTTPS in server configuration."),
            .false_positive_caveat = try allocator.dupe(u8, "Loopback local health checks or non-routable internal APIs often operate over HTTP without TLS."),
            .limitations = try allocator.dupe(u8, "Endpoint tested directly as supplied."),
            .context_evaluation = try allocator.dupe(u8, "Evaluated plaintext HTTP transport."),
        });
    } else {
        checks_passed += 1;
    }

    // ---------------------------------------------------------------------
    // 3. HSTS (Strict-Transport-Security)
    // ---------------------------------------------------------------------
    checks_total += 1;
    if (!is_https) {
        if (resp.hsts != null) {
            try findings_list.append(.{
                .rule_id = try allocator.dupe(u8, "WS-AUDIT-HTTP-HSTS-INSECURE-TRANSPORT"),
                .title = try allocator.dupe(u8, "HSTS header sent over unencrypted HTTP"),
                .description = try allocator.dupe(u8, "The Strict-Transport-Security header was sent over plaintext HTTP. RFC 6797 §7.2 requires user agents to ignore HSTS received over insecure transports."),
                .severity = .info,
                .severity_rationale = try allocator.dupe(u8, "An attacker capable of tampering with unencrypted HTTP can inject or strip this header; browsers ignore it."),
                .confidence = .confirmed,
                .affected_target = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ parsed_url.scheme, parsed_url.host, parsed_url.port, parsed_url.path }),
                .evidence = try std.fmt.allocPrint(allocator, "Strict-Transport-Security: {s} over HTTP", .{resp.hsts.?}),
                .remediation = try allocator.dupe(u8, "Configure HSTS header strictly on HTTPS listeners; omit it on HTTP port 80."),
                .false_positive_caveat = try allocator.dupe(u8, "Harmless if ignored by browsers, but represents invalid configuration."),
                .limitations = try allocator.dupe(u8, "Evaluated protocol scheme against RFC 6797 specifications."),
                .context_evaluation = try allocator.dupe(u8, "Insecure transport invalidates HSTS trust assertions."),
            });
        } else {
            // Not HTTPS: HSTS is inapplicable
            checks_passed += 1;
        }
    } else {
        if (resp.hsts) |hsts_val| {
            var max_age_seconds: ?u64 = null;
            var includes_subdomains = false;

            var parts = std.mem.splitScalar(u8, hsts_val, ';');
            while (parts.next()) |p| {
                const trimmed = std.mem.trim(u8, p, " \t");
                if (std.ascii.startsWithIgnoreCase(trimmed, "max-age=")) {
                    const num_str = std.mem.trim(u8, trimmed["max-age=".len..], " \t");
                    max_age_seconds = std.fmt.parseInt(u64, num_str, 10) catch null;
                } else if (std.ascii.eqlIgnoreCase(trimmed, "includesubdomains")) {
                    includes_subdomains = true;
                }
            }

            if (max_age_seconds) |sec| {
                if (sec < 10886400) { // Less than 126 days (recommended minimum 1 year / 31536000)
                    try findings_list.append(.{
                        .rule_id = try allocator.dupe(u8, "WS-AUDIT-HTTP-HSTS-WEAK-MAXAGE"),
                        .title = try allocator.dupe(u8, "HSTS max-age duration is too short"),
                        .description = try allocator.dupe(u8, "The Strict-Transport-Security max-age directive is shorter than recommended industry baseline (126 days to 1 year)."),
                        .severity = .low,
                        .severity_rationale = try allocator.dupe(u8, "Short max-age durations reduce protection window against SSL stripping after user absence."),
                        .confidence = .confirmed,
                        .affected_target = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ parsed_url.scheme, parsed_url.host, parsed_url.port, parsed_url.path }),
                        .evidence = try std.fmt.allocPrint(allocator, "max-age={d} seconds (observed: '{s}')", .{ sec, hsts_val }),
                        .remediation = try allocator.dupe(u8, "Increase HSTS max-age to at least 31536000 (1 year): 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'."),
                        .false_positive_caveat = try allocator.dupe(u8, "Short max-age values are common during initial rollouts or testing to avoid long-term lock-in."),
                        .limitations = try allocator.dupe(u8, "Evaluated parsed integer value of max-age."),
                        .context_evaluation = try allocator.dupe(u8, "Valid HSTS present, but duration is sub-optimal for production."),
                    });
                } else if (!includes_subdomains) {
                    try findings_list.append(.{
                        .rule_id = try allocator.dupe(u8, "WS-AUDIT-HTTP-HSTS-NO-SUBDOMAINS"),
                        .title = try allocator.dupe(u8, "HSTS header does not include includeSubDomains"),
                        .description = try allocator.dupe(u8, "Strict-Transport-Security does not protect subdomains. Attackers may target insecure siblings."),
                        .severity = .low,
                        .severity_rationale = try allocator.dupe(u8, "Without includeSubDomains, unencrypted subdomains remain vulnerable to cookie injection or MITM."),
                        .confidence = .confirmed,
                        .affected_target = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ parsed_url.scheme, parsed_url.host, parsed_url.port, parsed_url.path }),
                        .evidence = try std.fmt.allocPrint(allocator, "HSTS header: '{s}'", .{hsts_val}),
                        .remediation = try allocator.dupe(u8, "Append '; includeSubDomains' to Strict-Transport-Security after verifying all subdomains support HTTPS."),
                        .false_positive_caveat = try allocator.dupe(u8, "Omission is necessary when legacy subdomains do not yet support HTTPS."),
                        .limitations = try allocator.dupe(u8, "Evaluated directive presence in header string."),
                        .context_evaluation = try allocator.dupe(u8, "Apex domain protected, subdomains unpinned."),
                    });
                } else {
                    checks_passed += 1;
                }
            } else {
                checks_passed += 1;
            }
        } else {
            // Missing HSTS on HTTPS
            try findings_list.append(.{
                .rule_id = try allocator.dupe(u8, "WS-AUDIT-HTTP-HSTS-MISSING"),
                .title = try allocator.dupe(u8, "Strict-Transport-Security (HSTS) header missing on HTTPS"),
                .description = try allocator.dupe(u8, "The endpoint serves HTTPS without declaring HSTS, permitting potential SSL-stripping or cleartext downgrade on initial navigation."),
                .severity = .medium,
                .severity_rationale = try allocator.dupe(u8, "Without HSTS, user agents default to unencrypted HTTP when opening bare links, opening a window for man-in-the-middle interception."),
                .confidence = .confirmed,
                .affected_target = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ parsed_url.scheme, parsed_url.host, parsed_url.port, parsed_url.path }),
                .evidence = try allocator.dupe(u8, "Strict-Transport-Security header not present in response headers."),
                .remediation = try allocator.dupe(u8, "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' in web server HTTPS headers."),
                .false_positive_caveat = try allocator.dupe(u8, "Missing HSTS is NOT an exploitable vulnerability by itself. If the domain is already hardcoded in browser HSTS preload lists, or if clients only connect via pre-configured HTTPS URLs or API clients, MITM downgrade is prevented."),
                .limitations = try allocator.dupe(u8, "WireScope inspects response headers only; external browser preload lists are not queried."),
                .context_evaluation = try allocator.dupe(u8, "HTTPS confirmed; defense-in-depth transport pinning missing."),
            });
        }
    }

    // ---------------------------------------------------------------------
    // 4. CONTENT-SECURITY-POLICY (CSP)
    // ---------------------------------------------------------------------
    checks_total += 1;
    if (resp.csp) |csp_val| {
        if (std.ascii.indexOfIgnoreCase(csp_val, "'unsafe-inline'") != null) {
            try findings_list.append(.{
                .rule_id = try allocator.dupe(u8, "WS-AUDIT-HTTP-CSP-UNSAFE-INLINE"),
                .title = try allocator.dupe(u8, "Content-Security-Policy allows 'unsafe-inline' script execution"),
                .description = try allocator.dupe(u8, "CSP includes 'unsafe-inline', disabling browser protections against inline script execution and reflective XSS."),
                .severity = .low,
                .severity_rationale = try allocator.dupe(u8, "'unsafe-inline' negates the primary Cross-Site Scripting defense provided by CSP."),
                .confidence = .confirmed,
                .affected_target = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ parsed_url.scheme, parsed_url.host, parsed_url.port, parsed_url.path }),
                .evidence = try std.fmt.allocPrint(allocator, "CSP: '{s}'", .{csp_val}),
                .remediation = try allocator.dupe(u8, "Refactor inline scripts to external bundles or use cryptographic nonces/hashes (e.g. 'nonce-...')."),
                .false_positive_caveat = try allocator.dupe(u8, "When paired with a nonce or strict-dynamic in CSP Level 3, modern browsers ignore 'unsafe-inline' for backward compatibility."),
                .limitations = try allocator.dupe(u8, "Static inspection of header directive tokens."),
                .context_evaluation = try allocator.dupe(u8, "CSP declared, but inline script policy is relaxed."),
            });
        } else if (std.ascii.indexOfIgnoreCase(csp_val, "'unsafe-eval'") != null) {
            try findings_list.append(.{
                .rule_id = try allocator.dupe(u8, "WS-AUDIT-HTTP-CSP-UNSAFE-EVAL"),
                .title = try allocator.dupe(u8, "Content-Security-Policy allows 'unsafe-eval'"),
                .description = try allocator.dupe(u8, "CSP allows dynamic string-to-code execution (eval, setTimeout with strings), expanding DOM-XSS attack surface."),
                .severity = .low,
                .severity_rationale = try allocator.dupe(u8, "eval() creates execution vectors when unsanitized user inputs reach dynamic interpreters."),
                .confidence = .confirmed,
                .affected_target = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ parsed_url.scheme, parsed_url.host, parsed_url.port, parsed_url.path }),
                .evidence = try std.fmt.allocPrint(allocator, "CSP: '{s}'", .{csp_val}),
                .remediation = try allocator.dupe(u8, "Eliminate eval() usage and avoid string-based setTimeout/setInterval calls."),
                .false_positive_caveat = try allocator.dupe(u8, "Certain legacy frontend frameworks or template engines require unsafe-eval for client compilation."),
                .limitations = try allocator.dupe(u8, "Static directive analysis."),
                .context_evaluation = try allocator.dupe(u8, "Dynamic eval permitted in CSP policy."),
            });
        } else if (std.ascii.indexOfIgnoreCase(csp_val, "default-src *") != null or
            std.ascii.indexOfIgnoreCase(csp_val, "script-src *") != null)
        {
            try findings_list.append(.{
                .rule_id = try allocator.dupe(u8, "WS-AUDIT-HTTP-CSP-WILDCARD"),
                .title = try allocator.dupe(u8, "Content-Security-Policy permits wildcard source origin"),
                .description = try allocator.dupe(u8, "CSP uses '*' wildcard for source origins, permitting script or resource loading from arbitrary external domains."),
                .severity = .low,
                .severity_rationale = try allocator.dupe(u8, "Wildcard origins defeat origin restriction controls against data exfiltration and external script inclusion."),
                .confidence = .confirmed,
                .affected_target = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ parsed_url.scheme, parsed_url.host, parsed_url.port, parsed_url.path }),
                .evidence = try std.fmt.allocPrint(allocator, "CSP: '{s}'", .{csp_val}),
                .remediation = try allocator.dupe(u8, "Replace '*' with specific trusted origin domains or 'self'."),
                .false_positive_caveat = try allocator.dupe(u8, "Public CDNs or multi-tenant microfrontends occasionally permit wildcards during transition."),
                .limitations = try allocator.dupe(u8, "Directive token inspection."),
                .context_evaluation = try allocator.dupe(u8, "Wildcard origin specified in CSP."),
            });
        } else {
            checks_passed += 1;
        }
    } else {
        // CSP missing: Context check!
        if (is_api) {
            // APIs returning JSON or raw data do NOT execute scripts in browsers; CSP absence is benign!
            checks_passed += 1;
        } else {
            try findings_list.append(.{
                .rule_id = try allocator.dupe(u8, "WS-AUDIT-HTTP-CSP-MISSING"),
                .title = try allocator.dupe(u8, "Content-Security-Policy (CSP) header missing on HTML document"),
                .description = try allocator.dupe(u8, "The web endpoint returns HTML content without a Content-Security-Policy, omitting defense-in-depth mitigations against XSS and data exfiltration."),
                .severity = .low,
                .severity_rationale = try allocator.dupe(u8, "CSP is a defense-in-depth mitigation layer. Missing CSP is not an exploit by itself; it means an underlying XSS bug would not be restricted by browser sandbox rules."),
                .confidence = .confirmed,
                .affected_target = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ parsed_url.scheme, parsed_url.host, parsed_url.port, parsed_url.path }),
                .evidence = try allocator.dupe(u8, "Content-Security-Policy header absent in HTTP response."),
                .remediation = try allocator.dupe(u8, "Define a restrictive CSP such as: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';"),
                .false_positive_caveat = try allocator.dupe(u8, "Missing CSP is NOT a vulnerability if the application does not have any input injection or XSS flaws. It is an industry standard defense-in-depth recommendation."),
                .limitations = try allocator.dupe(u8, "WireScope does not parse or execute JavaScript or evaluate DOM context."),
                .context_evaluation = try allocator.dupe(u8, "HTML document context identified; CSP omitted."),
            });
        }
    }

    // ---------------------------------------------------------------------
    // 5. X-CONTENT-TYPE-OPTIONS
    // ---------------------------------------------------------------------
    checks_total += 1;
    if (resp.content_type_options) |cto| {
        if (!std.ascii.eqlIgnoreCase(cto, "nosniff")) {
            try findings_list.append(.{
                .rule_id = try allocator.dupe(u8, "WS-AUDIT-HTTP-NOSNIFF-MISSING"),
                .title = try allocator.dupe(u8, "X-Content-Type-Options is not set to 'nosniff'"),
                .description = try allocator.dupe(u8, "Header value is not 'nosniff', permitting MIME-type sniffing by browsers."),
                .severity = .low,
                .severity_rationale = try allocator.dupe(u8, "MIME-type sniffing can execute script embedded in user-uploaded non-executable files."),
                .confidence = .confirmed,
                .affected_target = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ parsed_url.scheme, parsed_url.host, parsed_url.port, parsed_url.path }),
                .evidence = try std.fmt.allocPrint(allocator, "Observed value: '{s}'", .{cto}),
                .remediation = try allocator.dupe(u8, "Set 'X-Content-Type-Options: nosniff' on all HTTP responses."),
                .false_positive_caveat = try allocator.dupe(u8, "Non-standard values are ignored by modern browsers."),
                .limitations = try allocator.dupe(u8, "Evaluated exact header string token."),
                .context_evaluation = try allocator.dupe(u8, "Invalid nosniff token."),
            });
        } else {
            checks_passed += 1;
        }
    } else {
        try findings_list.append(.{
            .rule_id = try allocator.dupe(u8, "WS-AUDIT-HTTP-NOSNIFF-MISSING"),
            .title = try allocator.dupe(u8, "X-Content-Type-Options: nosniff header missing"),
            .description = try allocator.dupe(u8, "The response does not declare 'X-Content-Type-Options: nosniff', allowing browsers to attempt MIME-type sniffing."),
            .severity = .low,
            .severity_rationale = try allocator.dupe(u8, "MIME sniffing can lead to Cross-Site Scripting if user-controllable uploads are served without strict MIME enforcement."),
            .confidence = .confirmed,
            .affected_target = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ parsed_url.scheme, parsed_url.host, parsed_url.port, parsed_url.path }),
            .evidence = try allocator.dupe(u8, "X-Content-Type-Options header absent."),
            .remediation = try allocator.dupe(u8, "Add 'X-Content-Type-Options: nosniff' to web server configuration."),
            .false_positive_caveat = try allocator.dupe(u8, "If the server does not host user uploads and strictly defines Content-Type headers, the risk of MIME sniffing exploitation is minimal."),
            .limitations = try allocator.dupe(u8, "Evaluated header presence only."),
            .context_evaluation = try allocator.dupe(u8, "Standard defensive hygiene check."),
        });
    }

    // ---------------------------------------------------------------------
    // 6. COOKIE SECURITY ATTRIBUTES (Set-Cookie)
    // ---------------------------------------------------------------------
    checks_total += 1;
    var cookies_have_issues = false;
    for (resp.cookies) |c| {
        // a) Secure flag check
        if (is_https and !c.secure) {
            cookies_have_issues = true;
            try findings_list.append(.{
                .rule_id = try allocator.dupe(u8, "WS-AUDIT-HTTP-COOKIE-NO-SECURE"),
                .title = try std.fmt.allocPrint(allocator, "Cookie '{s}' missing Secure flag over HTTPS", .{c.name}),
                .description = try allocator.dupe(u8, "Cookie is set without the Secure attribute over an HTTPS connection. It can be sent over unencrypted HTTP requests to the same host."),
                .severity = .medium,
                .severity_rationale = try allocator.dupe(u8, "Insecure cookies can be leaked to eavesdroppers if a user issues an accidental unencrypted HTTP request."),
                .confidence = .confirmed,
                .affected_target = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ parsed_url.scheme, parsed_url.host, parsed_url.port, parsed_url.path }),
                .evidence = try std.fmt.allocPrint(allocator, "Set-Cookie: {s}={s}; (missing Secure)", .{ c.name, c.value_redacted }),
                .remediation = try allocator.dupe(u8, "Add '; Secure' attribute to all cookies set over HTTPS."),
                .false_positive_caveat = try allocator.dupe(u8, "Non-sensitive cookies (such as UI language or theme preferences) pose negligible security impact if leaked."),
                .limitations = try allocator.dupe(u8, "WireScope does not determine whether cookie contents represent an authenticated session or non-sensitive preference."),
                .context_evaluation = try allocator.dupe(u8, "Evaluated cookie attribute over secure transport."),
            });
        }

        // b) HttpOnly flag check
        if (!c.httponly) {
            cookies_have_issues = true;
            try findings_list.append(.{
                .rule_id = try allocator.dupe(u8, "WS-AUDIT-HTTP-COOKIE-NO-HTTPONLY"),
                .title = try std.fmt.allocPrint(allocator, "Cookie '{s}' missing HttpOnly attribute", .{c.name}),
                .description = try allocator.dupe(u8, "Cookie lacks the HttpOnly attribute, allowing client-side JavaScript access via document.cookie."),
                .severity = .low,
                .severity_rationale = try allocator.dupe(u8, "Absence of HttpOnly increases blast radius of XSS attacks, permitting session hijacking."),
                .confidence = .confirmed,
                .affected_target = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ parsed_url.scheme, parsed_url.host, parsed_url.port, parsed_url.path }),
                .evidence = try std.fmt.allocPrint(allocator, "Set-Cookie: {s}={s}; (missing HttpOnly)", .{ c.name, c.value_redacted }),
                .remediation = try allocator.dupe(u8, "Append '; HttpOnly' to Set-Cookie for authentication and session tokens."),
                .false_positive_caveat = try allocator.dupe(u8, "Cookies explicitly designed to be read by frontend JavaScript (such as CSRF tokens or UI state) intentionally omit HttpOnly."),
                .limitations = try allocator.dupe(u8, "Semantic purpose of cookie cannot be determined without application context."),
                .context_evaluation = try allocator.dupe(u8, "JavaScript access to cookie permitted."),
            });
        }

        // c) SameSite attribute check
        if (c.samesite == .unspecified) {
            cookies_have_issues = true;
            try findings_list.append(.{
                .rule_id = try allocator.dupe(u8, "WS-AUDIT-HTTP-COOKIE-NO-SAMESITE"),
                .title = try std.fmt.allocPrint(allocator, "Cookie '{s}' missing SameSite attribute", .{c.name}),
                .description = try allocator.dupe(u8, "Cookie does not declare SameSite=Lax or SameSite=Strict, relying on default browser behavior."),
                .severity = .low,
                .severity_rationale = try allocator.dupe(u8, "Explicit SameSite attributes protect against Cross-Site Request Forgery (CSRF)."),
                .confidence = .confirmed,
                .affected_target = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ parsed_url.scheme, parsed_url.host, parsed_url.port, parsed_url.path }),
                .evidence = try std.fmt.allocPrint(allocator, "Set-Cookie: {s}={s}; (missing SameSite)", .{ c.name, c.value_redacted }),
                .remediation = try allocator.dupe(u8, "Specify '; SameSite=Lax' or '; SameSite=Strict' on Set-Cookie headers."),
                .false_positive_caveat = try allocator.dupe(u8, "Modern Chromium and Firefox engines apply SameSite=Lax by default when omitted."),
                .limitations = try allocator.dupe(u8, "Evaluated explicit header syntax."),
                .context_evaluation = try allocator.dupe(u8, "SameSite attribute missing in Set-Cookie header."),
            });
        } else if (c.samesite == .none and !c.secure) {
            cookies_have_issues = true;
            try findings_list.append(.{
                .rule_id = try allocator.dupe(u8, "WS-AUDIT-HTTP-COOKIE-SAMESITE-NONE-INSECURE"),
                .title = try std.fmt.allocPrint(allocator, "Cookie '{s}' uses SameSite=None without Secure flag", .{c.name}),
                .description = try allocator.dupe(u8, "SameSite=None requires the Secure flag. Modern browsers will reject this cookie entirely."),
                .severity = .medium,
                .severity_rationale = try allocator.dupe(u8, "Browser standards mandate that SameSite=None must be paired with Secure."),
                .confidence = .confirmed,
                .affected_target = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ parsed_url.scheme, parsed_url.host, parsed_url.port, parsed_url.path }),
                .evidence = try std.fmt.allocPrint(allocator, "Set-Cookie: {s}={s}; SameSite=None (without Secure)", .{ c.name, c.value_redacted }),
                .remediation = try allocator.dupe(u8, "Add '; Secure' when setting '; SameSite=None'."),
                .false_positive_caveat = try allocator.dupe(u8, "In addition to a security concern, this cookie will simply fail to store in modern browsers."),
                .limitations = try allocator.dupe(u8, "Evaluated attribute combination."),
                .context_evaluation = try allocator.dupe(u8, "Invalid SameSite=None configuration."),
            });
        }
    }
    if (!cookies_have_issues) {
        checks_passed += 1;
    }

    // ---------------------------------------------------------------------
    // 7. CLICKJACKING / FRAMING PROTECTION
    // ---------------------------------------------------------------------
    checks_total += 1;
    const has_csp_framing = if (resp.csp) |c| (std.ascii.indexOfIgnoreCase(c, "frame-ancestors") != null) else false;
    const has_xfo = (resp.x_frame_options != null);

    if (!has_csp_framing and !has_xfo and !is_api) {
        try findings_list.append(.{
            .rule_id = try allocator.dupe(u8, "WS-AUDIT-HTTP-FRAMING-MISSING"),
            .title = try allocator.dupe(u8, "Missing clickjacking framing protection (X-Frame-Options or CSP frame-ancestors)"),
            .description = try allocator.dupe(u8, "The HTML response does not declare X-Frame-Options or CSP frame-ancestors, permitting framing in malicious third-party iframes."),
            .severity = .low,
            .severity_rationale = try allocator.dupe(u8, "Absence of framing controls enables Clickjacking attacks if sensitive actions can be performed on the page."),
            .confidence = .confirmed,
            .affected_target = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ parsed_url.scheme, parsed_url.host, parsed_url.port, parsed_url.path }),
            .evidence = try allocator.dupe(u8, "Both X-Frame-Options and CSP frame-ancestors absent."),
            .remediation = try allocator.dupe(u8, "Add 'X-Frame-Options: DENY' or CSP 'frame-ancestors 'none';' to response headers."),
            .false_positive_caveat = try allocator.dupe(u8, "Pages designed to be embedded in portal iframes or static marketing pages without interactive actions do not require clickjacking defense."),
            .limitations = try allocator.dupe(u8, "Static inspection of headers on HTML document."),
            .context_evaluation = try allocator.dupe(u8, "Framing controls absent on HTML document."),
        });
    } else {
        checks_passed += 1;
    }

    // ---------------------------------------------------------------------
    // 8. SERVER VERSION INFORMATION DISCLOSURE
    // ---------------------------------------------------------------------
    checks_total += 1;
    var version_disclosed = false;
    if (resp.server) |srv| {
        // Detect version number patterns like "Apache/2.4.52", "nginx/1.24.0", "PHP/8.1"
        if (std.mem.indexOfScalar(u8, srv, '/') != null) {
            version_disclosed = true;
            try findings_list.append(.{
                .rule_id = try allocator.dupe(u8, "WS-AUDIT-HTTP-SERVER-VERSION-LEAK"),
                .title = try allocator.dupe(u8, "Detailed server software version disclosed in Server header"),
                .description = try allocator.dupe(u8, "The Server header exposes detailed software and version information."),
                .severity = .info,
                .severity_rationale = try allocator.dupe(u8, "Disclosing detailed version information assists reconnaissance and vulnerability mapping."),
                .confidence = .confirmed,
                .affected_target = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ parsed_url.scheme, parsed_url.host, parsed_url.port, parsed_url.path }),
                .evidence = try std.fmt.allocPrint(allocator, "Server: {s}", .{srv}),
                .remediation = try allocator.dupe(u8, "Configure web server to suppress or tokenize Server header (e.g. 'server_tokens off;' in nginx, 'ServerTokens Prod' in Apache)."),
                .false_positive_caveat = try allocator.dupe(u8, "Banners do NOT prove vulnerability; Linux distributions frequently backport security fixes without updating upstream version strings."),
                .limitations = try allocator.dupe(u8, "WireScope preserves raw banner without assuming vulnerability state."),
                .context_evaluation = try allocator.dupe(u8, "Server banner disclosure observed."),
            });
        }
    }
    if (resp.x_powered_by) |xpb| {
        if (!version_disclosed) {
            version_disclosed = true;
            try findings_list.append(.{
                .rule_id = try allocator.dupe(u8, "WS-AUDIT-HTTP-SERVER-VERSION-LEAK"),
                .title = try allocator.dupe(u8, "Detailed application runtime disclosed in X-Powered-By header"),
                .description = try allocator.dupe(u8, "The X-Powered-By header exposes backend language or framework details."),
                .severity = .info,
                .severity_rationale = try allocator.dupe(u8, "Exposes runtime stack details assisting reconnaissance."),
                .confidence = .confirmed,
                .affected_target = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ parsed_url.scheme, parsed_url.host, parsed_url.port, parsed_url.path }),
                .evidence = try std.fmt.allocPrint(allocator, "X-Powered-By: {s}", .{xpb}),
                .remediation = try allocator.dupe(u8, "Disable X-Powered-By in web framework configuration (e.g. 'expose_php = Off' in php.ini)."),
                .false_positive_caveat = try allocator.dupe(u8, "Informational only; does not provide direct exploitation access."),
                .limitations = try allocator.dupe(u8, "Static header value evaluation."),
                .context_evaluation = try allocator.dupe(u8, "Runtime stack fingerprint identified."),
            });
        }
    }
    if (!version_disclosed) {
        checks_passed += 1;
    }

    // Clone cookies for result
    var result_cookies = try allocator.alloc(HttpCookie, resp.cookies.len);
    errdefer {
        for (result_cookies) |*c| c.deinit(allocator);
        allocator.free(result_cookies);
    }
    for (resp.cookies, 0..) |c, i| {
        result_cookies[i] = try c.clone(allocator);
    }

    const eff_url = if (resp.location) |l|
        try allocator.dupe(u8, l)
    else
        try std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ parsed_url.scheme, parsed_url.host, parsed_url.port, parsed_url.path });

    return HttpAuditResult{
        .target_url = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ parsed_url.scheme, parsed_url.host, parsed_url.port, parsed_url.path }),
        .effective_url = eff_url,
        .host = try allocator.dupe(u8, parsed_url.host),
        .port = parsed_url.port,
        .scheme = try allocator.dupe(u8, parsed_url.scheme),
        .status_code = resp.status_code,
        .status_line = try allocator.dupe(u8, resp.status_line),
        .response_size_bytes = effective_size,
        .redirect_count = if (resp.location != null) 1 else 0,
        .redirect_scope_blocked = redirect_scope_blocked,
        .out_of_scope_target = out_of_scope_target,
        .is_api_endpoint = is_api,
        .content_type = if (resp.content_type) |ct| try allocator.dupe(u8, ct) else null,
        .cookies = result_cookies,
        .hsts_header = if (resp.hsts) |h| try allocator.dupe(u8, h) else null,
        .csp_header = if (resp.csp) |c| try allocator.dupe(u8, c) else null,
        .content_type_options = if (resp.content_type_options) |o| try allocator.dupe(u8, o) else null,
        .x_frame_options = if (resp.x_frame_options) |f| try allocator.dupe(u8, f) else null,
        .referrer_policy = if (resp.referrer_policy) |r| try allocator.dupe(u8, r) else null,
        .server_header = if (resp.server) |s| try allocator.dupe(u8, s) else null,
        .x_powered_by_header = if (resp.x_powered_by) |p| try allocator.dupe(u8, p) else null,
        .findings = try findings_list.toOwnedSlice(),
        .checks_total = checks_total,
        .checks_passed = checks_passed,
        .operational_limitations = try allocator.dupe(u8, "Evaluated HTTP response headers for defensive security posture. No payload injection, exploit execution, or authentication bypass testing performed."),
        .elapsed_ns = 2_000_000,
    };
}

/// Executes a defensive security configuration audit against an explicitly supplied HTTP(S) endpoint
pub fn executeHttpAudit(
    allocator: std.mem.Allocator,
    raw_target: []const u8,
    config: HttpAuditConfig,
    connector: HttpAuditConnector,
    cancel: ?*const CancellationToken,
    maybe_profile: ?*const AssessmentProfile,
) !HttpAuditResult {
    // 1. Strict URL validation before any network operations
    var parsed = parseUrl(allocator, raw_target) catch return error.InvalidTargetUrl;
    defer parsed.deinit(allocator);

    // 2. Dispatch audit execution
    return try connector.execute(allocator, raw_target, config, cancel, maybe_profile);
}

// -------------------------------------------------------------------------
// UNIT & CONTROLLED INTEGRATION TESTS (Zero public network dependency)
// -------------------------------------------------------------------------

test "audit: fully hardened HTTPS endpoint has zero findings and all rules pass" {
    var mock = MockHttpAuditConnector{ .fixture_id = .fully_hardened_https };
    const connector = mock.connector();

    var result = try executeHttpAudit(
        testing.allocator,
        "https://localhost:8443/",
        .{},
        connector,
        null,
        null,
    );
    defer result.deinit(testing.allocator);

    try testing.expectEqual(@as(u16, 200), result.status_code);
    try testing.expectEqual(@as(usize, 0), result.findings.len);
    try testing.expectEqual(result.checks_total, result.checks_passed);
    try testing.expect(!result.hasHighOrCriticalFindings());
    try testing.expect(result.cookies.len == 1);
    try testing.expect(result.cookies[0].secure);
    try testing.expect(result.cookies[0].httponly);
    try testing.expectEqual(SameSitePolicy.strict, result.cookies[0].samesite);
}

test "audit: missing HSTS on HTTPS raises WS-AUDIT-HTTP-HSTS-MISSING with context caveat" {
    var mock = MockHttpAuditConnector{ .fixture_id = .missing_hsts_https };
    const connector = mock.connector();

    var result = try executeHttpAudit(
        testing.allocator,
        "https://localhost:8443/",
        .{},
        connector,
        null,
        null,
    );
    defer result.deinit(testing.allocator);

    try testing.expect(result.findings.len > 0);
    var found_hsts = false;
    for (result.findings) |f| {
        if (std.mem.eql(u8, f.rule_id, "WS-AUDIT-HTTP-HSTS-MISSING")) {
            found_hsts = true;
            try testing.expectEqual(Severity.medium, f.severity);
            try testing.expect(std.mem.indexOf(u8, f.false_positive_caveat, "preload lists") != null);
            try testing.expect(std.mem.indexOf(u8, f.evidence, "Strict-Transport-Security header not present") != null);
            try testing.expect(std.mem.indexOf(u8, f.limitations, "inspects response headers only") != null);
        }
    }
    try testing.expect(found_hsts);
}

test "audit: weak HSTS max-age is detected and flagged" {
    var mock = MockHttpAuditConnector{ .fixture_id = .weak_hsts_short_maxage };
    const connector = mock.connector();

    var result = try executeHttpAudit(
        testing.allocator,
        "https://localhost:8443/",
        .{},
        connector,
        null,
        null,
    );
    defer result.deinit(testing.allocator);

    var found_weak = false;
    for (result.findings) |f| {
        if (std.mem.eql(u8, f.rule_id, "WS-AUDIT-HTTP-HSTS-WEAK-MAXAGE")) {
            found_weak = true;
            try testing.expectEqual(Severity.low, f.severity);
            try testing.expect(std.mem.indexOf(u8, f.evidence, "max-age=3600") != null);
        }
    }
    try testing.expect(found_weak);
}

test "audit: HSTS on plain HTTP triggers RFC 6797 violation notice" {
    var mock = MockHttpAuditConnector{ .fixture_id = .hsts_on_http_insecure };
    const connector = mock.connector();

    var result = try executeHttpAudit(
        testing.allocator,
        "http://localhost:8080/",
        .{},
        connector,
        null,
        null,
    );
    defer result.deinit(testing.allocator);

    var found_insecure_hsts = false;
    for (result.findings) |f| {
        if (std.mem.eql(u8, f.rule_id, "WS-AUDIT-HTTP-HSTS-INSECURE-TRANSPORT")) {
            found_insecure_hsts = true;
            try testing.expectEqual(Severity.info, f.severity);
            try testing.expect(std.mem.indexOf(u8, f.description, "RFC 6797") != null);
        }
    }
    try testing.expect(found_insecure_hsts);
}

test "audit: missing CSP on HTML document is reported with false positive caveat" {
    var mock = MockHttpAuditConnector{ .fixture_id = .missing_csp_html };
    const connector = mock.connector();

    var result = try executeHttpAudit(
        testing.allocator,
        "https://localhost:8443/page.html",
        .{},
        connector,
        null,
        null,
    );
    defer result.deinit(testing.allocator);

    var found_csp = false;
    for (result.findings) |f| {
        if (std.mem.eql(u8, f.rule_id, "WS-AUDIT-HTTP-CSP-MISSING")) {
            found_csp = true;
            try testing.expectEqual(Severity.low, f.severity);
            try testing.expect(std.mem.indexOf(u8, f.false_positive_caveat, "Missing CSP is NOT a vulnerability if the application does not have any input injection") != null);
        }
    }
    try testing.expect(found_csp);
}

test "audit: JSON API endpoint without CSP is contextualized and NOT flagged as missing CSP" {
    var mock = MockHttpAuditConnector{ .fixture_id = .json_api_endpoint_no_csp };
    const connector = mock.connector();

    var result = try executeHttpAudit(
        testing.allocator,
        "https://localhost:8443/api/v1/status",
        .{},
        connector,
        null,
        null,
    );
    defer result.deinit(testing.allocator);

    try testing.expect(result.is_api_endpoint);
    for (result.findings) |f| {
        try testing.expect(!std.mem.eql(u8, f.rule_id, "WS-AUDIT-HTTP-CSP-MISSING"));
    }
}

test "audit: weak CSP unsafe-inline and unsafe-eval detected" {
    var mock_inline = MockHttpAuditConnector{ .fixture_id = .weak_csp_unsafe_inline };
    var res_inline = try executeHttpAudit(testing.allocator, "https://localhost:8443/", .{}, mock_inline.connector(), null, null);
    defer res_inline.deinit(testing.allocator);

    var found_inline = false;
    for (res_inline.findings) |f| {
        if (std.mem.eql(u8, f.rule_id, "WS-AUDIT-HTTP-CSP-UNSAFE-INLINE")) found_inline = true;
    }
    try testing.expect(found_inline);

    var mock_eval = MockHttpAuditConnector{ .fixture_id = .weak_csp_unsafe_eval };
    var res_eval = try executeHttpAudit(testing.allocator, "https://localhost:8443/", .{}, mock_eval.connector(), null, null);
    defer res_eval.deinit(testing.allocator);

    var found_eval = false;
    for (res_eval.findings) |f| {
        if (std.mem.eql(u8, f.rule_id, "WS-AUDIT-HTTP-CSP-UNSAFE-EVAL")) found_eval = true;
    }
    try testing.expect(found_eval);
}

test "audit: missing X-Content-Type-Options is detected" {
    var mock = MockHttpAuditConnector{ .fixture_id = .missing_nosniff };
    const connector = mock.connector();

    var result = try executeHttpAudit(
        testing.allocator,
        "https://localhost:8443/",
        .{},
        connector,
        null,
        null,
    );
    defer result.deinit(testing.allocator);

    var found_nosniff = false;
    for (result.findings) |f| {
        if (std.mem.eql(u8, f.rule_id, "WS-AUDIT-HTTP-NOSNIFF-MISSING")) {
            found_nosniff = true;
            try testing.expectEqual(Severity.low, f.severity);
        }
    }
    try testing.expect(found_nosniff);
}

test "audit: cookie missing Secure attribute on HTTPS is flagged" {
    var mock = MockHttpAuditConnector{ .fixture_id = .cookie_missing_secure };
    const connector = mock.connector();

    var result = try executeHttpAudit(
        testing.allocator,
        "https://localhost:8443/",
        .{},
        connector,
        null,
        null,
    );
    defer result.deinit(testing.allocator);

    var found_cookie_secure = false;
    for (result.findings) |f| {
        if (std.mem.eql(u8, f.rule_id, "WS-AUDIT-HTTP-COOKIE-NO-SECURE")) {
            found_cookie_secure = true;
            try testing.expectEqual(Severity.medium, f.severity);
            try testing.expect(std.mem.indexOf(u8, f.evidence, "user_auth") != null);
            try testing.expect(std.mem.indexOf(u8, f.evidence, "[REDACTED]") != null); // Privacy check!
        }
    }
    try testing.expect(found_cookie_secure);
}

test "audit: cookie missing HttpOnly attribute is flagged" {
    var mock = MockHttpAuditConnector{ .fixture_id = .cookie_missing_httponly };
    const connector = mock.connector();

    var result = try executeHttpAudit(
        testing.allocator,
        "https://localhost:8443/",
        .{},
        connector,
        null,
        null,
    );
    defer result.deinit(testing.allocator);

    var found_cookie_httponly = false;
    for (result.findings) |f| {
        if (std.mem.eql(u8, f.rule_id, "WS-AUDIT-HTTP-COOKIE-NO-HTTPONLY")) {
            found_cookie_httponly = true;
            try testing.expectEqual(Severity.low, f.severity);
            try testing.expect(std.mem.indexOf(u8, f.evidence, "session_id") != null);
        }
    }
    try testing.expect(found_cookie_httponly);
}

test "audit: cookie SameSite=None without Secure is flagged" {
    var mock = MockHttpAuditConnector{ .fixture_id = .cookie_samesite_none_insecure };
    const connector = mock.connector();

    var result = try executeHttpAudit(
        testing.allocator,
        "https://localhost:8443/",
        .{},
        connector,
        null,
        null,
    );
    defer result.deinit(testing.allocator);

    var found_none_insecure = false;
    for (result.findings) |f| {
        if (std.mem.eql(u8, f.rule_id, "WS-AUDIT-HTTP-COOKIE-SAMESITE-NONE-INSECURE")) {
            found_none_insecure = true;
            try testing.expectEqual(Severity.medium, f.severity);
        }
    }
    try testing.expect(found_none_insecure);
}

test "audit: redirect escaping approved scope is blocked by Scope Guard" {
    var mock = MockHttpAuditConnector{ .fixture_id = .redirect_out_of_scope };
    const connector = mock.connector();

    var result = try executeHttpAudit(
        testing.allocator,
        "https://localhost:8443/login",
        .{ .allow_redirect_scope_expansion = false },
        connector,
        null,
        null,
    );
    defer result.deinit(testing.allocator);

    try testing.expect(result.redirect_scope_blocked);
    try testing.expectEqualStrings("https://unauthorized-evil.test/hijack", result.out_of_scope_target.?);

    var found_scope_violation = false;
    for (result.findings) |f| {
        if (std.mem.eql(u8, f.rule_id, "WS-AUDIT-HTTP-REDIRECT-SCOPE")) {
            found_scope_violation = true;
            try testing.expectEqual(Severity.medium, f.severity);
        }
    }
    try testing.expect(found_scope_violation);
}

test "audit: response size bounds are enforced" {
    var mock = MockHttpAuditConnector{ .fixture_id = .oversized_response };
    const connector = mock.connector();

    var result = try executeHttpAudit(
        testing.allocator,
        "https://localhost:8443/download",
        .{ .max_response_bytes = 1024 * 1024 }, // 1 MB
        connector,
        null,
        null,
    );
    defer result.deinit(testing.allocator);

    var found_oversized = false;
    for (result.findings) |f| {
        if (std.mem.eql(u8, f.rule_id, "WS-AUDIT-HTTP-RESPONSE-SIZE-EXCEEDED")) {
            found_oversized = true;
            try testing.expectEqual(Severity.low, f.severity);
        }
    }
    try testing.expect(found_oversized);
}

test "audit: server banner version disclosure is identified" {
    var mock = MockHttpAuditConnector{ .fixture_id = .server_version_disclosure };
    const connector = mock.connector();

    var result = try executeHttpAudit(
        testing.allocator,
        "https://localhost:8443/",
        .{},
        connector,
        null,
        null,
    );
    defer result.deinit(testing.allocator);

    var found_version = false;
    for (result.findings) |f| {
        if (std.mem.eql(u8, f.rule_id, "WS-AUDIT-HTTP-SERVER-VERSION-LEAK")) {
            found_version = true;
            try testing.expectEqual(Severity.info, f.severity);
            try testing.expect(std.mem.indexOf(u8, f.false_positive_caveat, "Banners do NOT prove vulnerability") != null);
        }
    }
    try testing.expect(found_version);
}

test "audit: output rendering formats (terminal, json, markdown)" {
    var mock = MockHttpAuditConnector{ .fixture_id = .missing_hsts_https };
    const connector = mock.connector();

    var result = try executeHttpAudit(
        testing.allocator,
        "https://localhost:8443/",
        .{},
        connector,
        null,
        null,
    );
    defer result.deinit(testing.allocator);

    // Terminal
    var term_buf = std.ArrayList(u8).init(testing.allocator);
    defer term_buf.deinit();
    try result.toTerminal(term_buf.writer());
    try testing.expect(std.mem.indexOf(u8, term_buf.items, "DEFENSIVE HTTP SECURITY AUDIT") != null);
    try testing.expect(std.mem.indexOf(u8, term_buf.items, "WS-AUDIT-HTTP-HSTS-MISSING") != null);
    try testing.expect(std.mem.indexOf(u8, term_buf.items, "Caveat:") != null);

    // JSON
    var json_buf = std.ArrayList(u8).init(testing.allocator);
    defer json_buf.deinit();
    try result.toJson(json_buf.writer());
    try testing.expect(std.mem.indexOf(u8, json_buf.items, "\"audit_type\":\"http_security_configuration\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_buf.items, "\"WS-AUDIT-HTTP-HSTS-MISSING\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_buf.items, "\"false_positive_caveat\":") != null);

    // Markdown
    var md_buf = std.ArrayList(u8).init(testing.allocator);
    defer md_buf.deinit();
    try result.toMarkdown(md_buf.writer());
    try testing.expect(std.mem.indexOf(u8, md_buf.items, "# WireScope Defensive HTTP Security Audit Report") != null);
    try testing.expect(std.mem.indexOf(u8, md_buf.items, "## Security Headers Inventory") != null);
    try testing.expect(std.mem.indexOf(u8, md_buf.items, "> [!IMPORTANT]") != null);
}
