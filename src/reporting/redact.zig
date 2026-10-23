const std = @import("std");
const testing = std.testing;
const json_mod = @import("json.zig");
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

pub const REDACTION_WARNING_NOTICE =
    "WARNING: Redaction was applied to this report. Redacting sensitive data may alter evidence strings, token values, or endpoint references, which can reduce report reproducibility during audit verification.";

pub const REDACTION_DISCLAIMER_MARKDOWN =
    "> [!WARNING]\n" ++
    "> **REDACTION APPLIED:** Redaction was applied to this report. Redacting sensitive data may alter evidence strings, token values, or endpoint references, which can reduce report reproducibility during audit verification.\n";

pub const default_sensitive_patterns = [_][]const u8{
    "password",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "auth_token",
    "bearer",
    "authorization",
    "private_key",
    "token",
};

pub const RedactionConfig = struct {
    enabled: bool = true,
    redact_credentials: bool = true,
    redact_ips: bool = false,
    redact_domains: bool = false,
    custom_patterns: []const []const u8 = &.{},
};

/// Check if a byte slice looks like an IPv4 address (e.g. 192.168.1.1)
fn matchIpv4(slice: []const u8) ?usize {
    var octets: usize = 0;
    var i: usize = 0;
    while (i < slice.len and octets < 4) {
        var digits: usize = 0;
        while (i < slice.len and std.ascii.isDigit(slice[i])) : (i += 1) {
            digits += 1;
        }
        if (digits == 0 or digits > 3) return null;
        octets += 1;
        if (octets < 4) {
            if (i >= slice.len or slice[i] != '.') return null;
            i += 1; // skip '.'
        }
    }
    if (octets == 4) return i;
    return null;
}

/// Redact text according to the specified RedactionConfig
pub fn redactText(allocator: std.mem.Allocator, input: []const u8, config: RedactionConfig) ![]u8 {
    if (!config.enabled or input.len == 0) {
        return allocator.dupe(u8, input);
    }

    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    var lower_buf = try allocator.alloc(u8, input.len);
    defer allocator.free(lower_buf);
    @memcpy(lower_buf, input);
    for (lower_buf) |*c| {
        c.* = std.ascii.toLower(c.*);
    }

    var i: usize = 0;
    while (i < input.len) {
        var matched = false;

        // 1. IP Redaction (if enabled)
        if (config.redact_ips) {
            if (matchIpv4(input[i..])) |ip_len| {
                const at_start = (i == 0) or (!std.ascii.isAlphanumeric(input[i - 1]));
                const end_pos = i + ip_len;
                const at_end = (end_pos == input.len) or (!std.ascii.isAlphanumeric(input[end_pos]));

                if (at_start and at_end) {
                    try result.appendSlice("[REDACTED_IP]");
                    i = end_pos;
                    matched = true;
                    continue;
                }
            }
        }

        // 2. Custom patterns
        for (config.custom_patterns) |pat| {
            if (pat.len > 0 and i + pat.len <= input.len and std.mem.eql(u8, lower_buf[i .. i + pat.len], pat)) {
                try result.appendSlice("[REDACTED]");
                i += pat.len;
                matched = true;
                break;
            }
        }
        if (matched) continue;

        // 3. Credential and token patterns (e.g. password=xyz, token: abc)
        if (config.redact_credentials) {
            for (default_sensitive_patterns) |pat| {
                if (i + pat.len <= input.len and std.mem.eql(u8, lower_buf[i .. i + pat.len], pat)) {
                    var delim_idx = i + pat.len;
                    var has_delim = false;
                    while (delim_idx < input.len and (input[delim_idx] == ' ' or input[delim_idx] == '=' or input[delim_idx] == ':')) : (delim_idx += 1) {
                        has_delim = true;
                    }

                    // Special handling for "Authorization: Bearer <token>"
                    if (delim_idx + 7 <= input.len and std.mem.eql(u8, lower_buf[delim_idx .. delim_idx + 7], "bearer ")) {
                        delim_idx += 7;
                        has_delim = true;
                    }

                    if (has_delim and delim_idx < input.len) {
                        var val_end = delim_idx;
                        while (val_end < input.len and input[val_end] != ' ' and input[val_end] != ',' and input[val_end] != '&' and input[val_end] != ';' and input[val_end] != '\n' and input[val_end] != '"') : (val_end += 1) {}

                        if (val_end > delim_idx) {
                            try result.appendSlice(input[i..delim_idx]);
                            try result.appendSlice("[REDACTED]");
                            i = val_end;
                            matched = true;
                            break;
                        }
                    }
                }
            }
        }

        if (!matched) {
            try result.append(input[i]);
            i += 1;
        }
    }

    return result.toOwnedSlice();
}

/// Clones and redacts an AssessmentReportData structure using an arena allocator
pub fn redactReportData(
    arena_allocator: std.mem.Allocator,
    src: *const AssessmentReportData,
    config: RedactionConfig,
) !AssessmentReportData {
    if (!config.enabled) {
        return src.*;
    }

    var dst = src.*;

    // Redact targets
    var new_targets = try arena_allocator.alloc([]const u8, src.targets.len);
    for (src.targets, 0..) |t, i| {
        new_targets[i] = try redactText(arena_allocator, t, config);
    }
    dst.targets = new_targets;

    // Redact exclusions
    var new_exclusions = try arena_allocator.alloc([]const u8, src.exclusions.len);
    for (src.exclusions, 0..) |ex, i| {
        new_exclusions[i] = try redactText(arena_allocator, ex, config);
    }
    dst.exclusions = new_exclusions;

    // Redact interruption reason
    if (src.interruption_reason) |r| {
        dst.interruption_reason = try redactText(arena_allocator, r, config);
    }

    // Redact checks
    var new_checks = try arena_allocator.alloc(CheckItem, src.checks.len);
    for (src.checks, 0..) |c, i| {
        new_checks[i] = CheckItem{
            .sequence_id = c.sequence_id,
            .check_type = try redactText(arena_allocator, c.check_type, config),
            .target = try redactText(arena_allocator, c.target, config),
            .status = c.status,
            .duration_ms = c.duration_ms,
        };
    }
    dst.checks = new_checks;

    // Redact findings
    var new_findings = try arena_allocator.alloc(FindingItem, src.findings.len);
    for (src.findings, 0..) |f, i| {
        new_findings[i] = FindingItem{
            .rule_id = f.rule_id,
            .rule_version = f.rule_version,
            .title = try redactText(arena_allocator, f.title, config),
            .severity = f.severity,
            .confidence = f.confidence,
            .evidence = try redactText(arena_allocator, f.evidence, config),
            .remediation = try redactText(arena_allocator, f.remediation, config),
            .target = try redactText(arena_allocator, f.target, config),
        };
    }
    dst.findings = new_findings;

    // Redact DNS observations
    var new_dns = try arena_allocator.alloc(DnsObsItem, src.dns_obs.len);
    for (src.dns_obs, 0..) |d, i| {
        var new_answers = try arena_allocator.alloc([]const u8, d.answers.len);
        for (d.answers, 0..) |ans, j| {
            new_answers[j] = try redactText(arena_allocator, ans, config);
        }
        new_dns[i] = DnsObsItem{
            .target = try redactText(arena_allocator, d.target, config),
            .answers = new_answers,
            .is_success = d.is_success,
            .duration_ms = d.duration_ms,
        };
    }
    dst.dns_obs = new_dns;

    // Redact TCP observations
    var new_tcp = try arena_allocator.alloc(TcpObsItem, src.tcp_obs.len);
    for (src.tcp_obs, 0..) |t, i| {
        new_tcp[i] = TcpObsItem{
            .target = try redactText(arena_allocator, t.target, config),
            .port = t.port,
            .is_open = t.is_open,
            .rtt_ms = t.rtt_ms,
        };
    }
    dst.tcp_obs = new_tcp;

    // Redact TLS observations
    var new_tls = try arena_allocator.alloc(TlsObsItem, src.tls_obs.len);
    for (src.tls_obs, 0..) |tl, i| {
        new_tls[i] = TlsObsItem{
            .target = try redactText(arena_allocator, tl.target, config),
            .port = tl.port,
            .protocol_version = tl.protocol_version,
            .hostname_matches = tl.hostname_matches,
            .is_valid_chain = tl.is_valid_chain,
            .days_to_expiration = tl.days_to_expiration,
        };
    }
    dst.tls_obs = new_tls;

    // Redact HTTP observations
    var new_http = try arena_allocator.alloc(HttpObsItem, src.http_obs.len);
    for (src.http_obs, 0..) |h, i| {
        new_http[i] = HttpObsItem{
            .target_url = try redactText(arena_allocator, h.target_url, config),
            .status_code = h.status_code,
            .is_https = h.is_https,
            .is_html = h.is_html,
            .is_json_api = h.is_json_api,
            .hsts_header = if (h.hsts_header) |hdr| try redactText(arena_allocator, hdr, config) else null,
            .csp_header = if (h.csp_header) |hdr| try redactText(arena_allocator, hdr, config) else null,
            .x_content_type_options = if (h.x_content_type_options) |hdr| try redactText(arena_allocator, hdr, config) else null,
        };
    }
    dst.http_obs = new_http;

    // Redact Active Listeners
    var new_listeners = try arena_allocator.alloc(ListenerObsItem, src.listener_obs.len);
    for (src.listener_obs, 0..) |l, i| {
        new_listeners[i] = ListenerObsItem{
            .transport = l.transport,
            .address = try redactText(arena_allocator, l.address, config),
            .port = l.port,
            .binding_type = l.binding_type,
            .pid = l.pid,
            .process_name = if (l.process_name) |pn| try redactText(arena_allocator, pn, config) else null,
            .is_unlisted = l.is_unlisted,
            .permission_limited = l.permission_limited,
        };
    }
    dst.listener_obs = new_listeners;

    // Redact Assets
    var new_assets = try arena_allocator.alloc(AssetItem, src.assets.len);
    for (src.assets, 0..) |a, i| {
        new_assets[i] = AssetItem{
            .target = try redactText(arena_allocator, a.target, config),
            .ip_address = if (a.ip_address) |ip| try redactText(arena_allocator, ip, config) else null,
            .open_ports = a.open_ports,
            .service_banner = if (a.service_banner) |b| try redactText(arena_allocator, b, config) else null,
        };
    }
    dst.assets = new_assets;

    // Redact Policy Results
    var new_policy_res = try arena_allocator.alloc(PolicyResultItem, src.policy_results.len);
    for (src.policy_results, 0..) |p, i| {
        new_policy_res[i] = PolicyResultItem{
            .rule_id = p.rule_id,
            .outcome = p.outcome,
            .target = try redactText(arena_allocator, p.target, config),
            .message = try redactText(arena_allocator, p.message, config),
        };
    }
    dst.policy_results = new_policy_res;

    // Redact Limitations
    var new_limitations = try arena_allocator.alloc(LimitationItem, src.limitations.len);
    for (src.limitations, 0..) |lim, i| {
        new_limitations[i] = LimitationItem{
            .category = lim.category,
            .component = lim.component,
            .description = try redactText(arena_allocator, lim.description, config),
        };
    }
    dst.limitations = new_limitations;

    // Redact Task Failures
    var new_failures = try arena_allocator.alloc(TaskFailureItem, src.task_failures.len);
    for (src.task_failures, 0..) |tf, i| {
        new_failures[i] = TaskFailureItem{
            .sequence_id = tf.sequence_id,
            .check_type = tf.check_type,
            .target = try redactText(arena_allocator, tf.target, config),
            .error_message = try redactText(arena_allocator, tf.error_message, config),
            .duration_ms = tf.duration_ms,
        };
    }
    dst.task_failures = new_failures;

    return dst;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "redaction: credential pattern and custom pattern replacement" {
    const allocator = testing.allocator;

    const input = "Authorization: Bearer secret_token_xyz; connecting with api_key=topsecret123 and custom_corp_val";
    const custom = [_][]const u8{"custom_corp_val"};
    const config = RedactionConfig{
        .enabled = true,
        .redact_credentials = true,
        .custom_patterns = &custom,
    };

    const redacted = try redactText(allocator, input, config);
    defer allocator.free(redacted);

    try testing.expect(std.mem.indexOf(u8, redacted, "secret_token_xyz") == null);
    try testing.expect(std.mem.indexOf(u8, redacted, "topsecret123") == null);
    try testing.expect(std.mem.indexOf(u8, redacted, "custom_corp_val") == null);
    try testing.expect(std.mem.indexOf(u8, redacted, "[REDACTED]") != null);
}

test "redaction: IP masking when enabled" {
    const allocator = testing.allocator;

    const input = "Target host 192.168.1.50 resolved from 10.0.0.1";
    const config = RedactionConfig{
        .enabled = true,
        .redact_ips = true,
    };

    const redacted = try redactText(allocator, input, config);
    defer allocator.free(redacted);

    try testing.expect(std.mem.indexOf(u8, redacted, "192.168.1.50") == null);
    try testing.expect(std.mem.indexOf(u8, redacted, "10.0.0.1") == null);
    try testing.expect(std.mem.indexOf(u8, redacted, "[REDACTED_IP]") != null);
}

test "redaction: warning notice constants exist" {
    try testing.expect(std.mem.indexOf(u8, REDACTION_WARNING_NOTICE, "reduce report reproducibility") != null);
    try testing.expect(std.mem.indexOf(u8, REDACTION_DISCLAIMER_MARKDOWN, "REDACTION APPLIED") != null);
}
