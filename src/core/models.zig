const std = @import("std");
const testing = std.testing;

pub const Severity = enum {
    info,
    low,
    medium,
    high,
    critical,

    pub fn toSlice(self: Severity) []const u8 {
        return @tagName(self);
    }
};

pub const Confidence = enum {
    tentative,
    likely,
    confirmed,

    pub fn toSlice(self: Confidence) []const u8 {
        return @tagName(self);
    }
};

pub const FindingStatus = enum {
    new,
    confirmed,
    accepted,
    fixed,
    reopened,
    not_applicable,

    pub fn toSlice(self: FindingStatus) []const u8 {
        return @tagName(self);
    }
};

/// Finding contract (Master Spec Section 8.4)
pub const Finding = struct {
    rule_id: []const u8,
    rule_version: u32,
    title: []const u8,
    description: []const u8,
    severity: Severity,
    severity_rationale: []const u8,
    confidence: Confidence,
    affected_target: []const u8,
    evidence: []const u8,
    remediation: []const u8,
    status: FindingStatus = .new,
    first_seen_ms: i64,
    last_seen_ms: i64,

    pub fn deinit(self: *Finding, allocator: std.mem.Allocator) void {
        allocator.free(self.rule_id);
        allocator.free(self.title);
        allocator.free(self.description);
        allocator.free(self.severity_rationale);
        allocator.free(self.affected_target);
        allocator.free(self.evidence);
        allocator.free(self.remediation);
    }
};

/// Service observation contract (Master Spec Section 8.3)
pub const ServiceObservation = struct {
    address: []const u8,
    port: u16,
    transport: []const u8,
    is_open: bool,
    service_name: ?[]const u8 = null,
    confidence: Confidence = .tentative,
    observed_time_ms: i64,

    pub fn deinit(self: *ServiceObservation, allocator: std.mem.Allocator) void {
        allocator.free(self.address);
        allocator.free(self.transport);
        if (self.service_name) |s| allocator.free(s);
    }
};

/// Asset model (Master Spec Section 8.2)
pub const Asset = struct {
    id: []const u8,
    canonical_address: []const u8,
    hostname: ?[]const u8 = null,
    first_seen_ms: i64,
    last_seen_ms: i64,

    pub fn deinit(self: *Asset, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.canonical_address);
        if (self.hostname) |h| allocator.free(h);
    }
};

test "finding model construction and cleanup" {
    const allocator = testing.allocator;

    var finding = Finding{
        .rule_id = try allocator.dupe(u8, "WS-HTTP-001"),
        .rule_version = 1,
        .title = try allocator.dupe(u8, "Missing HSTS Header"),
        .description = try allocator.dupe(u8, "Strict-Transport-Security header was not detected."),
        .severity = .medium,
        .severity_rationale = try allocator.dupe(u8, "Permits unencrypted downgrade attacks on HTTPS."),
        .confidence = .confirmed,
        .affected_target = try allocator.dupe(u8, "https://example.com"),
        .evidence = try allocator.dupe(u8, "Response headers lacked Strict-Transport-Security."),
        .remediation = try allocator.dupe(u8, "Configure Strict-Transport-Security: max-age=31536000."),
        .status = .new,
        .first_seen_ms = 1700000000000,
        .last_seen_ms = 1700000000000,
    };
    defer finding.deinit(allocator);

    try testing.expectEqualStrings("WS-HTTP-001", finding.rule_id);
    try testing.expectEqual(Severity.medium, finding.severity);
    try testing.expectEqual(Confidence.confirmed, finding.confidence);
    try testing.expectEqual(FindingStatus.new, finding.status);
}
