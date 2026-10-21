const std = @import("std");
const testing = std.testing;

pub const ProfileValidationError = error{
    EmptyTargets,
    EmptyTargetString,
    ExcessiveCidrRange,
    ExcessivePortCount,
    MissingAuthorizationAcknowledgement,
    InvalidTimeout,
    ExcessiveConcurrency,
};

pub const ProfileScope = struct {
    targets: []const []const u8,
    ports: []const u16,
    exclusions: []const []const u8 = &.{},
};

pub const ProfileChecks = struct {
    dns: bool = true,
    tcp: bool = true,
    tls: bool = true,
    http: bool = true,
    listeners: bool = true,
};

pub const ProfileLimits = struct {
    max_concurrency: u16 = 5,
    timeout_ms: u32 = 3000,
};

pub const AssessmentProfile = struct {
    profile_version: u32 = 1,
    id: []const u8,
    name: []const u8,
    description: []const u8,
    scope: ProfileScope,
    checks: ProfileChecks = .{},
    limits: ProfileLimits = .{},
    authorization_acknowledged: bool = false,

    pub fn isLoopbackTarget(target: []const u8) bool {
        if (std.mem.eql(u8, target, "127.0.0.1") or
            std.mem.eql(u8, target, "localhost") or
            std.mem.eql(u8, target, "::1"))
        {
            return true;
        }
        if (std.mem.startsWith(u8, target, "127.")) return true;
        return false;
    }

    /// Strict validation enforcing Master Specification Section 5.2 and 9
    pub fn validate(self: *const AssessmentProfile) ProfileValidationError!void {
        if (self.scope.targets.len == 0) return error.EmptyTargets;

        for (self.scope.targets) |t| {
            if (t.len == 0) return error.EmptyTargetString;

            // Reject broad or dangerous CIDR ranges
            if (std.mem.indexOfScalar(u8, t, '/')) |slash_idx| {
                const prefix_str = t[slash_idx + 1 ..];
                const prefix = std.fmt.parseInt(u8, prefix_str, 10) catch 0;
                // Forbid unbounded /0 through /23 (stricter than /24)
                if (prefix < 24) return error.ExcessiveCidrRange;
            }

            // Require explicit authorization for remote non-loopback targets
            if (!isLoopbackTarget(t) and !self.authorization_acknowledged) {
                return error.MissingAuthorizationAcknowledgement;
            }
        }

        // Bounded port checks
        if (self.scope.ports.len > 1000) return error.ExcessivePortCount;

        if (self.limits.timeout_ms < 100 or self.limits.timeout_ms > 60000) {
            return error.InvalidTimeout;
        }

        if (self.limits.max_concurrency == 0 or self.limits.max_concurrency > 50) {
            return error.ExcessiveConcurrency;
        }
    }

    /// Calculates exact planned operations count without expansion
    pub fn calculatePlannedOperations(self: *const AssessmentProfile) usize {
        const host_count = self.scope.targets.len;
        const port_count = if (self.scope.ports.len == 0) 1 else self.scope.ports.len;
        return host_count * port_count;
    }
};

/// Safe built-in loopback profile examples
pub const BuiltinProfiles = struct {
    pub const loopback_diagnostic = AssessmentProfile{
        .profile_version = 1,
        .id = "loopback-diagnostics",
        .name = "Loopback Connectivity Diagnostics",
        .description = "Safe local loopback diagnostic checks for DNS, TCP, and TLS.",
        .scope = .{
            .targets = &[_][]const u8{"127.0.0.1"},
            .ports = &[_]u16{ 80, 443, 8080 },
        },
        .checks = .{
            .dns = true,
            .tcp = true,
            .tls = false,
            .http = false,
            .listeners = true,
        },
        .limits = .{
            .max_concurrency = 2,
            .timeout_ms = 2000,
        },
        .authorization_acknowledged = true,
    };

    pub const local_security_audit = AssessmentProfile{
        .profile_version = 1,
        .id = "local-security-audit",
        .name = "Local Defensive Exposure Audit",
        .description = "Defensive inspection of local listeners and HTTP security headers.",
        .scope = .{
            .targets = &[_][]const u8{"localhost"},
            .ports = &[_]u16{ 8080, 8443 },
        },
        .checks = .{
            .dns = false,
            .tcp = true,
            .tls = true,
            .http = true,
            .listeners = true,
        },
        .limits = .{
            .max_concurrency = 4,
            .timeout_ms = 3000,
        },
        .authorization_acknowledged = true,
    };
};

test "loopback diagnostic profile is valid" {
    const profile = BuiltinProfiles.loopback_diagnostic;
    try profile.validate();
    try testing.expectEqualStrings("loopback-diagnostics", profile.id);
    try testing.expectEqual(@as(usize, 3), profile.calculatePlannedOperations());
}

test "local defensive audit profile is valid" {
    const profile = BuiltinProfiles.local_security_audit;
    try profile.validate();
    try testing.expectEqualStrings("local-security-audit", profile.id);
    try testing.expectEqual(@as(usize, 2), profile.calculatePlannedOperations());
}

test "remote target without authorization acknowledgement is rejected" {
    const remote_profile = AssessmentProfile{
        .id = "remote-test",
        .name = "Remote Test",
        .description = "Remote scan",
        .scope = .{
            .targets = &[_][]const u8{"192.168.1.50"},
            .ports = &[_]u16{80},
        },
        .authorization_acknowledged = false,
    };
    try testing.expectError(error.MissingAuthorizationAcknowledgement, remote_profile.validate());
}

test "excessive cidr range is rejected" {
    const wide_cidr = AssessmentProfile{
        .id = "wide-cidr-test",
        .name = "Wide CIDR",
        .description = "Internet-wide range",
        .scope = .{
            .targets = &[_][]const u8{"0.0.0.0/0"},
            .ports = &[_]u16{80},
        },
        .authorization_acknowledged = true,
    };
    try testing.expectError(error.ExcessiveCidrRange, wide_cidr.validate());
}

test "empty targets rejected" {
    const empty_profile = AssessmentProfile{
        .id = "empty",
        .name = "Empty",
        .description = "Empty",
        .scope = .{
            .targets = &.{},
            .ports = &[_]u16{80},
        },
    };
    try testing.expectError(error.EmptyTargets, empty_profile.validate());
}
