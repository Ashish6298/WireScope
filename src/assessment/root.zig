const std = @import("std");
const testing = std.testing;

pub const config = @import("config.zig");
pub const WireScopeConfig = config.WireScopeConfig;
pub const ConfigValidationError = config.ConfigValidationError;

pub const profile = @import("profile.zig");
pub const AssessmentProfile = profile.AssessmentProfile;
pub const ProfileScope = profile.ProfileScope;
pub const ProfileChecks = profile.ProfileChecks;
pub const ProfileLimits = profile.ProfileLimits;
pub const ProfileValidationError = profile.ProfileValidationError;
pub const BuiltinProfiles = profile.BuiltinProfiles;

pub const redact = @import("redact.zig");
pub const redactSensitive = redact.redactSensitive;

pub const AssessmentStatus = enum {
    not_started,
    in_progress,
    completed,
    partial,
    cancelled,
    failed,
};

test "assessment root re-exports compile cleanly" {
    _ = config;
    _ = profile;
    _ = redact;

    const def_cfg = WireScopeConfig{};
    try def_cfg.validate();

    const loopback = BuiltinProfiles.loopback_diagnostic;
    try loopback.validate();
}
