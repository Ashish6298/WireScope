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

pub const runner = @import("runner.zig");
pub const AssessmentStatus = runner.AssessmentStatus;
pub const AssessmentRunner = runner.AssessmentRunner;
pub const AssessmentResult = runner.AssessmentResult;
pub const AssessmentManifest = runner.AssessmentManifest;
pub const AssessmentObservations = runner.AssessmentObservations;
pub const AssessmentRunOptions = runner.AssessmentRunOptions;
pub const AssessmentExecutionMode = runner.AssessmentExecutionMode;
pub const TaskFailure = runner.TaskFailure;
pub const DnsObservationRecord = runner.DnsObservationRecord;
pub const TcpObservationRecord = runner.TcpObservationRecord;
pub const TlsObservationRecord = runner.TlsObservationRecord;
pub const HttpObservationRecord = runner.HttpObservationRecord;
pub const ListenerObservationRecord = runner.ListenerObservationRecord;

test "assessment root re-exports compile cleanly" {
    _ = config;
    _ = profile;
    _ = redact;
    _ = runner;

    const def_cfg = WireScopeConfig{};
    try def_cfg.validate();

    const loopback = BuiltinProfiles.loopback_diagnostic;
    try loopback.validate();
}
