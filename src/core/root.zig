const std = @import("std");
const testing = std.testing;

pub const outcome = @import("outcome.zig");
pub const OutcomeCategory = outcome.OutcomeCategory;

pub const errors = @import("errors.zig");
pub const ErrorCode = errors.ErrorCode;
pub const StructuredError = errors.StructuredError;

pub const clock = @import("clock.zig");
pub const Clock = clock.Clock;
pub const SystemClock = clock.SystemClock;
pub const MockClock = clock.MockClock;

pub const timing = @import("timing.zig");
pub const TimingStages = timing.TimingStages;
pub const OperationIdGenerator = timing.OperationIdGenerator;

pub const stats = @import("stats.zig");
pub const LatencyStats = stats.LatencyStats;
pub const PercentileSummary = stats.PercentileSummary;
pub const PercentileThresholds = stats.PercentileThresholds;

pub const results = @import("results.zig");
pub const OperationType = results.OperationType;
pub const OperationEnvelope = results.OperationEnvelope;
pub const OperationPayload = results.OperationPayload;
pub const DnsPayload = results.DnsPayload;
pub const TcpPayload = results.TcpPayload;
pub const TlsPayload = results.TlsPayload;
pub const HttpPayload = results.HttpPayload;
pub const InterfacePayload = results.InterfacePayload;
pub const ListenerPayload = results.ListenerPayload;
pub const GenericPayload = results.GenericPayload;

pub const models = @import("models.zig");
pub const Severity = models.Severity;
pub const Confidence = models.Confidence;
pub const Finding = models.Finding;
pub const FindingStatus = models.FindingStatus;
pub const ServiceObservation = models.ServiceObservation;
pub const Asset = models.Asset;

pub const Version = struct {
    pub const major: u32 = 0;
    pub const minor: u32 = 1;
    pub const patch: u32 = 0;
    pub const string: []const u8 = "0.1.0-dev";
};

test "core root re-exports compile and test cleanly" {
    _ = outcome;
    _ = errors;
    _ = clock;
    _ = timing;
    _ = stats;
    _ = results;
    _ = models;

    try testing.expectEqualStrings("0.1.0-dev", Version.string);
    try testing.expect(OutcomeCategory.success.isSuccess());
    try testing.expect(!OutcomeCategory.unsupported_capability.isSuccess());
}
