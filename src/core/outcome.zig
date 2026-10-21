const std = @import("std");
const testing = std.testing;

/// Typed outcome categories as defined in WireScope Master Specification Section 5.3 & 8.1
pub const OutcomeCategory = enum {
    success,
    refusal,
    timeout,
    no_answer,
    invalid_input,
    permission_denied,
    unsupported_capability,
    inconclusive,
    cancelled,
    operational_failure,

    /// Returns true strictly and only if the operation succeeded with verified evidence.
    pub fn isSuccess(self: OutcomeCategory) bool {
        return self == .success;
    }

    /// Returns true if the operation represents an explicit failure or inability to reach the target.
    pub fn isFailure(self: OutcomeCategory) bool {
        return switch (self) {
            .refusal, .timeout, .no_answer, .permission_denied, .operational_failure => true,
            else => false,
        };
    }

    /// Returns true if evidence is insufficient to determine target state.
    pub fn isInconclusive(self: OutcomeCategory) bool {
        return self == .inconclusive or self == .unsupported_capability or self == .cancelled;
    }

    pub fn toSlice(self: OutcomeCategory) []const u8 {
        return @tagName(self);
    }
};

test "outcome category classifications" {
    // Verified that unsupported and failed outcomes NEVER evaluate to success
    try testing.expect(OutcomeCategory.success.isSuccess());
    try testing.expect(!OutcomeCategory.unsupported_capability.isSuccess());
    try testing.expect(!OutcomeCategory.operational_failure.isSuccess());
    try testing.expect(!OutcomeCategory.inconclusive.isSuccess());
    try testing.expect(!OutcomeCategory.timeout.isSuccess());
    try testing.expect(!OutcomeCategory.refusal.isSuccess());
    try testing.expect(!OutcomeCategory.permission_denied.isSuccess());
    try testing.expect(!OutcomeCategory.cancelled.isSuccess());

    // Verified failure classification
    try testing.expect(OutcomeCategory.refusal.isFailure());
    try testing.expect(OutcomeCategory.timeout.isFailure());
    try testing.expect(!OutcomeCategory.success.isFailure());

    // Verified inconclusive classification
    try testing.expect(OutcomeCategory.inconclusive.isInconclusive());
    try testing.expect(OutcomeCategory.unsupported_capability.isInconclusive());
    try testing.expect(OutcomeCategory.cancelled.isInconclusive());
    try testing.expect(!OutcomeCategory.success.isInconclusive());
}
