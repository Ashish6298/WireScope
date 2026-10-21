const std = @import("std");
const testing = std.testing;
const OutcomeCategory = @import("outcome.zig").OutcomeCategory;

/// Machine-readable error codes for WireScope operations
pub const ErrorCode = enum {
    none,
    unknown_host,
    connection_refused,
    connection_timed_out,
    network_unreachable,
    host_unreachable,
    tls_handshake_failed,
    tls_certificate_expired,
    tls_hostname_mismatch,
    tls_untrusted_root,
    http_protocol_error,
    http_response_oversized,
    http_redirect_loop,
    out_of_scope_target,
    scope_limit_exceeded,
    permission_denied,
    unsupported_platform_api,
    operation_cancelled,
    io_error,
    storage_corruption,
    parse_error,
    internal_error,

    /// Maps machine-readable error code to appropriate OutcomeCategory
    pub fn toOutcome(self: ErrorCode) OutcomeCategory {
        return switch (self) {
            .none => .success,
            .unknown_host => .no_answer,
            .connection_refused => .refusal,
            .connection_timed_out => .timeout,
            .network_unreachable, .host_unreachable, .io_error, .http_protocol_error => .operational_failure,
            .tls_handshake_failed, .tls_certificate_expired, .tls_hostname_mismatch, .tls_untrusted_root => .operational_failure,
            .http_response_oversized, .http_redirect_loop => .operational_failure,
            .out_of_scope_target, .scope_limit_exceeded, .parse_error => .invalid_input,
            .permission_denied => .permission_denied,
            .unsupported_platform_api => .unsupported_capability,
            .operation_cancelled => .cancelled,
            .storage_corruption, .internal_error => .operational_failure,
        };
    }
};

/// Structured, machine-readable, and terminal-independent error description
pub const StructuredError = struct {
    code: ErrorCode,
    message: []const u8,
    details: ?[]const u8 = null,

    pub const none: StructuredError = .{
        .code = .none,
        .message = "No error",
        .details = null,
    };

    pub fn isError(self: StructuredError) bool {
        return self.code != .none;
    }

    /// Returns a sanitized error string safe for public reporting and JSON output
    pub fn formatSafe(self: StructuredError, buf: []u8) ![]const u8 {
        if (!self.isError()) return "none";
        return std.fmt.bufPrint(buf, "{s}: {s}", .{ @tagName(self.code), self.message });
    }
};

test "structured error mapping and safety" {
    const err = StructuredError{
        .code = .connection_refused,
        .message = "Target actively refused connection on port 443",
    };

    try testing.expect(err.isError());
    try testing.expectEqual(OutcomeCategory.refusal, err.code.toOutcome());

    var buf: [128]u8 = undefined;
    const formatted = try err.formatSafe(&buf);
    try testing.expectEqualStrings("connection_refused: Target actively refused connection on port 443", formatted);

    const no_err = StructuredError.none;
    try testing.expect(!no_err.isError());
    try testing.expectEqual(OutcomeCategory.success, no_err.code.toOutcome());
}
