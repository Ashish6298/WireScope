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

    /// Deterministic JSON serialization for structured error details
    pub fn toJson(self: StructuredError, writer: anytype) !void {
        try writer.print("{{\"code\":\"{s}\",\"message\":\"{s}\",\"details\":", .{
            @tagName(self.code),
            self.message,
        });
        if (self.details) |d| {
            try writer.print("\"{s}\"", .{d});
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll("}");
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

test "comprehensive error category outcome classifications" {
    // Network refusal & timeouts
    try testing.expectEqual(OutcomeCategory.refusal, ErrorCode.connection_refused.toOutcome());
    try testing.expectEqual(OutcomeCategory.timeout, ErrorCode.connection_timed_out.toOutcome());
    try testing.expectEqual(OutcomeCategory.no_answer, ErrorCode.unknown_host.toOutcome());

    // Security & policy boundaries
    try testing.expectEqual(OutcomeCategory.invalid_input, ErrorCode.out_of_scope_target.toOutcome());
    try testing.expectEqual(OutcomeCategory.invalid_input, ErrorCode.scope_limit_exceeded.toOutcome());
    try testing.expectEqual(OutcomeCategory.permission_denied, ErrorCode.permission_denied.toOutcome());
    try testing.expectEqual(OutcomeCategory.unsupported_capability, ErrorCode.unsupported_platform_api.toOutcome());
    try testing.expectEqual(OutcomeCategory.cancelled, ErrorCode.operation_cancelled.toOutcome());

    // Operational failures
    try testing.expectEqual(OutcomeCategory.operational_failure, ErrorCode.tls_handshake_failed.toOutcome());
    try testing.expectEqual(OutcomeCategory.operational_failure, ErrorCode.network_unreachable.toOutcome());
    try testing.expectEqual(OutcomeCategory.operational_failure, ErrorCode.http_protocol_error.toOutcome());
    try testing.expectEqual(OutcomeCategory.operational_failure, ErrorCode.storage_corruption.toOutcome());
    try testing.expectEqual(OutcomeCategory.operational_failure, ErrorCode.internal_error.toOutcome());
}

test "structured error json serialization" {
    const err = StructuredError{
        .code = .tls_hostname_mismatch,
        .message = "Certificate does not match hostname",
        .details = "SAN mismatch for example.internal",
    };

    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try err.toJson(fbs.writer());

    const expected = "{\"code\":\"tls_hostname_mismatch\",\"message\":\"Certificate does not match hostname\",\"details\":\"SAN mismatch for example.internal\"}";
    try testing.expectEqualStrings(expected, fbs.getWritten());
}
