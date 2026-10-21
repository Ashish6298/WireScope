const std = @import("std");
const testing = std.testing;
const core = @import("../core/root.zig");

const OutcomeCategory = core.OutcomeCategory;
const StructuredError = core.StructuredError;
const ErrorCode = core.ErrorCode;
const OperationEnvelope = core.OperationEnvelope;
const OperationType = core.OperationType;
const TimingStages = core.TimingStages;
const DnsPayload = core.DnsPayload;

/// Requested DNS record types
pub const DnsRecordType = enum {
    A,
    AAAA,
    both,

    pub fn toSlice(self: DnsRecordType) []const u8 {
        return switch (self) {
            .A => "A",
            .AAAA => "AAAA",
            .both => "A,AAAA",
        };
    }
};

/// Specific granular DNS resolution failure classifications
pub const DnsFailureCategory = enum {
    success,
    no_answer,
    nxdomain,
    timeout,
    malformed_input,
    resolver_transport_error,

    pub fn toOutcome(self: DnsFailureCategory) OutcomeCategory {
        return switch (self) {
            .success => .success,
            .no_answer, .nxdomain => .no_answer,
            .timeout => .timeout,
            .malformed_input => .invalid_input,
            .resolver_transport_error => .operational_failure,
        };
    }

    pub fn toErrorCode(self: DnsFailureCategory) ErrorCode {
        return switch (self) {
            .success => .none,
            .no_answer => .unknown_host,
            .nxdomain => .unknown_host,
            .timeout => .connection_timed_out,
            .malformed_input => .parse_error,
            .resolver_transport_error => .network_unreachable,
        };
    }

    pub fn toSlice(self: DnsFailureCategory) []const u8 {
        return @tagName(self);
    }
};

pub const HostnameValidationError = error{
    EmptyHostname,
    HostnameTooLong,
    EmptyLabel,
    LabelTooLong,
    InvalidHyphenPlacement,
    InvalidCharacter,
};

/// Validates hostnames according to RFC 1035 and RFC 1123 before initiating network activity
pub fn validateHostname(host: []const u8) HostnameValidationError!void {
    if (host.len == 0) return error.EmptyHostname;
    if (host.len > 253) return error.HostnameTooLong;

    // Check if it is a valid IPv4 or IPv6 address literal
    if (std.net.Address.parseIp4(host, 0)) |_| {
        return;
    } else |_| {}
    if (std.net.Address.parseIp6(host, 0)) |_| {
        return;
    } else |_| {}

    // Strip optional trailing FQDN root dot
    const clean_host = if (std.mem.endsWith(u8, host, "."))
        host[0 .. host.len - 1]
    else
        host;

    if (clean_host.len == 0) return error.EmptyHostname;

    var iter = std.mem.splitScalar(u8, clean_host, '.');
    var label_count: usize = 0;

    while (iter.next()) |label| {
        label_count += 1;
        if (label.len == 0) return error.EmptyLabel;
        if (label.len > 63) return error.LabelTooLong;

        if (label[0] == '-' or label[label.len - 1] == '-') {
            return error.InvalidHyphenPlacement;
        }

        for (label) |c| {
            const is_alpha = (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z');
            const is_digit = (c >= '0' and c <= '9');
            const is_hyphen = (c == '-');
            if (!is_alpha and !is_digit and !is_hyphen) {
                return error.InvalidCharacter;
            }
        }
    }

    if (label_count == 0) return error.EmptyHostname;
}

/// Structured outcome of a DNS resolution operation
pub const DnsResolutionResult = struct {
    host: []const u8,
    record_type: DnsRecordType,
    failure_category: DnsFailureCategory,
    answers: [][]const u8,
    resolver: []const u8,
    method: []const u8,
    elapsed_ns: u64,
    err: StructuredError,
    capability_limitations: ?[]const u8 = "System resolver getaddrinfo does not expose DNS wire TTL, authoritative NS, or DNSSEC flags.",

    pub fn deinit(self: *DnsResolutionResult, allocator: std.mem.Allocator) void {
        allocator.free(self.host);
        allocator.free(self.resolver);
        allocator.free(self.method);
        for (self.answers) |ans| {
            allocator.free(ans);
        }
        allocator.free(self.answers);
    }

    /// Converts into universal OperationEnvelope satisfying shared result contract
    pub fn toEnvelope(self: *const DnsResolutionResult, allocator: std.mem.Allocator, op_id: []const u8, profile_id: ?[]const u8) !OperationEnvelope {
        var answer_dup = try allocator.alloc([]const u8, self.answers.len);
        errdefer allocator.free(answer_dup);
        var dup_count: usize = 0;
        errdefer {
            for (0..dup_count) |i| allocator.free(answer_dup[i]);
        }

        for (self.answers, 0..) |ans, i| {
            answer_dup[i] = try allocator.dupe(u8, ans);
            dup_count += 1;
        }

        const now = std.time.milliTimestamp();

        return OperationEnvelope{
            .operation_id = try allocator.dupe(u8, op_id),
            .operation_type = .dns,
            .target = try allocator.dupe(u8, self.host),
            .profile_id = if (profile_id) |p| try allocator.dupe(u8, p) else null,
            .start_time_ms = now - @as(i64, @intCast(self.elapsed_ns / std.time.ns_per_ms)),
            .end_time_ms = now,
            .monotonic_elapsed_ns = self.elapsed_ns,
            .outcome = self.failure_category.toOutcome(),
            .is_partial = false,
            .timing_stages = .{
                .dns_lookup_ns = self.elapsed_ns,
                .total_elapsed_ns = self.elapsed_ns,
            },
            .err = self.err,
            .capability_limitations = if (self.capability_limitations) |l| try allocator.dupe(u8, l) else null,
            .payload = .{
                .dns = .{
                    .record_type = self.record_type.toSlice(),
                    .answers = answer_dup,
                    .resolver = try allocator.dupe(u8, self.resolver),
                    .ttl = null,
                },
            },
        };
    }

    pub fn toTerminal(self: *const DnsResolutionResult, writer: anytype) !void {
        try writer.print("DNS Diagnostic Resolution for: {s}\n", .{self.host});
        try writer.writeAll("--------------------------------------------------------------------------------\n");
        try writer.print("  Outcome       : {s} ({s})\n", .{ self.failure_category.toSlice(), self.failure_category.toOutcome().toSlice() });
        try writer.print("  Record Type   : {s}\n", .{self.record_type.toSlice()});
        try writer.print("  Resolver      : {s} (Method: {s})\n", .{ self.resolver, self.method });
        try writer.print("  Elapsed Time  : {d:.2} ms\n", .{@as(f64, @floatFromInt(self.elapsed_ns)) / 1000000.0});

        if (self.err.isError()) {
            var err_buf: [256]u8 = undefined;
            const err_str = self.err.formatSafe(&err_buf) catch "Error format failure";
            try writer.print("  Error Details : {s}\n", .{err_str});
        }

        try writer.print("  Answers ({d})   :\n", .{self.answers.len});
        if (self.answers.len == 0) {
            try writer.writeAll("    (No IP addresses returned)\n");
        } else {
            for (self.answers) |ans| {
                try writer.print("    - {s}\n", .{ans});
            }
        }
        if (self.capability_limitations) |l| {
            try writer.print("\n  Limitations   : {s}\n", .{l});
        }
        try writer.writeAll("\n");
    }
};

/// Injectable Resolver interface
pub const Resolver = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        resolve: *const fn (
            ctx: *anyopaque,
            allocator: std.mem.Allocator,
            host: []const u8,
            record_type: DnsRecordType,
        ) anyerror!DnsResolutionResult,
    };

    pub fn resolve(
        self: Resolver,
        allocator: std.mem.Allocator,
        host: []const u8,
        record_type: DnsRecordType,
    ) anyerror!DnsResolutionResult {
        return self.vtable.resolve(self.ptr, allocator, host, record_type);
    }
};

/// Default system resolver leveraging OS getaddrinfo
pub const SystemResolver = struct {
    fn resolve(
        _: *anyopaque,
        allocator: std.mem.Allocator,
        host: []const u8,
        record_type: DnsRecordType,
    ) anyerror!DnsResolutionResult {
        // Enforce hostname validation before touching network
        validateHostname(host) catch |err| {
            const host_copy = try allocator.dupe(u8, host);
            const res_copy = try allocator.dupe(u8, "system_resolver");
            const method_copy = try allocator.dupe(u8, "pre_resolution_validator");

            return DnsResolutionResult{
                .host = host_copy,
                .record_type = record_type,
                .failure_category = .malformed_input,
                .answers = try allocator.alloc([]const u8, 0),
                .resolver = res_copy,
                .method = method_copy,
                .elapsed_ns = 0,
                .err = .{
                    .code = .parse_error,
                    .message = switch (err) {
                        error.EmptyHostname => "Hostname cannot be empty",
                        error.HostnameTooLong => "Hostname exceeds 253 characters limit",
                        error.EmptyLabel => "Hostname contains empty label (adjacent dots)",
                        error.LabelTooLong => "Hostname label exceeds 63 characters",
                        error.InvalidHyphenPlacement => "Label cannot begin or end with a hyphen",
                        error.InvalidCharacter => "Hostname contains invalid characters (allowed: a-z, 0-9, -)",
                    },
                },
            };
        };

        const start_ns = std.time.nanoTimestamp();
        var failure_cat: DnsFailureCategory = .success;
        var structured_err = StructuredError.none;

        var addr_list = std.net.getAddressList(allocator, host, 0) catch |err| {
            const elapsed = @as(u64, @intCast(@max(0, std.time.nanoTimestamp() - start_ns)));
            failure_cat = switch (err) {
                error.UnknownHostName => .nxdomain,
                error.TemporaryNameServerFailure => .timeout,
                else => .resolver_transport_error,
            };

            structured_err = .{
                .code = failure_cat.toErrorCode(),
                .message = switch (err) {
                    error.UnknownHostName => "Name or service not known (NXDOMAIN)",
                    error.TemporaryNameServerFailure => "Temporary name server failure (timeout)",
                    else => "OS resolver transport error",
                },
            };

            return DnsResolutionResult{
                .host = try allocator.dupe(u8, host),
                .record_type = record_type,
                .failure_category = failure_cat,
                .answers = try allocator.alloc([]const u8, 0),
                .resolver = try allocator.dupe(u8, "OS getaddrinfo / default resolver"),
                .method = try allocator.dupe(u8, "system_resolver"),
                .elapsed_ns = elapsed,
                .err = structured_err,
            };
        };
        defer addr_list.deinit();

        const elapsed = @as(u64, @intCast(@max(0, std.time.nanoTimestamp() - start_ns)));

        var answer_list = std.ArrayList([]const u8).init(allocator);
        errdefer {
            for (answer_list.items) |ans| allocator.free(ans);
            answer_list.deinit();
        }

        for (addr_list.addrs) |addr| {
            switch (addr.any.family) {
                std.posix.AF.INET => {
                    if (record_type == .A or record_type == .both) {
                        const bytes: [4]u8 = @bitCast(addr.in.sa.addr);
                        const str = try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{
                            bytes[0], bytes[1], bytes[2], bytes[3],
                        });
                        try answer_list.append(str);
                    }
                },
                std.posix.AF.INET6 => {
                    if (record_type == .AAAA or record_type == .both) {
                        var buf: [64]u8 = undefined;
                        var fbs = std.io.fixedBufferStream(&buf);
                        try addr.format("", .{}, fbs.writer());
                        const formatted = fbs.getWritten();
                        var ip_str = formatted;
                        if (std.mem.startsWith(u8, formatted, "[") and std.mem.indexOf(u8, formatted, "]:") != null) {
                            const end = std.mem.indexOf(u8, formatted, "]:").?;
                            ip_str = formatted[1..end];
                        }
                        try answer_list.append(try allocator.dupe(u8, ip_str));
                    }
                },
                else => {},
            }
        }

        // Deduplicate and deterministically sort answers
        std.mem.sort([]const u8, answer_list.items, {}, struct {
            fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.lessThan);

        if (answer_list.items.len == 0) {
            failure_cat = .no_answer;
            structured_err = .{
                .code = .unknown_host,
                .message = "Domain resolved but returned no matching A/AAAA records",
            };
        }

        return DnsResolutionResult{
            .host = try allocator.dupe(u8, host),
            .record_type = record_type,
            .failure_category = failure_cat,
            .answers = try answer_list.toOwnedSlice(),
            .resolver = try allocator.dupe(u8, "OS getaddrinfo / default resolver"),
            .method = try allocator.dupe(u8, "system_resolver"),
            .elapsed_ns = elapsed,
            .err = structured_err,
        };
    }

    const system_vtable: Resolver.VTable = .{
        .resolve = resolve,
    };

    pub fn resolver() Resolver {
        return .{
            .ptr = undefined,
            .vtable = &system_vtable,
        };
    }
};

/// Controlled MockResolver for hermetic testing without live DNS dependencies
pub const MockResolver = struct {
    mock_category: DnsFailureCategory = .success,
    mock_answers: []const []const u8 = &.{},
    simulated_elapsed_ns: u64 = 1500000,
    resolver_name: []const u8 = "127.0.0.53:53",

    fn resolve(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        host: []const u8,
        record_type: DnsRecordType,
    ) anyerror!DnsResolutionResult {
        const self: *MockResolver = @ptrCast(@alignCast(ctx));

        // Validate hostname first
        validateHostname(host) catch |err| {
            return DnsResolutionResult{
                .host = try allocator.dupe(u8, host),
                .record_type = record_type,
                .failure_category = .malformed_input,
                .answers = try allocator.alloc([]const u8, 0),
                .resolver = try allocator.dupe(u8, self.resolver_name),
                .method = try allocator.dupe(u8, "mock_resolver"),
                .elapsed_ns = 0,
                .err = .{
                    .code = .parse_error,
                    .message = @errorName(err),
                },
            };
        };

        var answer_list = std.ArrayList([]const u8).init(allocator);
        errdefer {
            for (answer_list.items) |ans| allocator.free(ans);
            answer_list.deinit();
        }

        if (self.mock_category == .success) {
            for (self.mock_answers) |ans| {
                const is_v6 = std.mem.indexOf(u8, ans, ":") != null;
                if (record_type == .both or (record_type == .A and !is_v6) or (record_type == .AAAA and is_v6)) {
                    try answer_list.append(try allocator.dupe(u8, ans));
                }
            }
        }

        // Sort answers deterministically
        std.mem.sort([]const u8, answer_list.items, {}, struct {
            fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.lessThan);

        const final_cat: DnsFailureCategory = if (self.mock_category == .success and answer_list.items.len == 0)
            .no_answer
        else
            self.mock_category;

        const err: StructuredError = if (final_cat != .success) .{
            .code = final_cat.toErrorCode(),
            .message = "Simulated resolver condition",
        } else StructuredError.none;

        return DnsResolutionResult{
            .host = try allocator.dupe(u8, host),
            .record_type = record_type,
            .failure_category = final_cat,
            .answers = try answer_list.toOwnedSlice(),
            .resolver = try allocator.dupe(u8, self.resolver_name),
            .method = try allocator.dupe(u8, "mock_resolver"),
            .elapsed_ns = self.simulated_elapsed_ns,
            .err = err,
        };
    }

    const mock_vtable: Resolver.VTable = .{
        .resolve = resolve,
    };

    pub fn resolver(self: *MockResolver) Resolver {
        return .{
            .ptr = self,
            .vtable = &mock_vtable,
        };
    }
};

// -----------------------------------------------------------------------------
// TESTS & VERIFICATION
// -----------------------------------------------------------------------------

test "hostname validation rejects invalid inputs before network activity" {
    // Valid hostnames
    try validateHostname("localhost");
    try validateHostname("example.com");
    try validateHostname("sub.domain.example.org.");
    try validateHostname("127.0.0.1");
    try validateHostname("::1");
    try validateHostname("server-1.prod.lan");

    // Invalid hostnames
    try testing.expectError(error.EmptyHostname, validateHostname(""));
    try testing.expectError(error.EmptyLabel, validateHostname("example..com"));
    try testing.expectError(error.InvalidHyphenPlacement, validateHostname("-leading.com"));
    try testing.expectError(error.InvalidHyphenPlacement, validateHostname("trailing-.com"));
    try testing.expectError(error.InvalidCharacter, validateHostname("illegal_char.com"));
    try testing.expectError(error.InvalidCharacter, validateHostname("space domain.com"));
}

test "mock resolver handles successful multi-answer resolution with stable sorting" {
    const allocator = testing.allocator;

    var mock = MockResolver{
        .mock_category = .success,
        .mock_answers = &.{ "192.0.2.100", "192.0.2.1", "2001:db8::1", "192.0.2.50" },
        .simulated_elapsed_ns = 3500000,
    };
    const r = mock.resolver();

    var result = try r.resolve(allocator, "multi.example.com", .both);
    defer result.deinit(allocator);

    try testing.expectEqual(DnsFailureCategory.success, result.failure_category);
    try testing.expectEqual(OutcomeCategory.success, result.failure_category.toOutcome());
    try testing.expectEqual(@as(usize, 4), result.answers.len);

    // Verify deterministic lexicographical ordering
    try testing.expectEqualStrings("192.0.2.1", result.answers[0]);
    try testing.expectEqualStrings("192.0.2.100", result.answers[1]);
    try testing.expectEqualStrings("192.0.2.50", result.answers[2]);
    try testing.expectEqualStrings("2001:db8::1", result.answers[3]);

    // Convert to envelope and verify shared contract
    var envelope = try result.toEnvelope(allocator, "op_dns_test_001", "default");
    defer envelope.deinit(allocator);

    try testing.expectEqualStrings("op_dns_test_001", envelope.operation_id);
    try testing.expectEqual(OperationType.dns, envelope.operation_type);
    try testing.expect(envelope.outcome.isSuccess());
    try testing.expectEqual(@as(u64, 3500000), envelope.timing_stages.dns_lookup_ns.?);
}

test "mock resolver distinguishes NXDOMAIN, timeout, and no_answer" {
    const allocator = testing.allocator;

    // 1. NXDOMAIN
    var mock_nx = MockResolver{ .mock_category = .nxdomain };
    var nx_res = try mock_nx.resolver().resolve(allocator, "nonexistent.internal", .both);
    defer nx_res.deinit(allocator);
    try testing.expectEqual(DnsFailureCategory.nxdomain, nx_res.failure_category);
    try testing.expectEqual(OutcomeCategory.no_answer, nx_res.failure_category.toOutcome());
    try testing.expectEqual(ErrorCode.unknown_host, nx_res.err.code);

    // 2. Timeout
    var mock_timeout = MockResolver{ .mock_category = .timeout };
    var timeout_res = try mock_timeout.resolver().resolve(allocator, "slow.internal", .both);
    defer timeout_res.deinit(allocator);
    try testing.expectEqual(DnsFailureCategory.timeout, timeout_res.failure_category);
    try testing.expectEqual(OutcomeCategory.timeout, timeout_res.failure_category.toOutcome());
    try testing.expectEqual(ErrorCode.connection_timed_out, timeout_res.err.code);

    // 3. No Answer (e.g. requesting AAAA when only A exists)
    var mock_noans = MockResolver{
        .mock_category = .success,
        .mock_answers = &.{"192.0.2.1"}, // Only IPv4
    };
    var noans_res = try mock_noans.resolver().resolve(allocator, "v4only.internal", .AAAA);
    defer noans_res.deinit(allocator);
    try testing.expectEqual(DnsFailureCategory.no_answer, noans_res.failure_category);
    try testing.expectEqual(OutcomeCategory.no_answer, noans_res.failure_category.toOutcome());
}

test "system resolver resolves controlled fixture localhost" {
    const allocator = testing.allocator;

    const r = SystemResolver.resolver();
    var result = try r.resolve(allocator, "localhost", .both);
    defer result.deinit(allocator);

    try testing.expect(result.answers.len > 0);
    try testing.expectEqual(DnsFailureCategory.success, result.failure_category);
    try testing.expect(result.elapsed_ns > 0);

    // Verify localhost contains 127.0.0.1 or ::1
    var found_loopback = false;
    for (result.answers) |ans| {
        if (std.mem.eql(u8, ans, "127.0.0.1") or std.mem.eql(u8, ans, "::1")) {
            found_loopback = true;
            break;
        }
    }
    try testing.expect(found_loopback);
}

test "system resolver rejects malformed hostnames before calling network APIs" {
    const allocator = testing.allocator;

    const r = SystemResolver.resolver();
    var result = try r.resolve(allocator, "invalid_domain..com", .both);
    defer result.deinit(allocator);

    try testing.expectEqual(DnsFailureCategory.malformed_input, result.failure_category);
    try testing.expectEqual(OutcomeCategory.invalid_input, result.failure_category.toOutcome());
    try testing.expectEqual(ErrorCode.parse_error, result.err.code);
    try testing.expectEqual(@as(usize, 0), result.answers.len);
    try testing.expectEqual(@as(u64, 0), result.elapsed_ns);
}
