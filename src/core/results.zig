const std = @import("std");
const testing = std.testing;
const OutcomeCategory = @import("outcome.zig").OutcomeCategory;
const StructuredError = @import("errors.zig").StructuredError;
const TimingStages = @import("timing.zig").TimingStages;

/// Standard classification of diagnostic and assessment probe operations
pub const OperationType = enum {
    dns,
    tcp,
    tls,
    http,
    interface,
    listener,
    generic,

    pub fn toSlice(self: OperationType) []const u8 {
        return @tagName(self);
    }
};

/// DNS query payload
pub const DnsPayload = struct {
    record_type: []const u8,
    answers: [][]const u8,
    resolver: ?[]const u8 = null,
    ttl: ?u32 = null,

    pub fn deinit(self: *DnsPayload, allocator: std.mem.Allocator) void {
        for (self.answers) |ans| {
            allocator.free(ans);
        }
        allocator.free(self.answers);
        if (self.resolver) |r| allocator.free(r);
    }

    /// Deterministically sorts answers lexicographically
    pub fn sortAnswers(self: *DnsPayload) void {
        std.mem.sort([]const u8, self.answers, {}, struct {
            fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.lessThan);
    }

    pub fn toJson(self: DnsPayload, writer: anytype) !void {
        try writer.print("{{\"record_type\":\"{s}\",\"resolver\":", .{self.record_type});
        if (self.resolver) |r| {
            try writer.print("\"{s}\"", .{r});
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(",\"ttl\":");
        if (self.ttl) |t| {
            try writer.print("{d}", .{t});
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(",\"answers\":[");
        for (self.answers, 0..) |ans, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.print("\"{s}\"", .{ans});
        }
        try writer.writeAll("]}");
    }
};

/// TCP connection payload
pub const TcpPayload = struct {
    port: u16,
    is_open: bool,
    connect_time_ns: u64,
    bytes_sent: usize = 0,
    bytes_received: usize = 0,

    pub fn toJson(self: TcpPayload, writer: anytype) !void {
        try writer.print("{{\"port\":{d},\"is_open\":{s},\"connect_time_ns\":{d},\"bytes_sent\":{d},\"bytes_received\":{d}}}", .{
            self.port,
            if (self.is_open) "true" else "false",
            self.connect_time_ns,
            self.bytes_sent,
            self.bytes_received,
        });
    }
};

/// TLS inspection payload
pub const TlsPayload = struct {
    protocol_version: []const u8,
    cipher_suite: []const u8,
    subject: []const u8,
    issuer: []const u8,
    not_before: i64,
    not_after: i64,
    hostname_matched: bool,
    chain_valid: bool,

    pub fn deinit(self: *TlsPayload, allocator: std.mem.Allocator) void {
        allocator.free(self.protocol_version);
        allocator.free(self.cipher_suite);
        allocator.free(self.subject);
        allocator.free(self.issuer);
    }

    pub fn toJson(self: TlsPayload, writer: anytype) !void {
        try writer.print("{{\"protocol_version\":\"{s}\",\"cipher_suite\":\"{s}\",\"subject\":\"{s}\",\"issuer\":\"{s}\",\"not_before\":{d},\"not_after\":{d},\"hostname_matched\":{s},\"chain_valid\":{s}}}", .{
            self.protocol_version,
            self.cipher_suite,
            self.subject,
            self.issuer,
            self.not_before,
            self.not_after,
            if (self.hostname_matched) "true" else "false",
            if (self.chain_valid) "true" else "false",
        });
    }
};

/// HTTP security audit payload
pub const HttpPayload = struct {
    status_code: u16,
    hsts_header: ?[]const u8 = null,
    csp_header: ?[]const u8 = null,
    content_type_options: ?[]const u8 = null,
    redirect_target: ?[]const u8 = null,
    response_size_bytes: usize = 0,

    pub fn deinit(self: *HttpPayload, allocator: std.mem.Allocator) void {
        if (self.hsts_header) |h| allocator.free(h);
        if (self.csp_header) |c| allocator.free(c);
        if (self.content_type_options) |o| allocator.free(o);
        if (self.redirect_target) |r| allocator.free(r);
    }

    pub fn toJson(self: HttpPayload, writer: anytype) !void {
        try writer.print("{{\"status_code\":{d},\"response_size_bytes\":{d},\"hsts_header\":", .{
            self.status_code,
            self.response_size_bytes,
        });
        if (self.hsts_header) |h| try writer.print("\"{s}\"", .{h}) else try writer.writeAll("null");
        try writer.writeAll(",\"csp_header\":");
        if (self.csp_header) |c| try writer.print("\"{s}\"", .{c}) else try writer.writeAll("null");
        try writer.writeAll(",\"content_type_options\":");
        if (self.content_type_options) |o| try writer.print("\"{s}\"", .{o}) else try writer.writeAll("null");
        try writer.writeAll(",\"redirect_target\":");
        if (self.redirect_target) |r| try writer.print("\"{s}\"", .{r}) else try writer.writeAll("null");
        try writer.writeAll("}");
    }
};

/// Network interface payload
pub const InterfacePayload = struct {
    name: []const u8,
    display_name: []const u8,
    ipv4_addresses: [][]const u8,
    ipv6_addresses: [][]const u8,
    is_up: bool,
    is_loopback: bool,

    pub fn deinit(self: *InterfacePayload, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.display_name);
        for (self.ipv4_addresses) |addr| allocator.free(addr);
        allocator.free(self.ipv4_addresses);
        for (self.ipv6_addresses) |addr| allocator.free(addr);
        allocator.free(self.ipv6_addresses);
    }

    pub fn toJson(self: InterfacePayload, writer: anytype) !void {
        try writer.print("{{\"name\":\"{s}\",\"display_name\":\"{s}\",\"is_up\":{s},\"is_loopback\":{s},\"ipv4_addresses\":[", .{
            self.name,
            self.display_name,
            if (self.is_up) "true" else "false",
            if (self.is_loopback) "true" else "false",
        });
        for (self.ipv4_addresses, 0..) |ip, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.print("\"{s}\"", .{ip});
        }
        try writer.writeAll("],\"ipv6_addresses\":[");
        for (self.ipv6_addresses, 0..) |ip, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.print("\"{s}\"", .{ip});
        }
        try writer.writeAll("]}");
    }
};

/// Local listener payload
pub const ListenerPayload = struct {
    protocol: []const u8,
    local_address: []const u8,
    local_port: u16,
    is_loopback_only: bool,
    is_wildcard: bool,
    pid: ?u32 = null,

    pub fn deinit(self: *ListenerPayload, allocator: std.mem.Allocator) void {
        allocator.free(self.protocol);
        allocator.free(self.local_address);
    }

    pub fn toJson(self: ListenerPayload, writer: anytype) !void {
        try writer.print("{{\"protocol\":\"{s}\",\"local_address\":\"{s}\",\"local_port\":{d},\"is_loopback_only\":{s},\"is_wildcard\":{s},\"pid\":", .{
            self.protocol,
            self.local_address,
            self.local_port,
            if (self.is_loopback_only) "true" else "false",
            if (self.is_wildcard) "true" else "false",
        });
        if (self.pid) |p| try writer.print("{d}", .{p}) else try writer.writeAll("null");
        try writer.writeAll("}");
    }
};

/// Generic payload for standard connectivity or timing checks
pub const GenericPayload = struct {
    sample_count: usize = 1,
    details: ?[]const u8 = null,

    pub fn toJson(self: GenericPayload, writer: anytype) !void {
        try writer.print("{{\"sample_count\":{d},\"details\":", .{self.sample_count});
        if (self.details) |d| try writer.print("\"{s}\"", .{d}) else try writer.writeAll("null");
        try writer.writeAll("}");
    }
};

/// Tagged union of probe-specific payloads (Section 8.1 envelope pattern)
pub const OperationPayload = union(enum) {
    dns: DnsPayload,
    tcp: TcpPayload,
    tls: TlsPayload,
    http: HttpPayload,
    interface: InterfacePayload,
    listener: ListenerPayload,
    generic: GenericPayload,

    pub fn deinit(self: *OperationPayload, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .dns => |*d| d.deinit(allocator),
            .tls => |*t| t.deinit(allocator),
            .http => |*h| h.deinit(allocator),
            .interface => |*i| i.deinit(allocator),
            .listener => |*l| l.deinit(allocator),
            .tcp, .generic => {},
        }
    }

    pub fn toJson(self: OperationPayload, writer: anytype) !void {
        switch (self) {
            .dns => |d| try d.toJson(writer),
            .tcp => |t| try t.toJson(writer),
            .tls => |l| try l.toJson(writer),
            .http => |h| try h.toJson(writer),
            .interface => |i| try i.toJson(writer),
            .listener => |s| try s.toJson(writer),
            .generic => |g| try g.toJson(writer),
        }
    }
};

/// Standard Operation Result Envelope (Master Spec Section 8.1)
pub const OperationEnvelope = struct {
    operation_id: []const u8,
    operation_type: OperationType,
    target: []const u8,
    profile_id: ?[]const u8 = null,
    start_time_ms: i64,
    end_time_ms: i64,
    monotonic_elapsed_ns: u64,
    outcome: OutcomeCategory,
    is_partial: bool = false,
    timing_stages: TimingStages = .{},
    err: StructuredError = StructuredError.none,
    capability_limitations: ?[]const u8 = null,
    payload: OperationPayload,

    pub fn deinit(self: *OperationEnvelope, allocator: std.mem.Allocator) void {
        allocator.free(self.operation_id);
        allocator.free(self.target);
        if (self.profile_id) |p| allocator.free(p);
        if (self.capability_limitations) |l| allocator.free(l);
        self.payload.deinit(allocator);
    }

    /// Serializes envelope with strictly deterministic key ordering
    pub fn toJson(self: *const OperationEnvelope, writer: anytype) !void {
        try writer.print(
            \\{{"operation_id":"{s}","operation_type":"{s}","target":"{s}","profile_id":
        , .{
            self.operation_id,
            self.operation_type.toSlice(),
            self.target,
        });

        if (self.profile_id) |p| {
            try writer.print("\"{s}\"", .{p});
        } else {
            try writer.writeAll("null");
        }

        try writer.print(
            \\,"start_time_ms":{d},"end_time_ms":{d},"monotonic_elapsed_ns":{d},"outcome":"{s}","is_partial":{s},"timing_stages":
        , .{
            self.start_time_ms,
            self.end_time_ms,
            self.monotonic_elapsed_ns,
            self.outcome.toSlice(),
            if (self.is_partial) "true" else "false",
        });

        try self.timing_stages.toJson(writer);

        try writer.writeAll(",\"error\":");
        try self.err.toJson(writer);

        try writer.writeAll(",\"capability_limitations\":");
        if (self.capability_limitations) |l| {
            try writer.print("\"{s}\"", .{l});
        } else {
            try writer.writeAll("null");
        }

        try writer.writeAll(",\"payload\":");
        try self.payload.toJson(writer);

        try writer.writeAll("}\n");
    }
};

test "result envelope construction and memory deinit" {
    const allocator = testing.allocator;

    var answers = try allocator.alloc([]const u8, 2);
    answers[0] = try allocator.dupe(u8, "127.0.0.1");
    answers[1] = try allocator.dupe(u8, "::1");

    var envelope = OperationEnvelope{
        .operation_id = try allocator.dupe(u8, "op-dns-001"),
        .operation_type = .dns,
        .target = try allocator.dupe(u8, "localhost"),
        .profile_id = try allocator.dupe(u8, "default"),
        .start_time_ms = 1700000000000,
        .end_time_ms = 1700000000005,
        .monotonic_elapsed_ns = 2500000,
        .outcome = .success,
        .is_partial = false,
        .timing_stages = .{
            .dns_lookup_ns = 2500000,
            .total_elapsed_ns = 2500000,
        },
        .err = StructuredError.none,
        .capability_limitations = null,
        .payload = .{
            .dns = .{
                .record_type = "A,AAAA",
                .answers = answers,
                .resolver = try allocator.dupe(u8, "127.0.0.53"),
            },
        },
    };
    defer envelope.deinit(allocator);

    try testing.expectEqualStrings("op-dns-001", envelope.operation_id);
    try testing.expectEqual(OperationType.dns, envelope.operation_type);
    try testing.expectEqualStrings("localhost", envelope.target);
    try testing.expect(envelope.outcome.isSuccess());
    try testing.expectEqual(@as(usize, 2), envelope.payload.dns.answers.len);
}

test "deterministic envelope JSON serialization" {
    const allocator = testing.allocator;

    var envelope = OperationEnvelope{
        .operation_id = try allocator.dupe(u8, "op_tcp_000001"),
        .operation_type = .tcp,
        .target = try allocator.dupe(u8, "127.0.0.1:8080"),
        .profile_id = try allocator.dupe(u8, "loopback"),
        .start_time_ms = 1700000000000,
        .end_time_ms = 1700000000010,
        .monotonic_elapsed_ns = 1200000,
        .outcome = .refusal,
        .is_partial = false,
        .timing_stages = .{
            .tcp_connect_ns = 1200000,
            .total_elapsed_ns = 1200000,
        },
        .err = .{
            .code = .connection_refused,
            .message = "Connection refused on port 8080",
            .details = null,
        },
        .capability_limitations = null,
        .payload = .{
            .tcp = .{
                .port = 8080,
                .is_open = false,
                .connect_time_ns = 1200000,
                .bytes_sent = 0,
                .bytes_received = 0,
            },
        },
    };
    defer envelope.deinit(allocator);

    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try envelope.toJson(fbs.writer());

    const expected = "{\"operation_id\":\"op_tcp_000001\",\"operation_type\":\"tcp\",\"target\":\"127.0.0.1:8080\",\"profile_id\":\"loopback\",\"start_time_ms\":1700000000000,\"end_time_ms\":1700000000010,\"monotonic_elapsed_ns\":1200000,\"outcome\":\"refusal\",\"is_partial\":false,\"timing_stages\":{\"tcp_connect_ns\":1200000,\"total_elapsed_ns\":1200000},\"error\":{\"code\":\"connection_refused\",\"message\":\"Connection refused on port 8080\",\"details\":null},\"capability_limitations\":null,\"payload\":{\"port\":8080,\"is_open\":false,\"connect_time_ns\":1200000,\"bytes_sent\":0,\"bytes_received\":0}}\n";
    try testing.expectEqualStrings(expected, fbs.getWritten());
}

test "partial and cancelled operations remain distinguishable" {
    const allocator = testing.allocator;

    // 1. Cancelled operation
    var cancelled_env = OperationEnvelope{
        .operation_id = try allocator.dupe(u8, "op_cancel_1"),
        .operation_type = .http,
        .target = try allocator.dupe(u8, "https://127.0.0.1:8443"),
        .start_time_ms = 1700000000000,
        .end_time_ms = 1700000000020,
        .monotonic_elapsed_ns = 20000000,
        .outcome = .cancelled,
        .is_partial = true,
        .timing_stages = .{ .total_elapsed_ns = 20000000 },
        .err = .{ .code = .operation_cancelled, .message = "Operation aborted by user" },
        .payload = .{
            .http = .{ .status_code = 0, .response_size_bytes = 0 },
        },
    };
    defer cancelled_env.deinit(allocator);

    // 2. Timed out operation (partial due to timeout)
    var timeout_env = OperationEnvelope{
        .operation_id = try allocator.dupe(u8, "op_timeout_2"),
        .operation_type = .tcp,
        .target = try allocator.dupe(u8, "10.0.0.99:443"),
        .start_time_ms = 1700000000000,
        .end_time_ms = 1700000005000,
        .monotonic_elapsed_ns = 5000000000,
        .outcome = .timeout,
        .is_partial = true,
        .timing_stages = .{ .total_elapsed_ns = 5000000000 },
        .err = .{ .code = .connection_timed_out, .message = "TCP connect deadline exceeded" },
        .payload = .{
            .tcp = .{ .port = 443, .is_open = false, .connect_time_ns = 5000000000 },
        },
    };
    defer timeout_env.deinit(allocator);

    // 3. Inconclusive operation
    var inconclusive_env = OperationEnvelope{
        .operation_id = try allocator.dupe(u8, "op_inconclusive_3"),
        .operation_type = .generic,
        .target = try allocator.dupe(u8, "192.168.1.1"),
        .start_time_ms = 1700000000000,
        .end_time_ms = 1700000000050,
        .monotonic_elapsed_ns = 50000000,
        .outcome = .inconclusive,
        .is_partial = false,
        .timing_stages = .{ .total_elapsed_ns = 50000000 },
        .err = StructuredError.none,
        .payload = .{ .generic = .{ .details = "Packet dropped by intermediate firewall" } },
    };
    defer inconclusive_env.deinit(allocator);

    // Strict distinguishability assertions:
    try testing.expectEqual(OutcomeCategory.cancelled, cancelled_env.outcome);
    try testing.expectEqual(OutcomeCategory.timeout, timeout_env.outcome);
    try testing.expectEqual(OutcomeCategory.inconclusive, inconclusive_env.outcome);

    try testing.expect(cancelled_env.is_partial);
    try testing.expect(timeout_env.is_partial);
    try testing.expect(!inconclusive_env.is_partial);

    try testing.expect(cancelled_env.outcome != timeout_env.outcome);
    try testing.expect(cancelled_env.outcome != inconclusive_env.outcome);
    try testing.expect(timeout_env.outcome != inconclusive_env.outcome);
}

test "dns payload answer sorting is deterministic" {
    const allocator = testing.allocator;

    var answers = try allocator.alloc([]const u8, 4);
    answers[0] = try allocator.dupe(u8, "192.168.1.100");
    answers[1] = try allocator.dupe(u8, "10.0.0.1");
    answers[2] = try allocator.dupe(u8, "172.16.0.5");
    answers[3] = try allocator.dupe(u8, "127.0.0.1");

    var payload = DnsPayload{
        .record_type = "A",
        .answers = answers,
    };
    defer payload.deinit(allocator);

    payload.sortAnswers();

    try testing.expectEqualStrings("10.0.0.1", payload.answers[0]);
    try testing.expectEqualStrings("127.0.0.1", payload.answers[1]);
    try testing.expectEqualStrings("172.16.0.5", payload.answers[2]);
    try testing.expectEqualStrings("192.168.1.100", payload.answers[3]);
}
