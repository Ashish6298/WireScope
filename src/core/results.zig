const std = @import("std");
const testing = std.testing;
const OutcomeCategory = @import("outcome.zig").OutcomeCategory;
const StructuredError = @import("errors.zig").StructuredError;

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
};

/// TCP connection payload
pub const TcpPayload = struct {
    port: u16,
    is_open: bool,
    connect_time_ns: u64,
    bytes_sent: usize = 0,
    bytes_received: usize = 0,
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
};

/// Generic payload for standard connectivity or timing checks
pub const GenericPayload = struct {
    sample_count: usize = 1,
    details: ?[]const u8 = null,
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
};

/// Standard Operation Result Envelope
pub const OperationEnvelope = struct {
    operation_id: []const u8,
    target: []const u8,
    profile_id: ?[]const u8 = null,
    start_time_ms: i64,
    elapsed_ns: u64,
    outcome: OutcomeCategory,
    err: StructuredError = StructuredError.none,
    payload: OperationPayload,

    pub fn deinit(self: *OperationEnvelope, allocator: std.mem.Allocator) void {
        allocator.free(self.operation_id);
        allocator.free(self.target);
        if (self.profile_id) |p| allocator.free(p);
        self.payload.deinit(allocator);
    }
};

test "result envelope construction and memory deinit" {
    const allocator = testing.allocator;

    var answers = try allocator.alloc([]const u8, 2);
    answers[0] = try allocator.dupe(u8, "127.0.0.1");
    answers[1] = try allocator.dupe(u8, "::1");

    var envelope = OperationEnvelope{
        .operation_id = try allocator.dupe(u8, "op-dns-001"),
        .target = try allocator.dupe(u8, "localhost"),
        .profile_id = try allocator.dupe(u8, "default"),
        .start_time_ms = 1700000000000,
        .elapsed_ns = 2500000,
        .outcome = .success,
        .err = StructuredError.none,
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
    try testing.expectEqualStrings("localhost", envelope.target);
    try testing.expect(envelope.outcome.isSuccess());
    try testing.expectEqual(@as(usize, 2), envelope.payload.dns.answers.len);
}

test "TCP operation envelope without memory leaks" {
    const allocator = testing.allocator;

    var envelope = OperationEnvelope{
        .operation_id = try allocator.dupe(u8, "op-tcp-002"),
        .target = try allocator.dupe(u8, "127.0.0.1:8080"),
        .start_time_ms = 1700000000000,
        .elapsed_ns = 1200000,
        .outcome = .refusal,
        .err = .{
            .code = .connection_refused,
            .message = "Connection refused on port 8080",
        },
        .payload = .{
            .tcp = .{
                .port = 8080,
                .is_open = false,
                .connect_time_ns = 1200000,
            },
        },
    };
    defer envelope.deinit(allocator);

    try testing.expect(!envelope.outcome.isSuccess());
    try testing.expect(envelope.outcome.isFailure());
    try testing.expectEqual(@as(u16, 8080), envelope.payload.tcp.port);
}
