const std = @import("std");
const testing = std.testing;
const core = @import("../core/root.zig");

pub const troubleshooting_mod = @import("dns_troubleshooting.zig");
pub const DnsTroubleshooting = troubleshooting_mod.DnsTroubleshooting;
pub const generateTroubleshooting = troubleshooting_mod.generateTroubleshooting;
pub const explainDisagreement = troubleshooting_mod.explainDisagreement;

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

        const tb = self.getTroubleshooting();
        try writer.writeAll("\n  Troubleshooting Guidance:\n");
        try writer.print("    Summary: {s}\n", .{tb.summary});
        if (tb.possible_causes.len > 0) {
            try writer.writeAll("    Possible Causes:\n");
            for (tb.possible_causes) |cause| {
                try writer.print("      * {s}\n", .{cause});
            }
        }
        if (tb.recommended_actions.len > 0) {
            try writer.writeAll("    Recommended Actions:\n");
            for (tb.recommended_actions) |action| {
                try writer.print("      * {s}\n", .{action});
            }
        }
        if (tb.context_notes) |notes| {
            try writer.print("    Context: {s}\n", .{notes});
        }
        try writer.writeAll("\n");
    }

    pub fn getTroubleshooting(self: *const DnsResolutionResult) DnsTroubleshooting {
        return generateTroubleshooting(self.failure_category.toSlice(), self.answers.len);
    }
};

/// Preserved individual result entry from an explicitly queried resolver
pub const ResolverComparisonEntry = struct {
    resolver: []const u8,
    failure_category: DnsFailureCategory,
    answers: [][]const u8,
    elapsed_ns: u64,
    err: StructuredError,

    pub fn deinit(self: *ResolverComparisonEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.resolver);
        for (self.answers) |ans| allocator.free(ans);
        allocator.free(self.answers);
    }
};

/// Side-by-side comparison result across multiple explicitly configured resolvers
pub const ResolverComparisonResult = struct {
    host: []const u8,
    record_type: DnsRecordType,
    entries: []ResolverComparisonEntry,
    answers_match: bool,
    disagreement_analysis: ?[]const u8 = null,

    pub fn deinit(self: *ResolverComparisonResult, allocator: std.mem.Allocator) void {
        allocator.free(self.host);
        for (self.entries) |*e| e.deinit(allocator);
        allocator.free(self.entries);
    }

    pub fn toJson(self: *const ResolverComparisonResult, writer: anytype) !void {
        try writer.print(
            \\{{"host":"{s}","record_type":"{s}","answers_match":{s},"disagreement_analysis":
        , .{
            self.host,
            self.record_type.toSlice(),
            if (self.answers_match) "true" else "false",
        });
        if (self.disagreement_analysis) |da| {
            try writer.print("\"{s}\"", .{da});
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(",\"resolvers\":[");
        for (self.entries, 0..) |e, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.print(
                \\{{"resolver":"{s}","outcome":"{s}","elapsed_ns":{d},"error":
            , .{
                e.resolver,
                e.failure_category.toSlice(),
                e.elapsed_ns,
            });
            try e.err.toJson(writer);
            try writer.writeAll(",\"answers\":[");
            for (e.answers, 0..) |ans, ai| {
                if (ai > 0) try writer.writeAll(",");
                try writer.print("\"{s}\"", .{ans});
            }
            try writer.writeAll("]}");
        }
        try writer.writeAll("]}\n");
    }

    pub fn toTerminal(self: *const ResolverComparisonResult, writer: anytype) !void {
        try writer.print("DNS Resolver Comparison for: {s} ({s})\n", .{ self.host, self.record_type.toSlice() });
        try writer.writeAll("--------------------------------------------------------------------------------\n");
        try writer.print("  {s:<25} {s:<18} {s:<12} {s}\n", .{ "Resolver", "Outcome", "Latency", "Answers" });
        try writer.writeAll("  ----------------------------------------------------------------------------\n");

        for (self.entries) |e| {
            var ans_summary_buf: [128]u8 = undefined;
            var ans_str: []const u8 = "-";
            if (e.answers.len > 0) {
                if (e.answers.len == 1) {
                    ans_str = e.answers[0];
                } else {
                    ans_str = std.fmt.bufPrint(&ans_summary_buf, "{s} (+{d} more)", .{ e.answers[0], e.answers.len - 1 }) catch e.answers[0];
                }
            }

            const latency_ms = @as(f64, @floatFromInt(e.elapsed_ns)) / 1000000.0;
            try writer.print("  {s:<25} {s:<18} {d:>8.2} ms   {s}\n", .{
                e.resolver,
                e.failure_category.toSlice(),
                latency_ms,
                ans_str,
            });
        }
        try writer.writeAll("\n");

        if (!self.answers_match) {
            try writer.writeAll("  Observations & Analysis:\n");
            try writer.print("    [!] Answer Disagreement Observed: {s}\n\n", .{
                self.disagreement_analysis orelse "Answers differ across queried resolvers.",
            });
        } else {
            try writer.writeAll("  Observations & Analysis:\n");
            try writer.writeAll("    [=] Answer Consistency: All responding resolvers returned identical answer sets.\n\n");
        }
    }
};

/// Compares resolution outcomes across explicitly configured resolvers
pub fn compareResolvers(
    allocator: std.mem.Allocator,
    host: []const u8,
    record_type: DnsRecordType,
    resolvers: []const Resolver,
    labels: []const []const u8,
) !ResolverComparisonResult {
    var entries = try allocator.alloc(ResolverComparisonEntry, resolvers.len);
    var entries_initialized: usize = 0;
    errdefer {
        for (0..entries_initialized) |i| entries[i].deinit(allocator);
        allocator.free(entries);
    }

    for (resolvers, 0..) |r, i| {
        var res = try r.resolve(allocator, host, record_type);
        defer res.deinit(allocator);

        var answers_copy = try allocator.alloc([]const u8, res.answers.len);
        var ans_dup_count: usize = 0;
        errdefer {
            for (0..ans_dup_count) |j| allocator.free(answers_copy[j]);
            allocator.free(answers_copy);
        }
        for (res.answers, 0..) |ans, j| {
            answers_copy[j] = try allocator.dupe(u8, ans);
            ans_dup_count += 1;
        }

        entries[i] = .{
            .resolver = try allocator.dupe(u8, labels[i]),
            .failure_category = res.failure_category,
            .answers = answers_copy,
            .elapsed_ns = res.elapsed_ns,
            .err = res.err,
        };
        entries_initialized += 1;
    }

    // Compare answer sets across successful entries
    var answers_match = true;
    var first_successful_idx: ?usize = null;

    for (entries, 0..) |e, i| {
        if (e.failure_category == .success) {
            if (first_successful_idx == null) {
                first_successful_idx = i;
            } else {
                const first = entries[first_successful_idx.?];
                if (first.answers.len != e.answers.len) {
                    answers_match = false;
                    break;
                }
                for (first.answers, 0..) |ans, a_idx| {
                    if (!std.mem.eql(u8, ans, e.answers[a_idx])) {
                        answers_match = false;
                        break;
                    }
                }
                if (!answers_match) break;
            }
        }
    }

    const analysis: ?[]const u8 = if (!answers_match)
        explainDisagreement("resolver_a", "resolver_b")
    else
        null;

    return ResolverComparisonResult{
        .host = try allocator.dupe(u8, host),
        .record_type = record_type,
        .entries = entries,
        .answers_match = answers_match,
        .disagreement_analysis = analysis,
    };
}

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

/// Direct UDP DNS resolver querying specific nameservers via RFC 1035 wire protocol
pub const CustomUdpResolver = struct {
    resolver_ip: []const u8,
    port: u16 = 53,
    timeout_ms: u32 = 3000,

    fn resolve(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        host: []const u8,
        record_type: DnsRecordType,
    ) anyerror!DnsResolutionResult {
        const self: *CustomUdpResolver = @ptrCast(@alignCast(ctx));

        validateHostname(host) catch |err| {
            return DnsResolutionResult{
                .host = try allocator.dupe(u8, host),
                .record_type = record_type,
                .failure_category = .malformed_input,
                .answers = try allocator.alloc([]const u8, 0),
                .resolver = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ self.resolver_ip, self.port }),
                .method = try allocator.dupe(u8, "custom_udp_resolver"),
                .elapsed_ns = 0,
                .err = .{
                    .code = .parse_error,
                    .message = @errorName(err),
                },
            };
        };

        const start_ns = std.time.nanoTimestamp();

        const res_addr = std.net.Address.parseIp(self.resolver_ip, self.port) catch {
            return DnsResolutionResult{
                .host = try allocator.dupe(u8, host),
                .record_type = record_type,
                .failure_category = .resolver_transport_error,
                .answers = try allocator.alloc([]const u8, 0),
                .resolver = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ self.resolver_ip, self.port }),
                .method = try allocator.dupe(u8, "custom_udp_resolver"),
                .elapsed_ns = 0,
                .err = .{
                    .code = .parse_error,
                    .message = "Invalid resolver IP address syntax",
                },
            };
        };

        var query_buf: [512]u8 = undefined;
        var query_fbs = std.io.fixedBufferStream(&query_buf);
        const q_writer = query_fbs.writer();

        const query_id: u16 = 0x5753; // "WS" WireScope
        try q_writer.writeInt(u16, query_id, .big);
        try q_writer.writeInt(u16, 0x0100, .big); // Standard query with recursion desired
        try q_writer.writeInt(u16, 1, .big); // QDCOUNT: 1
        try q_writer.writeInt(u16, 0, .big);
        try q_writer.writeInt(u16, 0, .big);
        try q_writer.writeInt(u16, 0, .big);

        var iter = std.mem.splitScalar(u8, host, '.');
        while (iter.next()) |lbl| {
            if (lbl.len == 0) continue;
            try q_writer.writeByte(@intCast(lbl.len));
            try q_writer.writeAll(lbl);
        }
        try q_writer.writeByte(0);

        const qtype: u16 = if (record_type == .AAAA) 28 else 1;
        try q_writer.writeInt(u16, qtype, .big);
        try q_writer.writeInt(u16, 1, .big);

        const query_payload = query_fbs.getWritten();

        const sock = std.posix.socket(res_addr.any.family, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP) catch {
            const elapsed = @as(u64, @intCast(@max(0, std.time.nanoTimestamp() - start_ns)));
            return DnsResolutionResult{
                .host = try allocator.dupe(u8, host),
                .record_type = record_type,
                .failure_category = .resolver_transport_error,
                .answers = try allocator.alloc([]const u8, 0),
                .resolver = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ self.resolver_ip, self.port }),
                .method = try allocator.dupe(u8, "custom_udp_resolver"),
                .elapsed_ns = elapsed,
                .err = .{ .code = .network_unreachable, .message = "Failed to allocate socket" },
            };
        };
        defer std.posix.close(sock);

        var resp_buf: [1024]u8 = undefined;
        var recvd: usize = 0;
        if (comptime @import("builtin").os.tag == .windows) {
            const SOL_SOCKET_WIN: i32 = 0xffff;
            const SO_RCVTIMEO_WIN: i32 = 0x1006;
            const tv_ms: u32 = self.timeout_ms;
            _ = std.os.windows.ws2_32.setsockopt(sock, SOL_SOCKET_WIN, SO_RCVTIMEO_WIN, @ptrCast(&tv_ms), @sizeOf(u32));

            _ = std.os.windows.ws2_32.sendto(sock, query_payload.ptr, @intCast(query_payload.len), 0, @ptrCast(&res_addr.any), @intCast(res_addr.getOsSockLen()));

            var from_len: i32 = @sizeOf(std.os.windows.ws2_32.sockaddr);
            const r_ret = std.os.windows.ws2_32.recvfrom(sock, &resp_buf, @intCast(resp_buf.len), 0, null, &from_len);
            if (r_ret < 0) {
                const elapsed = @as(u64, @intCast(@max(0, std.time.nanoTimestamp() - start_ns)));
                return DnsResolutionResult{
                    .host = try allocator.dupe(u8, host),
                    .record_type = record_type,
                    .failure_category = .timeout,
                    .answers = try allocator.alloc([]const u8, 0),
                    .resolver = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ self.resolver_ip, self.port }),
                    .method = try allocator.dupe(u8, "custom_udp_resolver"),
                    .elapsed_ns = elapsed,
                    .err = .{
                        .code = .connection_timed_out,
                        .message = "Resolver UDP response timed out",
                    },
                };
            }
            recvd = @intCast(r_ret);
        } else {
            const PosixTimeval = extern struct {
                sec: isize,
                usec: isize,
            };
            const tv = PosixTimeval{
                .sec = @intCast(self.timeout_ms / 1000),
                .usec = @intCast((self.timeout_ms % 1000) * 1000),
            };
            _ = std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};

            _ = std.posix.sendto(sock, query_payload, 0, &res_addr.any, res_addr.getOsSockLen()) catch {
                const elapsed = @as(u64, @intCast(@max(0, std.time.nanoTimestamp() - start_ns)));
                return DnsResolutionResult{
                    .host = try allocator.dupe(u8, host),
                    .record_type = record_type,
                    .failure_category = .resolver_transport_error,
                    .answers = try allocator.alloc([]const u8, 0),
                    .resolver = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ self.resolver_ip, self.port }),
                    .method = try allocator.dupe(u8, "custom_udp_resolver"),
                    .elapsed_ns = elapsed,
                    .err = .{ .code = .network_unreachable, .message = "Failed to transmit UDP query to resolver" },
                };
            };

            var src_addr: std.posix.sockaddr = undefined;
            var src_addr_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
            recvd = std.posix.recvfrom(sock, &resp_buf, 0, &src_addr, &src_addr_len) catch |err| {
                const elapsed = @as(u64, @intCast(@max(0, std.time.nanoTimestamp() - start_ns)));
                const is_timeout = (err == error.WouldBlock or err == error.TimedOut);
                return DnsResolutionResult{
                    .host = try allocator.dupe(u8, host),
                    .record_type = record_type,
                    .failure_category = if (is_timeout) .timeout else .resolver_transport_error,
                    .answers = try allocator.alloc([]const u8, 0),
                    .resolver = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ self.resolver_ip, self.port }),
                    .method = try allocator.dupe(u8, "custom_udp_resolver"),
                    .elapsed_ns = elapsed,
                    .err = .{
                        .code = if (is_timeout) .connection_timed_out else .network_unreachable,
                        .message = if (is_timeout) "Resolver UDP response timed out" else @errorName(err),
                    },
                };
            };
        }

        const elapsed = @as(u64, @intCast(@max(0, std.time.nanoTimestamp() - start_ns)));

        if (recvd < 12) {
            return DnsResolutionResult{
                .host = try allocator.dupe(u8, host),
                .record_type = record_type,
                .failure_category = .resolver_transport_error,
                .answers = try allocator.alloc([]const u8, 0),
                .resolver = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ self.resolver_ip, self.port }),
                .method = try allocator.dupe(u8, "custom_udp_resolver"),
                .elapsed_ns = elapsed,
                .err = .{ .code = .io_error, .message = "DNS response truncated" },
            };
        }

        const flags = std.mem.readInt(u16, resp_buf[2..4], .big);
        const rcode = flags & 0x000F;

        if (rcode == 3) {
            return DnsResolutionResult{
                .host = try allocator.dupe(u8, host),
                .record_type = record_type,
                .failure_category = .nxdomain,
                .answers = try allocator.alloc([]const u8, 0),
                .resolver = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ self.resolver_ip, self.port }),
                .method = try allocator.dupe(u8, "custom_udp_resolver"),
                .elapsed_ns = elapsed,
                .err = .{ .code = .unknown_host, .message = "NXDOMAIN received from resolver" },
            };
        }

        const ancount = std.mem.readInt(u16, resp_buf[6..8], .big);
        if (ancount == 0) {
            return DnsResolutionResult{
                .host = try allocator.dupe(u8, host),
                .record_type = record_type,
                .failure_category = .no_answer,
                .answers = try allocator.alloc([]const u8, 0),
                .resolver = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ self.resolver_ip, self.port }),
                .method = try allocator.dupe(u8, "custom_udp_resolver"),
                .elapsed_ns = elapsed,
                .err = .{ .code = .unknown_host, .message = "No matching records found in resolver answer" },
            };
        }

        var offset: usize = 12;
        while (offset < recvd) {
            const len = resp_buf[offset];
            if (len == 0) {
                offset += 5;
                break;
            } else if ((len & 0xC0) == 0xC0) {
                offset += 6;
                break;
            } else {
                offset += 1 + len;
            }
        }

        var ans_list = std.ArrayList([]const u8).init(allocator);
        errdefer {
            for (ans_list.items) |ans| allocator.free(ans);
            ans_list.deinit();
        }

        var parsed_answers: usize = 0;
        while (parsed_answers < ancount and offset + 10 <= recvd) : (parsed_answers += 1) {
            if ((resp_buf[offset] & 0xC0) == 0xC0) {
                offset += 2;
            } else {
                while (offset < recvd and resp_buf[offset] != 0) {
                    offset += 1 + resp_buf[offset];
                }
                offset += 1;
            }

            if (offset + 10 > recvd) break;
            const atype = std.mem.readInt(u16, resp_buf[offset..][0..2], .big);
            const rdlen = std.mem.readInt(u16, resp_buf[offset + 8 ..][0..2], .big);
            offset += 10;

            if (atype == 1 and rdlen == 4 and offset + 4 <= recvd) {
                const ip = try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{
                    resp_buf[offset], resp_buf[offset + 1], resp_buf[offset + 2], resp_buf[offset + 3],
                });
                try ans_list.append(ip);
            }
            offset += rdlen;
        }

        std.mem.sort([]const u8, ans_list.items, {}, struct {
            fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.lessThan);

        const cat: DnsFailureCategory = if (ans_list.items.len > 0) .success else .no_answer;

        return DnsResolutionResult{
            .host = try allocator.dupe(u8, host),
            .record_type = record_type,
            .failure_category = cat,
            .answers = try ans_list.toOwnedSlice(),
            .resolver = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ self.resolver_ip, self.port }),
            .method = try allocator.dupe(u8, "custom_udp_resolver"),
            .elapsed_ns = elapsed,
            .err = if (cat == .success) StructuredError.none else .{ .code = .unknown_host, .message = "No matching records found" },
        };
    }

    const udp_vtable: Resolver.VTable = .{
        .resolve = resolve,
    };

    pub fn resolver(self: *CustomUdpResolver) Resolver {
        return .{
            .ptr = self,
            .vtable = &udp_vtable,
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

test "compare resolvers with identical answers" {
    const allocator = testing.allocator;

    var mock1 = MockResolver{
        .mock_category = .success,
        .mock_answers = &.{ "192.0.2.1", "192.0.2.2" },
        .resolver_name = "1.1.1.1:53",
    };
    var mock2 = MockResolver{
        .mock_category = .success,
        .mock_answers = &.{ "192.0.2.2", "192.0.2.1" }, // Order swapped, but sort will match
        .resolver_name = "8.8.8.8:53",
    };

    const resolvers = [_]Resolver{ mock1.resolver(), mock2.resolver() };
    const labels = [_][]const u8{ "Cloudflare (1.1.1.1)", "Google (8.8.8.8)" };

    var comp = try compareResolvers(allocator, "service.example.com", .A, &resolvers, &labels);
    defer comp.deinit(allocator);

    try testing.expect(comp.answers_match);
    try testing.expect(comp.disagreement_analysis == null);
    try testing.expectEqual(@as(usize, 2), comp.entries.len);
    try testing.expectEqualStrings("Cloudflare (1.1.1.1)", comp.entries[0].resolver);
    try testing.expectEqualStrings("Google (8.8.8.8)", comp.entries[1].resolver);
}

test "compare resolvers with split-horizon differing answers" {
    const allocator = testing.allocator;

    var internal_mock = MockResolver{
        .mock_category = .success,
        .mock_answers = &.{"10.0.1.50"}, // RFC 1918 private address
        .resolver_name = "10.0.0.1:53",
    };
    var public_mock = MockResolver{
        .mock_category = .success,
        .mock_answers = &.{"198.51.100.25"}, // Public address
        .resolver_name = "1.1.1.1:53",
    };

    const resolvers = [_]Resolver{ internal_mock.resolver(), public_mock.resolver() };
    const labels = [_][]const u8{ "Internal DNS (10.0.0.1)", "Public DNS (1.1.1.1)" };

    var comp = try compareResolvers(allocator, "app.corp.internal", .A, &resolvers, &labels);
    defer comp.deinit(allocator);

    // Answers differ due to split-horizon
    try testing.expect(!comp.answers_match);
    try testing.expect(comp.disagreement_analysis != null);

    // Verify neutral explanation without poisoning accusations
    const explanation = comp.disagreement_analysis.?;
    try testing.expect(std.mem.indexOf(u8, explanation, "do NOT indicate DNS poisoning or hijacking") != null);
    try testing.expect(std.mem.indexOf(u8, explanation, "Split-horizon") != null);

    // Verify JSON serialization contains disagreement analysis and resolvers
    var json_buf: [2048]u8 = undefined;
    var json_fbs = std.io.fixedBufferStream(&json_buf);
    try comp.toJson(json_fbs.writer());
    const json_str = json_fbs.getWritten();
    try testing.expect(std.mem.indexOf(u8, json_str, "\"answers_match\":false") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "Split-horizon") != null);
}

test "compare resolvers preserves individual failure and timeout" {
    const allocator = testing.allocator;

    var healthy_mock = MockResolver{
        .mock_category = .success,
        .mock_answers = &.{"192.0.2.1"},
        .resolver_name = "8.8.8.8:53",
    };
    var timeout_mock = MockResolver{
        .mock_category = .timeout,
        .resolver_name = "192.0.2.254:53",
    };

    const resolvers = [_]Resolver{ healthy_mock.resolver(), timeout_mock.resolver() };
    const labels = [_][]const u8{ "Healthy (8.8.8.8)", "Unresponsive (192.0.2.254)" };

    var comp = try compareResolvers(allocator, "test.example.com", .A, &resolvers, &labels);
    defer comp.deinit(allocator);

    try testing.expectEqual(@as(usize, 2), comp.entries.len);
    try testing.expectEqual(DnsFailureCategory.success, comp.entries[0].failure_category);
    try testing.expectEqual(DnsFailureCategory.timeout, comp.entries[1].failure_category);
    try testing.expectEqual(ErrorCode.connection_timed_out, comp.entries[1].err.code);
}
