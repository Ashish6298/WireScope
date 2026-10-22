const std = @import("std");
const testing = std.testing;
const builtin = @import("builtin");

const core = @import("../core/root.zig");
const dns = @import("dns.zig");
const types = @import("types.zig");
const engine = @import("engine.zig");

const OutcomeCategory = core.OutcomeCategory;
const StructuredError = core.StructuredError;
const ErrorCode = core.ErrorCode;
const OperationEnvelope = core.OperationEnvelope;
const OperationType = core.OperationType;
const TimingStages = core.TimingStages;
const TcpPayload = core.TcpPayload;
pub const CancellationToken = types.CancellationToken;
const ProbeEngine = engine.ProbeEngine;
const EngineConfig = types.EngineConfig;

const SOL_SOCKET_WIN: i32 = 0xffff;
const SO_ERROR_WIN: i32 = 0x1007;

const WSAECONNREFUSED: i32 = 10061;
const WSAETIMEDOUT: i32 = 10060;
const WSAEHOSTUNREACH: i32 = 10065;
const WSAENETUNREACH: i32 = 10051;
const WSAEACCES: i32 = 10013;
const WSAEWOULDBLOCK: i32 = 10035;

/// Closes an OS socket descriptor deterministically across Windows and POSIX platforms
pub fn closeSocket(sock: std.posix.socket_t) void {
    if (comptime builtin.os.tag == .windows) {
        _ = std.os.windows.ws2_32.closesocket(sock);
    } else {
        std.posix.close(sock);
    }
}

/// Granular TCP connectivity failure classifications (Section 6.4)
pub const TcpFailureCategory = enum {
    success,
    refusal,
    timeout,
    cancelled,
    permission_denied,
    network_unreachable,
    malformed_input,
    operational_failure,

    pub fn toOutcome(self: TcpFailureCategory) OutcomeCategory {
        return switch (self) {
            .success => .success,
            .refusal => .refusal,
            .timeout => .timeout,
            .cancelled => .cancelled,
            .permission_denied => .permission_denied,
            .network_unreachable => .operational_failure,
            .malformed_input => .invalid_input,
            .operational_failure => .operational_failure,
        };
    }

    pub fn toErrorCode(self: TcpFailureCategory) ErrorCode {
        return switch (self) {
            .success => .none,
            .refusal => .connection_refused,
            .timeout => .connection_timed_out,
            .cancelled => .none,
            .permission_denied => .permission_denied,
            .network_unreachable => .network_unreachable,
            .malformed_input => .parse_error,
            .operational_failure => .internal_error,
        };
    }

    pub fn toSlice(self: TcpFailureCategory) []const u8 {
        return @tagName(self);
    }
};

/// Validates port numbers strictly within RFC 793 range [1, 65535]
pub fn validatePort(port: u32) !u16 {
    if (port == 0 or port > 65535) {
        return error.InvalidPortRange;
    }
    return @intCast(port);
}

/// Parsed host and port specification
pub const TargetSpec = struct {
    host: []const u8,
    port: u16,
};

/// Parses target string with syntax validation before opening any sockets
pub fn parseTargetAndPort(raw_target: []const u8, default_port: ?u16) !TargetSpec {
    const trimmed = std.mem.trim(u8, raw_target, " \t\r\n");
    if (trimmed.len == 0) return error.EmptyTarget;

    // Check for IPv6 bracketed format: [::1]:80 or [::1]
    if (std.mem.startsWith(u8, trimmed, "[")) {
        const close_bracket = std.mem.indexOfScalar(u8, trimmed, ']') orelse return error.MalformedIpv6Bracket;
        const host_part = trimmed[1..close_bracket];
        if (host_part.len == 0) return error.EmptyHostname;

        if (trimmed.len > close_bracket + 1) {
            if (trimmed[close_bracket + 1] != ':') return error.InvalidTargetSyntax;
            const port_str = trimmed[close_bracket + 2 ..];
            if (port_str.len == 0) return error.MissingPort;
            const port_num = std.fmt.parseInt(u32, port_str, 10) catch return error.InvalidPortSyntax;
            const valid_port = try validatePort(port_num);
            return TargetSpec{ .host = host_part, .port = valid_port };
        } else {
            const port_val = default_port orelse return error.MissingPort;
            const valid_port = try validatePort(port_val);
            return TargetSpec{ .host = host_part, .port = valid_port };
        }
    }

    // Standard host:port format or bare hostname/IP
    if (std.mem.lastIndexOfScalar(u8, trimmed, ':')) |colon_idx| {
        // Ensure this isn't an unbracketed IPv6 address literal
        const first_colon = std.mem.indexOfScalar(u8, trimmed, ':').?;
        if (first_colon != colon_idx) {
            // Multiple colons without brackets -> unbracketed IPv6 literal
            const port_val = default_port orelse return error.MissingPort;
            const valid_port = try validatePort(port_val);
            return TargetSpec{ .host = trimmed, .port = valid_port };
        }

        const host_part = trimmed[0..colon_idx];
        const port_str = trimmed[colon_idx + 1 ..];

        if (host_part.len == 0) return error.EmptyHostname;
        if (port_str.len == 0) return error.MissingPort;

        const port_num = std.fmt.parseInt(u32, port_str, 10) catch return error.InvalidPortSyntax;
        const valid_port = try validatePort(port_num);
        return TargetSpec{ .host = host_part, .port = valid_port };
    }

    // No colon -> bare hostname or IPv4 address
    const port_val = default_port orelse return error.MissingPort;
    const valid_port = try validatePort(port_val);
    return TargetSpec{ .host = trimmed, .port = valid_port };
}

/// Preserved outcome of an explicit TCP connectivity probe
pub const TcpProbeResult = struct {
    host: []const u8,
    port: u16,
    resolved_ip: ?[]const u8 = null,
    is_open: bool,
    failure_category: TcpFailureCategory,
    elapsed_ns: u64,
    connect_time_ns: u64,
    dns_time_ns: ?u64 = null,
    err: StructuredError = StructuredError.none,
    capability_limitations: ?[]const u8 = null,

    pub fn deinit(self: *TcpProbeResult, allocator: std.mem.Allocator) void {
        allocator.free(self.host);
        if (self.resolved_ip) |ip| allocator.free(ip);
        if (self.capability_limitations) |l| allocator.free(l);
    }

    /// Converts into universal OperationEnvelope satisfying shared result contract
    pub fn toEnvelope(self: *const TcpProbeResult, allocator: std.mem.Allocator, op_id: []const u8, profile_id: ?[]const u8) !OperationEnvelope {
        const now = std.time.milliTimestamp();
        const target_str = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ self.host, self.port });
        errdefer allocator.free(target_str);

        return OperationEnvelope{
            .operation_id = try allocator.dupe(u8, op_id),
            .operation_type = .tcp,
            .target = target_str,
            .profile_id = if (profile_id) |p| try allocator.dupe(u8, p) else null,
            .start_time_ms = now - @as(i64, @intCast(self.elapsed_ns / std.time.ns_per_ms)),
            .end_time_ms = now,
            .monotonic_elapsed_ns = self.elapsed_ns,
            .outcome = self.failure_category.toOutcome(),
            .is_partial = (self.failure_category == .cancelled),
            .timing_stages = .{
                .dns_lookup_ns = self.dns_time_ns,
                .tcp_connect_ns = self.connect_time_ns,
                .total_elapsed_ns = self.elapsed_ns,
            },
            .err = self.err,
            .capability_limitations = if (self.capability_limitations) |l| try allocator.dupe(u8, l) else null,
            .payload = .{
                .tcp = .{
                    .port = self.port,
                    .is_open = self.is_open,
                    .connect_time_ns = self.connect_time_ns,
                    .bytes_sent = 0,
                    .bytes_received = 0,
                },
            },
        };
    }

    pub fn toTerminal(self: *const TcpProbeResult, writer: anytype) !void {
        try writer.print("TCP Connectivity Probe for: {s}:{d}\n", .{ self.host, self.port });
        try writer.writeAll("--------------------------------------------------------------------------------\n");
        const state_str = if (self.is_open) "OPEN (Established)" else switch (self.failure_category) {
            .refusal => "CLOSED (Connection Refused)",
            .timeout => "FILTERED / TIMED OUT",
            .permission_denied => "BLOCKED (Permission Denied)",
            .cancelled => "CANCELLED",
            .network_unreachable => "UNREACHABLE",
            .malformed_input => "INVALID TARGET",
            .operational_failure => "OPERATIONAL FAILURE",
            .success => "OPEN",
        };

        try writer.print("  Target Port   : {d}\n", .{self.port});
        try writer.print("  Port State    : {s}\n", .{state_str});
        try writer.print("  Outcome       : {s} ({s})\n", .{ self.failure_category.toSlice(), self.failure_category.toOutcome().toSlice() });

        if (self.resolved_ip) |ip| {
            try writer.print("  Destination IP: {s}\n", .{ip});
        }
        if (self.dns_time_ns) |dns_ns| {
            try writer.print("  DNS Lookup    : {d:.2} ms\n", .{@as(f64, @floatFromInt(dns_ns)) / 1000000.0});
        }

        try writer.print("  TCP Connect   : {d:.2} ms\n", .{@as(f64, @floatFromInt(self.connect_time_ns)) / 1000000.0});
        try writer.print("  Total Elapsed : {d:.2} ms\n", .{@as(f64, @floatFromInt(self.elapsed_ns)) / 1000000.0});

        if (self.err.isError()) {
            var err_buf: [256]u8 = undefined;
            const err_str = self.err.formatSafe(&err_buf) catch "Error format failure";
            try writer.print("  Error Details : {s}\n", .{err_str});
        }

        if (self.capability_limitations) |l| {
            try writer.print("  Limitations   : {s}\n", .{l});
        }

        // Section 6.5: Explicitly clarify that TCP connection time is not ICMP ping latency
        try writer.writeAll("\n  Timing Notice: TCP connect time reflects 3-way SYN/SYN-ACK handshake duration,\n");
        try writer.writeAll("                 not ICMP echo ping latency.\n\n");
    }

    pub fn toJson(self: *const TcpProbeResult, writer: anytype) !void {
        try writer.print("{{\"host\":\"{s}\",\"port\":{d},\"resolved_ip\":", .{ self.host, self.port });
        if (self.resolved_ip) |ip| {
            try writer.print("\"{s}\"", .{ip});
        } else {
            try writer.writeAll("null");
        }
        try writer.print(",\"is_open\":{s},\"outcome\":\"{s}\",\"connect_time_ns\":{d},\"dns_time_ns\":", .{
            if (self.is_open) "true" else "false",
            self.failure_category.toOutcome().toSlice(),
            self.connect_time_ns,
        });
        if (self.dns_time_ns) |dns_ns| {
            try writer.print("{d}", .{dns_ns});
        } else {
            try writer.writeAll("null");
        }
        try writer.print(",\"total_elapsed_ns\":{d},\"error\":", .{self.elapsed_ns});
        try self.err.toJson(writer);
        try writer.writeAll("}\n");
    }
};

/// Abstract TCP Connector interface allowing dependency injection for hermetic unit testing
pub const TcpConnector = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        connect: *const fn (
            ctx: *anyopaque,
            allocator: std.mem.Allocator,
            host: []const u8,
            port: u16,
            timeout_ms: u32,
            cancel: *const CancellationToken,
        ) anyerror!TcpProbeResult,
    };

    pub fn connect(
        self: TcpConnector,
        allocator: std.mem.Allocator,
        host: []const u8,
        port: u16,
        timeout_ms: u32,
        cancel: *const CancellationToken,
    ) anyerror!TcpProbeResult {
        return self.vtable.connect(self.ptr, allocator, host, port, timeout_ms, cancel);
    }
};

/// Real OS TCP socket connector implementing non-blocking connect with timeout and cancellation
pub const RealTcpConnector = struct {
    fn pollSocketForConnect(sock: std.posix.socket_t, timeout_ms: u32, cancel: *const CancellationToken) !enum { ready, timed_out, cancelled } {
        const start_ms = std.time.milliTimestamp();
        const slice_ms: i32 = 25; // 25ms polling slices allow prompt cancellation checks

        while (true) {
            if (cancel.isCancelled()) {
                return .cancelled;
            }

            const elapsed_ms = std.time.milliTimestamp() - start_ms;
            if (elapsed_ms >= timeout_ms) {
                return .timed_out;
            }

            const remaining = @as(i32, @intCast(@min(slice_ms, @as(i64, timeout_ms) - elapsed_ms)));
            const wait_ms = @max(1, remaining);

            if (comptime builtin.os.tag == .windows) {
                var write_fds = std.os.windows.ws2_32.fd_set{
                    .fd_count = 1,
                    .fd_array = undefined,
                };
                write_fds.fd_array[0] = sock;

                var except_fds = std.os.windows.ws2_32.fd_set{
                    .fd_count = 1,
                    .fd_array = undefined,
                };
                except_fds.fd_array[0] = sock;

                const tv = std.os.windows.ws2_32.timeval{
                    .tv_sec = @intCast(@divTrunc(wait_ms, 1000)),
                    .tv_usec = @intCast(@mod(wait_ms, 1000) * 1000),
                };

                const rc = std.os.windows.ws2_32.select(0, null, &write_fds, &except_fds, &tv);
                if (rc < 0) {
                    const wsa_err = std.os.windows.ws2_32.WSAGetLastError();
                    std.debug.print("\nselect returned {d}, WSAGetLastError: {}\n", .{ rc, wsa_err });
                }
                if (rc > 0) {
                    return .ready;
                }
            } else {
                var pfd = [1]std.posix.pollfd{
                    .{
                        .fd = sock,
                        .events = std.posix.POLL.OUT,
                        .revents = 0,
                    },
                };
                const rc = try std.posix.poll(&pfd, wait_ms);
                if (rc > 0) {
                    return .ready;
                }
            }
        }
    }

    fn checkSocketError(sock: std.posix.socket_t) i32 {
        var so_error: i32 = 0;
        if (comptime builtin.os.tag == .windows) {
            var opt_len: i32 = @sizeOf(i32);
            _ = std.os.windows.ws2_32.getsockopt(
                sock,
                SOL_SOCKET_WIN,
                SO_ERROR_WIN,
                @ptrCast(&so_error),
                &opt_len,
            );
        } else {
            var opt_len: std.posix.socklen_t = @sizeOf(i32);
            _ = std.posix.system.getsockopt(
                sock,
                std.posix.SOL.SOCKET,
                std.posix.SO.ERROR,
                @ptrCast(&so_error),
                &opt_len,
            );
        }
        return so_error;
    }

    pub fn connect(
        _: *anyopaque,
        allocator: std.mem.Allocator,
        host: []const u8,
        port: u16,
        timeout_ms: u32,
        cancel: *const CancellationToken,
    ) anyerror!TcpProbeResult {
        // 1. Cooperative cancellation check prior to starting
        if (cancel.isCancelled()) {
            return TcpProbeResult{
                .host = try allocator.dupe(u8, host),
                .port = port,
                .resolved_ip = null,
                .is_open = false,
                .failure_category = .cancelled,
                .elapsed_ns = 0,
                .connect_time_ns = 0,
                .dns_time_ns = null,
                .err = .{ .code = .none, .message = "Operation cancelled before execution" },
            };
        }

        // 2. Syntax validation
        _ = validatePort(port) catch {
            return TcpProbeResult{
                .host = try allocator.dupe(u8, host),
                .port = port,
                .resolved_ip = null,
                .is_open = false,
                .failure_category = .malformed_input,
                .elapsed_ns = 0,
                .connect_time_ns = 0,
                .dns_time_ns = null,
                .err = .{ .code = .parse_error, .message = "Invalid port number. Must be between 1 and 65535." },
            };
        };

        dns.validateHostname(host) catch |err| {
            return TcpProbeResult{
                .host = try allocator.dupe(u8, host),
                .port = port,
                .resolved_ip = null,
                .is_open = false,
                .failure_category = .malformed_input,
                .elapsed_ns = 0,
                .connect_time_ns = 0,
                .dns_time_ns = null,
                .err = .{
                    .code = .parse_error,
                    .message = switch (err) {
                        error.EmptyHostname => "Hostname cannot be empty",
                        error.HostnameTooLong => "Hostname exceeds 253 characters limit",
                        error.EmptyLabel => "Hostname contains empty label (adjacent dots)",
                        error.LabelTooLong => "Hostname label exceeds 63 characters",
                        error.InvalidHyphenPlacement => "Label cannot begin or end with a hyphen",
                        error.InvalidCharacter => "Hostname contains invalid characters",
                    },
                },
            };
        };

        const total_start_ns = std.time.nanoTimestamp();
        var dns_duration_ns: ?u64 = null;
        var target_addr: std.net.Address = undefined;
        var resolved_ip_str: ?[]const u8 = null;
        errdefer if (resolved_ip_str) |ip| allocator.free(ip);

        // 3. Resolve address or parse IP literal
        if (std.net.Address.parseIp4(host, port)) |addr| {
            target_addr = addr;
            resolved_ip_str = try allocator.dupe(u8, host);
        } else |_| {
            if (std.net.Address.parseIp6(host, port)) |addr| {
                target_addr = addr;
                resolved_ip_str = try allocator.dupe(u8, host);
            } else |_| {
                // Hostname resolution stage
                const dns_start_ns = std.time.nanoTimestamp();
                var addr_list = std.net.getAddressList(allocator, host, port) catch |err| {
                    const elapsed = @as(u64, @intCast(@max(0, std.time.nanoTimestamp() - total_start_ns)));
                    return TcpProbeResult{
                        .host = try allocator.dupe(u8, host),
                        .port = port,
                        .resolved_ip = null,
                        .is_open = false,
                        .failure_category = switch (err) {
                            error.UnknownHostName => .network_unreachable,
                            error.TemporaryNameServerFailure => .timeout,
                            else => .operational_failure,
                        },
                        .elapsed_ns = elapsed,
                        .connect_time_ns = 0,
                        .dns_time_ns = elapsed,
                        .err = .{
                            .code = switch (err) {
                                error.UnknownHostName => .unknown_host,
                                error.TemporaryNameServerFailure => .connection_timed_out,
                                else => .internal_error,
                            },
                            .message = switch (err) {
                                error.UnknownHostName => "Name or service not known (DNS resolution failed)",
                                error.TemporaryNameServerFailure => "DNS resolver timed out during resolution",
                                else => "DNS resolution operational failure",
                            },
                        },
                    };
                };
                defer addr_list.deinit();

                if (addr_list.addrs.len == 0) {
                    const elapsed = @as(u64, @intCast(@max(0, std.time.nanoTimestamp() - total_start_ns)));
                    return TcpProbeResult{
                        .host = try allocator.dupe(u8, host),
                        .port = port,
                        .resolved_ip = null,
                        .is_open = false,
                        .failure_category = .network_unreachable,
                        .elapsed_ns = elapsed,
                        .connect_time_ns = 0,
                        .dns_time_ns = elapsed,
                        .err = .{ .code = .unknown_host, .message = "No IP addresses returned for host" },
                    };
                }

                target_addr = addr_list.addrs[0];
                dns_duration_ns = @as(u64, @intCast(@max(0, std.time.nanoTimestamp() - dns_start_ns)));

                // Format resolved IP string for diagnostics
                switch (target_addr.any.family) {
                    std.posix.AF.INET => {
                        const bytes: [4]u8 = @bitCast(target_addr.in.sa.addr);
                        resolved_ip_str = try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{
                            bytes[0], bytes[1], bytes[2], bytes[3],
                        });
                    },
                    std.posix.AF.INET6 => {
                        resolved_ip_str = try std.fmt.allocPrint(allocator, "{any}", .{target_addr.in6.sa.addr});
                    },
                    else => {
                        resolved_ip_str = try allocator.dupe(u8, "unknown_family");
                    },
                }
            }
        }

        // 4. Cancellation check after DNS before socket creation
        if (cancel.isCancelled()) {
            const elapsed = @as(u64, @intCast(@max(0, std.time.nanoTimestamp() - total_start_ns)));
            return TcpProbeResult{
                .host = try allocator.dupe(u8, host),
                .port = port,
                .resolved_ip = resolved_ip_str,
                .is_open = false,
                .failure_category = .cancelled,
                .elapsed_ns = elapsed,
                .connect_time_ns = 0,
                .dns_time_ns = dns_duration_ns,
                .err = .{ .code = .none, .message = "Probe cancelled prior to socket connection" },
            };
        }

        // 5. Create TCP socket
        const sock = std.posix.socket(target_addr.any.family, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP) catch |err| {
            const elapsed = @as(u64, @intCast(@max(0, std.time.nanoTimestamp() - total_start_ns)));
            return TcpProbeResult{
                .host = try allocator.dupe(u8, host),
                .port = port,
                .resolved_ip = resolved_ip_str,
                .is_open = false,
                .failure_category = switch (err) {
                    error.PermissionDenied => .permission_denied,
                    else => .operational_failure,
                },
                .elapsed_ns = elapsed,
                .connect_time_ns = 0,
                .dns_time_ns = dns_duration_ns,
                .err = .{ .code = .internal_error, .message = "Failed to allocate local socket" },
            };
        };
        // Deterministic socket cleanup on all return paths
        defer closeSocket(sock);

        // 6. Set socket to non-blocking mode
        if (comptime builtin.os.tag == .windows) {
            var mode: c_ulong = 1;
            if (std.os.windows.ws2_32.ioctlsocket(sock, std.os.windows.ws2_32.FIONBIO, &mode) != 0) {
                const elapsed = @as(u64, @intCast(@max(0, std.time.nanoTimestamp() - total_start_ns)));
                return TcpProbeResult{
                    .host = try allocator.dupe(u8, host),
                    .port = port,
                    .resolved_ip = resolved_ip_str,
                    .is_open = false,
                    .failure_category = .operational_failure,
                    .elapsed_ns = elapsed,
                    .connect_time_ns = 0,
                    .dns_time_ns = dns_duration_ns,
                    .err = .{ .code = .internal_error, .message = "Failed to configure socket non-blocking mode" },
                };
            }
        } else {
            var flags = std.posix.fcntl(sock, std.posix.F.GETFL, 0) catch {
                const elapsed = @as(u64, @intCast(@max(0, std.time.nanoTimestamp() - total_start_ns)));
                return TcpProbeResult{
                    .host = try allocator.dupe(u8, host),
                    .port = port,
                    .resolved_ip = resolved_ip_str,
                    .is_open = false,
                    .failure_category = .operational_failure,
                    .elapsed_ns = elapsed,
                    .connect_time_ns = 0,
                    .dns_time_ns = dns_duration_ns,
                    .err = .{ .code = .internal_error, .message = "Failed to get socket flags" },
                };
            };
            flags |= 1 << @bitOffsetOf(std.posix.O, "NONBLOCK");
            _ = std.posix.fcntl(sock, std.posix.F.SETFL, flags) catch {
                const elapsed = @as(u64, @intCast(@max(0, std.time.nanoTimestamp() - total_start_ns)));
                return TcpProbeResult{
                    .host = try allocator.dupe(u8, host),
                    .port = port,
                    .resolved_ip = resolved_ip_str,
                    .is_open = false,
                    .failure_category = .operational_failure,
                    .elapsed_ns = elapsed,
                    .connect_time_ns = 0,
                    .dns_time_ns = dns_duration_ns,
                    .err = .{ .code = .internal_error, .message = "Failed to set socket flags" },
                };
            };
        }

        // 7. Initiate connection and measure connect duration
        const connect_start_ns = std.time.nanoTimestamp();
        const conn_res = std.posix.connect(sock, &target_addr.any, target_addr.getOsSockLen());

        var is_open = false;
        var failure_cat: TcpFailureCategory = .success;
        var err_detail = StructuredError.none;

        if (conn_res) |_| {
            // Immediate connection established (common on loopback)
            is_open = true;
            failure_cat = .success;
        } else |err| switch (err) {
            error.ConnectionRefused => {
                is_open = false;
                failure_cat = .refusal;
                err_detail = .{ .code = .connection_refused, .message = "Connection refused by target host" };
            },
            error.NetworkUnreachable => {
                is_open = false;
                failure_cat = .network_unreachable;
                err_detail = .{ .code = .network_unreachable, .message = "Network or host unreachable" };
            },
            error.PermissionDenied => {
                is_open = false;
                failure_cat = .permission_denied;
                err_detail = .{ .code = .permission_denied, .message = "Connection blocked by local firewall or permissions" };
            },
            error.WouldBlock => {
                // Connection in progress; wait with polling
                const poll_status = pollSocketForConnect(sock, timeout_ms, cancel) catch {
                    const connect_elapsed = @as(u64, @intCast(@max(0, std.time.nanoTimestamp() - connect_start_ns)));
                    const total_elapsed = @as(u64, @intCast(@max(0, std.time.nanoTimestamp() - total_start_ns)));
                    return TcpProbeResult{
                        .host = try allocator.dupe(u8, host),
                        .port = port,
                        .resolved_ip = resolved_ip_str,
                        .is_open = false,
                        .failure_category = .operational_failure,
                        .elapsed_ns = total_elapsed,
                        .connect_time_ns = connect_elapsed,
                        .dns_time_ns = dns_duration_ns,
                        .err = .{ .code = .internal_error, .message = "Socket polling failed" },
                    };
                };

                switch (poll_status) {
                    .cancelled => {
                        is_open = false;
                        failure_cat = .cancelled;
                        err_detail = .{ .code = .none, .message = "Operation cancelled during TCP handshake" };
                    },
                    .timed_out => {
                        is_open = false;
                        failure_cat = .timeout;
                        err_detail = .{ .code = .connection_timed_out, .message = "TCP connection timed out" };
                    },
                    .ready => {
                        const so_err = checkSocketError(sock);
                        if (so_err == 0) {
                            is_open = true;
                            failure_cat = .success;
                        } else {
                            is_open = false;
                            if (comptime builtin.os.tag == .windows) {
                                failure_cat = switch (so_err) {
                                    WSAECONNREFUSED => .refusal,
                                    WSAETIMEDOUT => .timeout,
                                    WSAEHOSTUNREACH, WSAENETUNREACH => .network_unreachable,
                                    WSAEACCES => .permission_denied,
                                    else => .operational_failure,
                                };
                            } else {
                                if (so_err == @intFromEnum(std.posix.E.CONNREFUSED)) {
                                    failure_cat = .refusal;
                                } else if (so_err == @intFromEnum(std.posix.E.TIMEDOUT)) {
                                    failure_cat = .timeout;
                                } else if (so_err == @intFromEnum(std.posix.E.HOSTUNREACH) or so_err == @intFromEnum(std.posix.E.NETUNREACH)) {
                                    failure_cat = .network_unreachable;
                                } else if (so_err == @intFromEnum(std.posix.E.ACCES) or so_err == @intFromEnum(std.posix.E.PERM)) {
                                    failure_cat = .permission_denied;
                                } else {
                                    failure_cat = .operational_failure;
                                }
                            }
                            err_detail = .{
                                .code = failure_cat.toErrorCode(),
                                .message = switch (failure_cat) {
                                    .refusal => "Connection refused by destination host",
                                    .timeout => "TCP handshake timed out",
                                    .network_unreachable => "Destination host or network unreachable",
                                    .permission_denied => "Permission denied by firewall",
                                    else => "TCP connection error reported by OS",
                                },
                            };
                        }
                    },
                }
            },
            else => {
                is_open = false;
                failure_cat = .operational_failure;
                err_detail = .{ .code = .internal_error, .message = @errorName(err) };
            },
        }

        const connect_elapsed = @as(u64, @intCast(@max(0, std.time.nanoTimestamp() - connect_start_ns)));
        const total_elapsed = @as(u64, @intCast(@max(0, std.time.nanoTimestamp() - total_start_ns)));

        return TcpProbeResult{
            .host = try allocator.dupe(u8, host),
            .port = port,
            .resolved_ip = resolved_ip_str,
            .is_open = is_open,
            .failure_category = failure_cat,
            .elapsed_ns = total_elapsed,
            .connect_time_ns = connect_elapsed,
            .dns_time_ns = dns_duration_ns,
            .err = err_detail,
        };
    }

    const real_vtable: TcpConnector.VTable = .{
        .connect = connect,
    };

    pub fn connector() TcpConnector {
        return .{
            .ptr = undefined,
            .vtable = &real_vtable,
        };
    }
};

/// Deterministic mock TCP connector for hermetic CI testing without network dependencies
pub const MockTcpConnector = struct {
    mock_outcome: TcpFailureCategory = .success,
    simulated_latency_ns: u64 = 1500000,
    resolved_ip: []const u8 = "127.0.0.1",

    fn connect(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        host: []const u8,
        port: u16,
        _: u32,
        cancel: *const CancellationToken,
    ) anyerror!TcpProbeResult {
        const self: *MockTcpConnector = @ptrCast(@alignCast(ctx));

        if (cancel.isCancelled()) {
            return TcpProbeResult{
                .host = try allocator.dupe(u8, host),
                .port = port,
                .resolved_ip = try allocator.dupe(u8, self.resolved_ip),
                .is_open = false,
                .failure_category = .cancelled,
                .elapsed_ns = 1000,
                .connect_time_ns = 1000,
                .dns_time_ns = null,
                .err = .{ .code = .none, .message = "Operation cancelled" },
            };
        }

        const is_open = (self.mock_outcome == .success);

        return TcpProbeResult{
            .host = try allocator.dupe(u8, host),
            .port = port,
            .resolved_ip = try allocator.dupe(u8, self.resolved_ip),
            .is_open = is_open,
            .failure_category = self.mock_outcome,
            .elapsed_ns = self.simulated_latency_ns,
            .connect_time_ns = self.simulated_latency_ns,
            .dns_time_ns = null,
            .err = if (is_open)
                StructuredError.none
            else
                .{
                    .code = self.mock_outcome.toErrorCode(),
                    .message = switch (self.mock_outcome) {
                        .refusal => "Mock connection refused",
                        .timeout => "Mock connection timed out",
                        .permission_denied => "Mock permission denied",
                        .cancelled => "Mock cancelled",
                        .network_unreachable => "Mock host unreachable",
                        .malformed_input => "Mock malformed input",
                        .operational_failure => "Mock operational failure",
                        .success => "None",
                    },
                },
        };
    }

    const mock_vtable: TcpConnector.VTable = .{
        .connect = connect,
    };

    pub fn connector(self: *MockTcpConnector) TcpConnector {
        return .{
            .ptr = self,
            .vtable = &mock_vtable,
        };
    }
};

/// Context structure for scheduling TCP probes through the shared ProbeEngine
pub const TcpEngineContext = struct {
    allocator: std.mem.Allocator,
    connector: TcpConnector,
    host: []const u8,
    port: u16,
    timeout_ms: u32,
    result: ?TcpProbeResult = null,
};

/// Executable probe task function compatible with ProbeEngine TaskFn signature
pub fn tcpTaskRunFn(ctx_ptr: ?*anyopaque, cancel: *const CancellationToken) anyerror!OutcomeCategory {
    const context: *TcpEngineContext = @ptrCast(@alignCast(ctx_ptr orelse return error.NullContext));
    var res = try context.connector.connect(
        context.allocator,
        context.host,
        context.port,
        context.timeout_ms,
        cancel,
    );
    const outcome = res.failure_category.toOutcome();
    context.result = res;
    return outcome;
}

/// Executes a TCP probe through the shared ProbeEngine, respecting concurrency limits and deadlines
pub fn executeTcpProbeWithEngine(
    allocator: std.mem.Allocator,
    probe_engine: *ProbeEngine,
    connector: TcpConnector,
    host: []const u8,
    port: u16,
    timeout_ms: u32,
) !TcpProbeResult {
    var ctx = TcpEngineContext{
        .allocator = allocator,
        .connector = connector,
        .host = host,
        .port = port,
        .timeout_ms = timeout_ms,
    };

    const task_desc = types.TaskDescriptor{
        .id = 1,
        .name = "tcp_probe",
        .timeout_ms = timeout_ms,
        .is_retryable = false,
        .max_retries = 0,
        .context = &ctx,
        .run_fn = tcpTaskRunFn,
    };

    try probe_engine.enqueue(task_desc);
    probe_engine.wait();

    if (ctx.result) |res| {
        return res;
    }

    return error.TaskDidNotProduceResult;
}

// ============================================================================
// UNIT & INTEGRATION TESTS
// ============================================================================

test "target and port parsing with valid inputs" {
    // 1. Host with explicit port
    const t1 = try parseTargetAndPort("example.com:80", null);
    try testing.expectEqualStrings("example.com", t1.host);
    try testing.expectEqual(@as(u16, 80), t1.port);

    // 2. IPv4 with explicit port
    const t2 = try parseTargetAndPort("192.168.1.1:8080", null);
    try testing.expectEqualStrings("192.168.1.1", t2.host);
    try testing.expectEqual(@as(u16, 8080), t2.port);

    // 3. Bracketed IPv6 with explicit port
    const t3 = try parseTargetAndPort("[::1]:443", null);
    try testing.expectEqualStrings("::1", t3.host);
    try testing.expectEqual(@as(u16, 443), t3.port);

    // 4. Bare host with default port
    const t4 = try parseTargetAndPort("localhost", 80);
    try testing.expectEqualStrings("localhost", t4.host);
    try testing.expectEqual(@as(u16, 80), t4.port);

    // 5. Bare IPv4 with default port
    const t5 = try parseTargetAndPort("127.0.0.1", 3000);
    try testing.expectEqualStrings("127.0.0.1", t5.host);
    try testing.expectEqual(@as(u16, 3000), t5.port);

    // 6. Bracketed IPv6 with default port
    const t6 = try parseTargetAndPort("[fe80::1]", 22);
    try testing.expectEqualStrings("fe80::1", t6.host);
    try testing.expectEqual(@as(u16, 22), t6.port);
}

test "target and port parsing rejects invalid inputs" {
    // Empty target
    try testing.expectError(error.EmptyTarget, parseTargetAndPort("", 80));
    try testing.expectError(error.EmptyTarget, parseTargetAndPort("   ", 80));

    // Missing port when no default provided
    try testing.expectError(error.MissingPort, parseTargetAndPort("localhost", null));

    // Port out of range
    try testing.expectError(error.InvalidPortRange, parseTargetAndPort("localhost:0", null));
    try testing.expectError(error.InvalidPortRange, parseTargetAndPort("localhost:65536", null));
    try testing.expectError(error.InvalidPortRange, parseTargetAndPort("localhost:99999", null));

    // Non-numeric port
    try testing.expectError(error.InvalidPortSyntax, parseTargetAndPort("localhost:abc", null));
    try testing.expectError(error.InvalidPortSyntax, parseTargetAndPort("localhost:-1", null));

    // Malformed bracketed IPv6
    try testing.expectError(error.MalformedIpv6Bracket, parseTargetAndPort("[::1", 80));
}

test "mock tcp connector simulates open and refusal" {
    var mock_open = MockTcpConnector{ .mock_outcome = .success };
    const token = CancellationToken.init();

    var res_open = try mock_open.connector().connect(testing.allocator, "127.0.0.1", 80, 1000, &token);
    defer res_open.deinit(testing.allocator);
    try testing.expect(res_open.is_open);
    try testing.expectEqual(TcpFailureCategory.success, res_open.failure_category);
    try testing.expectEqual(OutcomeCategory.success, res_open.failure_category.toOutcome());

    var mock_refused = MockTcpConnector{ .mock_outcome = .refusal };
    var res_refused = try mock_refused.connector().connect(testing.allocator, "127.0.0.1", 81, 1000, &token);
    defer res_refused.deinit(testing.allocator);
    try testing.expect(!res_refused.is_open);
    try testing.expectEqual(TcpFailureCategory.refusal, res_refused.failure_category);
    try testing.expectEqual(OutcomeCategory.refusal, res_refused.failure_category.toOutcome());
}

test "mock tcp connector simulates timeout, cancellation, and permission denied" {
    const token = CancellationToken.init();

    // Timeout
    var mock_timeout = MockTcpConnector{ .mock_outcome = .timeout };
    var res_timeout = try mock_timeout.connector().connect(testing.allocator, "192.0.2.1", 80, 100, &token);
    defer res_timeout.deinit(testing.allocator);
    try testing.expect(!res_timeout.is_open);
    try testing.expectEqual(TcpFailureCategory.timeout, res_timeout.failure_category);
    try testing.expectEqual(OutcomeCategory.timeout, res_timeout.failure_category.toOutcome());

    // Cancellation
    var cancel_token = CancellationToken.init();
    cancel_token.cancel();
    var res_cancelled = try mock_timeout.connector().connect(testing.allocator, "127.0.0.1", 80, 1000, &cancel_token);
    defer res_cancelled.deinit(testing.allocator);
    try testing.expect(!res_cancelled.is_open);
    try testing.expectEqual(TcpFailureCategory.cancelled, res_cancelled.failure_category);
    try testing.expectEqual(OutcomeCategory.cancelled, res_cancelled.failure_category.toOutcome());

    // Permission denied
    var mock_perm = MockTcpConnector{ .mock_outcome = .permission_denied };
    var res_perm = try mock_perm.connector().connect(testing.allocator, "127.0.0.1", 80, 1000, &token);
    defer res_perm.deinit(testing.allocator);
    try testing.expect(!res_perm.is_open);
    try testing.expectEqual(TcpFailureCategory.permission_denied, res_perm.failure_category);
    try testing.expectEqual(OutcomeCategory.permission_denied, res_perm.failure_category.toOutcome());
}

test "tcp probe envelope conversion and json serialization" {
    var mock = MockTcpConnector{ .mock_outcome = .success, .simulated_latency_ns = 2500000 };
    const token = CancellationToken.init();

    var res = try mock.connector().connect(testing.allocator, "localhost", 443, 1000, &token);
    defer res.deinit(testing.allocator);

    var envelope = try res.toEnvelope(testing.allocator, "op_tcp_001", "prof_audit");
    defer envelope.deinit(testing.allocator);

    try testing.expectEqualStrings("op_tcp_001", envelope.operation_id);
    try testing.expectEqual(OperationType.tcp, envelope.operation_type);
    try testing.expectEqualStrings("localhost:443", envelope.target);
    try testing.expectEqualStrings("prof_audit", envelope.profile_id.?);
    try testing.expectEqual(OutcomeCategory.success, envelope.outcome);

    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try envelope.toJson(fbs.writer());

    const json_str = fbs.getWritten();
    try testing.expect(std.mem.indexOf(u8, json_str, "\"operation_type\":\"tcp\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"port\":443") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"is_open\":true") != null);
}

test "execute tcp probe through shared probe engine" {
    const config = EngineConfig{
        .max_concurrency = 4,
        .max_queue_size = 50,
        .default_timeout_ms = 2000,
    };
    var pe = try ProbeEngine.init(testing.allocator, config);
    defer pe.deinit();

    var mock = MockTcpConnector{ .mock_outcome = .success, .simulated_latency_ns = 500000 };
    var res = try executeTcpProbeWithEngine(
        testing.allocator,
        pe,
        mock.connector(),
        "127.0.0.1",
        8080,
        1000,
    );
    defer res.deinit(testing.allocator);

    try testing.expect(res.is_open);
    try testing.expectEqual(TcpFailureCategory.success, res.failure_category);
    try testing.expectEqual(@as(usize, 1), pe.getMetrics().completed);
}

test "real socket fixture: open local listener" {
    // 1. Setup local listening fixture on ephemeral port
    const bind_addr = try std.net.Address.parseIp4("127.0.0.1", 0);
    const listen_sock = try std.posix.socket(bind_addr.any.family, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
    defer closeSocket(listen_sock);

    try std.posix.bind(listen_sock, &bind_addr.any, bind_addr.getOsSockLen());
    try std.posix.listen(listen_sock, 5);

    var bound_addr: std.posix.sockaddr.in = undefined;
    if (comptime builtin.os.tag == .windows) {
        var win_len: i32 = @sizeOf(std.posix.sockaddr.in);
        _ = std.os.windows.ws2_32.getsockname(listen_sock, @ptrCast(&bound_addr), &win_len);
    } else {
        var bound_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in);
        try std.posix.getsockname(listen_sock, @ptrCast(&bound_addr), &bound_len);
    }

    const assigned_port = std.mem.bigToNative(u16, bound_addr.port);

    // 2. Connect with RealTcpConnector
    const cancel = CancellationToken.init();
    var res = try RealTcpConnector.connector().connect(
        testing.allocator,
        "127.0.0.1",
        assigned_port,
        2000,
        &cancel,
    );
    defer res.deinit(testing.allocator);

    try testing.expect(res.is_open);
    try testing.expectEqual(TcpFailureCategory.success, res.failure_category);
    try testing.expectEqual(OutcomeCategory.success, res.failure_category.toOutcome());
    try testing.expect(res.elapsed_ns > 0);
}

test "real socket fixture: refused closed local port" {
    // 1. Bind to ephemeral port and close socket immediately to guarantee port is closed
    const bind_addr = try std.net.Address.parseIp4("127.0.0.1", 0);
    const temp_sock = try std.posix.socket(bind_addr.any.family, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
    try std.posix.bind(temp_sock, &bind_addr.any, bind_addr.getOsSockLen());

    var bound_addr: std.posix.sockaddr.in = undefined;
    if (comptime builtin.os.tag == .windows) {
        var win_len: i32 = @sizeOf(std.posix.sockaddr.in);
        _ = std.os.windows.ws2_32.getsockname(temp_sock, @ptrCast(&bound_addr), &win_len);
    } else {
        var bound_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in);
        try std.posix.getsockname(temp_sock, @ptrCast(&bound_addr), &bound_len);
    }
    const closed_port = std.mem.bigToNative(u16, bound_addr.port);
    closeSocket(temp_sock); // Port is now definitively closed

    // 2. Connect to closed port -> should receive refusal
    const cancel = CancellationToken.init();
    var res = try RealTcpConnector.connector().connect(
        testing.allocator,
        "127.0.0.1",
        closed_port,
        3500,
        &cancel,
    );
    defer res.deinit(testing.allocator);
    try testing.expect(!res.is_open);
    try testing.expectEqual(TcpFailureCategory.refusal, res.failure_category);
    try testing.expectEqual(OutcomeCategory.refusal, res.failure_category.toOutcome());
}

test "real socket connector handles malformed host syntax" {
    const cancel = CancellationToken.init();
    var res = try RealTcpConnector.connector().connect(
        testing.allocator,
        "illegal..host..name",
        80,
        1000,
        &cancel,
    );
    defer res.deinit(testing.allocator);
    try testing.expect(!res.is_open);
    try testing.expectEqual(TcpFailureCategory.malformed_input, res.failure_category);
    try testing.expectEqual(OutcomeCategory.invalid_input, res.failure_category.toOutcome());
}
