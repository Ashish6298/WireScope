const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

pub const ServiceKind = enum {
    raw_tcp,
    http_mock_vulnerable,
    http_mock_hardened,
};

pub const LabServiceError = error{
    NonLoopbackBindForbidden,
    SocketCreationFailed,
    BindFailed,
    ListenFailed,
    PortResolutionFailed,
    SocketSendFailed,
    SocketRecvFailed,
};

/// Cross-platform socket close helper
pub fn closeSocket(sock: std.posix.socket_t) void {
    if (comptime builtin.os.tag == .windows) {
        _ = std.os.windows.ws2_32.closesocket(sock);
    } else {
        std.posix.close(sock);
    }
}

/// Cross-platform socket send helper avoiding libc dependency on Windows
pub fn sendBytes(sock: std.posix.socket_t, bytes: []const u8) !usize {
    if (comptime builtin.os.tag == .windows) {
        const rc = std.os.windows.ws2_32.send(sock, bytes.ptr, @intCast(bytes.len), 0);
        if (rc == std.os.windows.ws2_32.SOCKET_ERROR) return error.SocketSendFailed;
        return @intCast(rc);
    } else {
        return std.posix.send(sock, bytes, 0);
    }
}

/// Cross-platform socket recv helper avoiding libc dependency on Windows
pub fn recvBytes(sock: std.posix.socket_t, buf: []u8) !usize {
    if (comptime builtin.os.tag == .windows) {
        const rc = std.os.windows.ws2_32.recv(sock, buf.ptr, @intCast(buf.len), 0);
        if (rc == std.os.windows.ws2_32.SOCKET_ERROR) return error.SocketRecvFailed;
        return @intCast(rc);
    } else {
        return std.posix.recv(sock, buf, 0);
    }
}

pub const LabLoopbackService = struct {
    allocator: std.mem.Allocator,
    sock: std.posix.socket_t,
    port: u16,
    bind_ip: []const u8,
    service_kind: ServiceKind,
    should_stop: std.atomic.Value(bool),
    thread: ?std.Thread,

    pub fn start(
        allocator: std.mem.Allocator,
        bind_ip: []const u8,
        requested_port: u16,
        kind: ServiceKind,
    ) !*LabLoopbackService {
        // Enforce loopback binding isolation
        if (!std.mem.eql(u8, bind_ip, "127.0.0.1") and !std.mem.eql(u8, bind_ip, "::1")) {
            return LabServiceError.NonLoopbackBindForbidden;
        }

        const bind_addr = std.net.Address.parseIp4(bind_ip, requested_port) catch {
            return LabServiceError.BindFailed;
        };

        const sock = std.posix.socket(
            bind_addr.any.family,
            std.posix.SOCK.STREAM,
            std.posix.IPPROTO.TCP,
        ) catch return LabServiceError.SocketCreationFailed;
        errdefer closeSocket(sock);

        std.posix.bind(sock, &bind_addr.any, bind_addr.getOsSockLen()) catch {
            return LabServiceError.BindFailed;
        };

        std.posix.listen(sock, 16) catch {
            return LabServiceError.ListenFailed;
        };

        // Determine actual bound port (crucial for ephemeral port 0)
        var actual_port: u16 = requested_port;
        var bound_addr: std.posix.sockaddr.in = undefined;
        if (comptime builtin.os.tag == .windows) {
            var win_len: i32 = @sizeOf(std.posix.sockaddr.in);
            const rc = std.os.windows.ws2_32.getsockname(sock, @ptrCast(&bound_addr), &win_len);
            if (rc != 0) return LabServiceError.PortResolutionFailed;
        } else {
            var bound_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in);
            std.posix.getsockname(sock, @ptrCast(&bound_addr), &bound_len) catch {
                return LabServiceError.PortResolutionFailed;
            };
        }
        actual_port = std.mem.bigToNative(u16, bound_addr.port);

        const self = try allocator.create(LabLoopbackService);
        self.* = .{
            .allocator = allocator,
            .sock = sock,
            .port = actual_port,
            .bind_ip = bind_ip,
            .service_kind = kind,
            .should_stop = std.atomic.Value(bool).init(false),
            .thread = null,
        };

        const thread = std.Thread.spawn(.{}, workerLoop, .{self}) catch {
            allocator.destroy(self);
            return LabServiceError.SocketCreationFailed;
        };
        self.thread = thread;

        return self;
    }

    pub fn stop(self: *LabLoopbackService) void {
        self.should_stop.store(true, .seq_cst);

        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }

        closeSocket(self.sock);

        const alloc = self.allocator;
        alloc.destroy(self);
    }

    fn workerLoop(self: *LabLoopbackService) void {
        while (!self.should_stop.load(.seq_cst)) {
            if (comptime builtin.os.tag == .windows) {
                var read_fds = std.os.windows.ws2_32.fd_set{
                    .fd_count = 1,
                    .fd_array = undefined,
                };
                read_fds.fd_array[0] = self.sock;

                const tv = std.os.windows.ws2_32.timeval{
                    .tv_sec = 0,
                    .tv_usec = 25_000, // 25ms polling timeout
                };

                const rc = std.os.windows.ws2_32.select(0, &read_fds, null, null, &tv);
                if (rc > 0) {
                    var client_addr: std.posix.sockaddr.in = undefined;
                    var client_len: i32 = @sizeOf(std.posix.sockaddr.in);
                    const client_sock = std.os.windows.ws2_32.accept(self.sock, @ptrCast(&client_addr), &client_len);
                    if (client_sock != std.os.windows.ws2_32.INVALID_SOCKET) {
                        defer closeSocket(client_sock);
                        handleClient(client_sock, self.service_kind);
                    }
                }
            } else {
                var pfd = [1]std.posix.pollfd{
                    .{
                        .fd = self.sock,
                        .events = std.posix.POLL.IN,
                        .revents = 0,
                    },
                };
                const rc = std.posix.poll(&pfd, 25) catch 0;
                if (rc > 0 and (pfd[0].revents & std.posix.POLL.IN) != 0) {
                    var client_addr: std.posix.sockaddr = undefined;
                    var client_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
                    const client_sock = std.posix.accept(self.sock, &client_addr, &client_len, 0) catch continue;
                    defer closeSocket(client_sock);
                    handleClient(client_sock, self.service_kind);
                }
            }
        }
    }

    fn handleClient(sock: std.posix.socket_t, kind: ServiceKind) void {
        if (kind != .raw_tcp) {
            // Optional read with timeout for HTTP requests
            if (comptime builtin.os.tag == .windows) {
                const tv_ms: u32 = 100;
                _ = std.os.windows.ws2_32.setsockopt(sock, 0xffff, 0x1006, @ptrCast(&tv_ms), @sizeOf(u32));
            }
            var buf: [512]u8 = undefined;
            _ = recvBytes(sock, &buf) catch {};
        }

        const response: []const u8 = switch (kind) {
            .raw_tcp => "WireScope Lab Synthetic TCP Service Active\r\n",
            .http_mock_vulnerable => "HTTP/1.1 200 OK\r\n" ++
                "Server: WireScope-Lab-Mock/1.0\r\n" ++
                "Content-Type: text/plain\r\n" ++
                "Content-Length: 21\r\n" ++
                "Connection: close\r\n" ++
                "\r\n" ++
                "Lab HTTP Vulnerable\n",
            .http_mock_hardened => "HTTP/1.1 200 OK\r\n" ++
                "Server: WireScope-Lab-Mock/1.0\r\n" ++
                "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" ++
                "Content-Security-Policy: default-src 'self'\r\n" ++
                "X-Content-Type-Options: nosniff\r\n" ++
                "X-Frame-Options: DENY\r\n" ++
                "Content-Type: text/plain\r\n" ++
                "Content-Length: 19\r\n" ++
                "Connection: close\r\n" ++
                "\r\n" ++
                "Lab HTTP Hardened\n",
        };

        _ = sendBytes(sock, response) catch {};
    }
};

test "lab service: strictly forbids non-loopback bind addresses" {
    const res1 = LabLoopbackService.start(testing.allocator, "0.0.0.0", 0, .raw_tcp);
    try testing.expectError(LabServiceError.NonLoopbackBindForbidden, res1);

    const res2 = LabLoopbackService.start(testing.allocator, "192.168.1.1", 0, .raw_tcp);
    try testing.expectError(LabServiceError.NonLoopbackBindForbidden, res2);

    const res3 = LabLoopbackService.start(testing.allocator, "8.8.8.8", 0, .raw_tcp);
    try testing.expectError(LabServiceError.NonLoopbackBindForbidden, res3);
}

test "lab service: binds to loopback and allocates ephemeral port" {
    var service = try LabLoopbackService.start(testing.allocator, "127.0.0.1", 0, .raw_tcp);
    defer service.stop();

    try testing.expect(service.port > 0);
    try testing.expectEqualStrings("127.0.0.1", service.bind_ip);

    // Verify connection to the loopback service
    const target_addr = try std.net.Address.parseIp4("127.0.0.1", service.port);
    const client_sock = try std.posix.socket(target_addr.any.family, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
    defer closeSocket(client_sock);

    try std.posix.connect(client_sock, &target_addr.any, target_addr.getOsSockLen());

    var buf: [128]u8 = undefined;
    const n = try recvBytes(client_sock, &buf);
    try testing.expect(n > 0);
    try testing.expect(std.mem.indexOf(u8, buf[0..n], "WireScope Lab") != null);
}

test "lab service: repeatable lifecycle" {
    // Start and stop cycle 1
    {
        var s1 = try LabLoopbackService.start(testing.allocator, "127.0.0.1", 0, .http_mock_vulnerable);
        try testing.expect(s1.port > 0);
        s1.stop();
    }

    // Start and stop cycle 2
    {
        var s2 = try LabLoopbackService.start(testing.allocator, "127.0.0.1", 0, .http_mock_hardened);
        try testing.expect(s2.port > 0);
        s2.stop();
    }
}
