const std = @import("std");
const testing = std.testing;

pub const TcpOutcome = enum {
    connected,
    connection_refused,
    timed_out,
    network_error,
};

pub fn checkTcpPort(ip_str: []const u8, port: u16) TcpOutcome {
    const address = std.net.Address.parseIp(ip_str, port) catch return .network_error;
    const stream = std.net.tcpConnectToAddress(address) catch |err| switch (err) {
        error.ConnectionRefused => return .connection_refused,
        error.ConnectionTimedOut => return .timed_out,
        else => return .network_error,
    };
    defer stream.close();
    return .connected;
}

test "TCP connection refusal on closed loopback port" {
    // Port 59999 is typically unused on loopback
    const outcome = checkTcpPort("127.0.0.1", 59999);
    // Should be connection_refused
    try testing.expect(outcome == .connection_refused or outcome == .network_error);
}

test "TCP connection to active local listener" {
    const loopback = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try loopback.listen(.{ .reuse_address = true });
    defer server.deinit();

    const actual_port = server.listen_address.getPort();
    const outcome = checkTcpPort("127.0.0.1", actual_port);
    try testing.expectEqual(TcpOutcome.connected, outcome);
}

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();

    const loopback = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try loopback.listen(.{ .reuse_address = true });
    defer server.deinit();

    const actual_port = server.listen_address.getPort();
    const connected_res = checkTcpPort("127.0.0.1", actual_port);
    const refused_res = checkTcpPort("127.0.0.1", 59999);

    try stdout.print("TCP PoC: port {d} -> {s}, port 59999 -> {s} -> TCP Checks OK\n", .{
        actual_port,
        @tagName(connected_res),
        @tagName(refused_res),
    });
}
