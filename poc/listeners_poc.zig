const std = @import("std");
const testing = std.testing;

pub fn executeNetstatFallback(allocator: std.mem.Allocator) !usize {
    if (@import("builtin").os.tag != .windows) return 0;

    var child = std.process.Child.init(&[_][]const u8{ "netstat.exe", "-ano", "-p", "tcp" }, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;

    try child.spawn();

    const max_bytes = 64 * 1024; // Bounded output buffer (64KB)
    var stdout_buf = std.ArrayList(u8).init(allocator);
    defer stdout_buf.deinit();

    var reader = child.stdout.?.reader();
    var buf: [1024]u8 = undefined;
    var total_read: usize = 0;

    while (true) {
        const bytes_read = try reader.read(&buf);
        if (bytes_read == 0) break;
        total_read += bytes_read;
        if (total_read > max_bytes) break;
        try stdout_buf.appendSlice(buf[0..bytes_read]);
    }

    _ = try child.wait();
    return stdout_buf.items.len;
}

test "Bounded subprocess execution for listener fallback" {
    if (@import("builtin").os.tag != .windows) return;
    const len = try executeNetstatFallback(testing.allocator);
    try testing.expect(len > 0);
}

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    if (@import("builtin").os.tag != .windows) {
        try stdout.print("Listeners PoC: Non-Windows platform\n", .{});
        return;
    }

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const bytes = try executeNetstatFallback(allocator);
    try stdout.print("Listeners PoC: Bounded netstat captured {d} bytes of output -> Subprocess Fallback OK\n", .{bytes});
}
