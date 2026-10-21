const std = @import("std");
const testing = std.testing;

pub const OsTag = @import("builtin").os.tag;

pub const PlatformInfo = struct {
    os_name: []const u8,
    is_supported: bool,
};

pub fn getPlatformInfo() PlatformInfo {
    return switch (OsTag) {
        .windows => .{ .os_name = "windows", .is_supported = true },
        .linux => .{ .os_name = "linux", .is_supported = true },
        .macos => .{ .os_name = "macos", .is_supported = true },
        else => .{ .os_name = "unknown", .is_supported = false },
    };
}

test "platform adapter detects valid OS" {
    const info = getPlatformInfo();
    try testing.expect(info.is_supported);
}
