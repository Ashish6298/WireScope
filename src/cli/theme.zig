const std = @import("std");

pub const Theme = struct {
    pub const reset = "\x1b[0m";
    pub const bold = "\x1b[1m";
    pub const dim = "\x1b[2m";
    pub const italic = "\x1b[3m";
    pub const underline = "\x1b[4m";

    // Foreground colors
    pub const black = "\x1b[30m";
    pub const red = "\x1b[31m";
    pub const green = "\x1b[32m";
    pub const yellow = "\x1b[33m";
    pub const blue = "\x1b[34m";
    pub const magenta = "\x1b[35m";
    pub const cyan = "\x1b[36m";
    pub const white = "\x1b[37m";

    // Bright foreground colors
    pub const bright_gray = "\x1b[90m";
    pub const bright_red = "\x1b[91m";
    pub const bright_green = "\x1b[92m";
    pub const bright_yellow = "\x1b[93m";
    pub const bright_blue = "\x1b[94m";
    pub const bright_magenta = "\x1b[95m";
    pub const bright_cyan = "\x1b[96m";
    pub const bright_white = "\x1b[97m";

    // Background colors
    pub const bg_blue = "\x1b[44m";
    pub const bg_cyan = "\x1b[46m";
    pub const bg_gray = "\x1b[100m";

    pub fn enableVirtualTerminal() void {
        if (@import("builtin").os.tag == .windows) {
            const windows = std.os.windows;
            if (windows.kernel32.GetStdHandle(windows.STD_OUTPUT_HANDLE)) |handle| {
                if (handle != windows.INVALID_HANDLE_VALUE) {
                    var mode: windows.DWORD = 0;
                    if (windows.kernel32.GetConsoleMode(handle, &mode) != 0) {
                        _ = windows.kernel32.SetConsoleMode(handle, mode | 0x0004); // ENABLE_VIRTUAL_TERMINAL_PROCESSING
                    }
                }
            }
        }
    }

    pub fn shouldColorize(no_color_flag: bool) bool {
        if (no_color_flag) return false;
        // Check for NO_COLOR env var
        if (std.process.getEnvVarOwned(std.heap.page_allocator, "NO_COLOR")) |val| {
            std.heap.page_allocator.free(val);
            return false;
        } else |_| {}
        return true;
    }

    pub fn printBanner(writer: anytype, color: bool) !void {
        if (color) {
            try writer.print("{s}", .{bright_cyan});
            try writer.print(
                \\  __        ___           ____                      
                \\  \ \      / (_)_ __ ___ / ___|  ___ ___  _ __   ___ 
                \\
            , .{});
            try writer.print("{s}", .{cyan});
            try writer.print(
                \\   \ \ /\ / /| | '__/ _ \\___ \ / __/ _ \| '_ \ / _ \
                \\    \ V  V / | | | |  __/ ___) | (_| (_) | |_) |  __/
                \\
            , .{});
            try writer.print("{s}", .{bright_blue});
            try writer.print(
                \\     \_/\_/  |_|_|  \___||____/ \___\___/| .__/ \___|
                \\                                         |_|         
                \\
            , .{});
            try writer.print("{s}{s}  Local-First Network Diagnostics & Defensive Security Toolkit{s}\n", .{ bold, bright_white, reset });
            try writer.print("{s}  Zero Telemetry | Non-Root Auditing | Deterministic Outcomes{s}\n\n", .{ bright_gray, reset });
        } else {
            try writer.print(
                \\  __        ___           ____                      
                \\  \ \      / (_)_ __ ___ / ___|  ___ ___  _ __   ___ 
                \\   \ \ /\ / /| | '__/ _ \\___ \ / __/ _ \| '_ \ / _ \
                \\    \ V  V / | | | |  __/ ___) | (_| (_) | |_) |  __/
                \\     \_/\_/  |_|_|  \___||____/ \___\___/| .__/ \___|
                \\                                         |_|         
                \\  Local-First Network Diagnostics & Defensive Security Toolkit
                \\  Zero Telemetry | Non-Root Auditing | Deterministic Outcomes
                \\
                \\
            , .{});
        }
    }

    pub fn badgePass(writer: anytype, color: bool) !void {
        if (color) {
            try writer.print("{s}{s}[PASS]{s}", .{ bold, bright_green, reset });
        } else {
            try writer.print("[PASS]", .{});
        }
    }

    pub fn badgeFail(writer: anytype, color: bool) !void {
        if (color) {
            try writer.print("{s}{s}[FAIL]{s}", .{ bold, bright_red, reset });
        } else {
            try writer.print("[FAIL]", .{});
        }
    }

    pub fn badgeWarn(writer: anytype, color: bool) !void {
        if (color) {
            try writer.print("{s}{s}[WARN]{s}", .{ bold, bright_yellow, reset });
        } else {
            try writer.print("[WARN]", .{});
        }
    }

    pub fn badgeInfo(writer: anytype, color: bool) !void {
        if (color) {
            try writer.print("{s}{s}[INFO]{s}", .{ bold, bright_cyan, reset });
        } else {
            try writer.print("[INFO]", .{});
        }
    }

    pub fn badgeOpen(writer: anytype, color: bool) !void {
        if (color) {
            try writer.print("{s}{s}[OPEN]{s}", .{ bold, bright_green, reset });
        } else {
            try writer.print("[OPEN]", .{});
        }
    }

    pub fn badgeClosed(writer: anytype, color: bool) !void {
        if (color) {
            try writer.print("{s}{s}[CLOSED]{s}", .{ bold, bright_red, reset });
        } else {
            try writer.print("[CLOSED]", .{});
        }
    }
};

test "Theme styling smoke test" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const writer = fbs.writer();

    try Theme.printBanner(writer, false);
    try std.testing.expect(fbs.getWritten().len > 0);
}
