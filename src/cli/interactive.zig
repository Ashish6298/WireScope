const std = @import("std");
const windows = std.os.windows;
const theme = @import("theme.zig");
const Theme = theme.Theme;
const root = @import("root.zig");

const KEY_EVENT_RECORD = extern struct {
    bKeyDown: windows.BOOL,
    wRepeatCount: windows.WORD,
    wVirtualKeyCode: windows.WORD,
    wVirtualScanCode: windows.WORD,
    uChar: extern union {
        UnicodeChar: windows.WCHAR,
        AsciiChar: windows.CHAR,
    },
    dwControlKeyState: windows.DWORD,
};

const INPUT_RECORD = extern struct {
    EventType: windows.WORD,
    Event: extern union {
        KeyEvent: KEY_EVENT_RECORD,
        MouseEvent: [16]u8,
        WindowBufferSizeEvent: [4]u8,
        MenuEvent: [4]u8,
        FocusEvent: [4]u8,
    },
};

extern "kernel32" fn ReadConsoleInputW(
    hConsoleInput: windows.HANDLE,
    lpBuffer: [*]INPUT_RECORD,
    nLength: windows.DWORD,
    lpNumberOfEventsRead: *windows.DWORD,
) callconv(windows.WINAPI) windows.BOOL;

const KeyAction = union(enum) {
    up,
    down,
    left,
    right,
    enter,
    escape,
    char: u8,
    none,
};

fn readConsoleKey(handle: windows.HANDLE) KeyAction {
    var record: INPUT_RECORD = undefined;
    var events_read: windows.DWORD = 0;
    while (true) {
        if (ReadConsoleInputW(handle, (&record)[0..1].ptr, 1, &events_read) == 0 or events_read == 0) {
            return .none;
        }
        if (record.EventType == 0x0001) {
            const key_event = record.Event.KeyEvent;
            if (key_event.bKeyDown != 0) {
                switch (key_event.wVirtualKeyCode) {
                    0x26 => return .up,
                    0x28 => return .down,
                    0x25 => return .left,
                    0x27 => return .right,
                    0x0D => return .enter,
                    0x1B => return .escape,
                    else => {
                        const ch = key_event.uChar.AsciiChar;
                        if (ch != 0) {
                            return .{ .char = @as(u8, @bitCast(ch)) };
                        }
                    },
                }
            }
        }
    }
}

// 9 items, each has 5 lines, for unselected and selected
const cards_color_unsel = [9][5][]const u8{
    .{
        "\\x1b[38;2;140;155;170m╭──────────────────────╮\\x1b[0m",
        "\\x1b[38;2;140;155;170m│\\x1b[0m         \\x1b[1m\\x1b[38;2;205;212;220m[1]\\x1b[0m          \\x1b[38;2;140;155;170m│\\x1b[0m",
        "\\x1b[38;2;140;155;170m│\\x1b[0m    \\x1b[38;2;205;212;220mAudit Exposure\\x1b[0m    \\x1b[38;2;140;155;170m│\\x1b[0m",
        "\\x1b[38;2;140;155;170m│\\x1b[0m   \\x1b[90mports, listeners\\x1b[0m   \\x1b[38;2;140;155;170m│\\x1b[0m",
        "\\x1b[38;2;140;155;170m╰──────────────────────╯\\x1b[0m",
    },
    .{
        "\\x1b[38;2;140;155;170m╭──────────────────────╮\\x1b[0m",
        "\\x1b[38;2;140;155;170m│\\x1b[0m         \\x1b[1m\\x1b[38;2;205;212;220m[2]\\x1b[0m          \\x1b[38;2;140;155;170m│\\x1b[0m",
        "\\x1b[38;2;140;155;170m│\\x1b[0m      \\x1b[38;2;205;212;220mTCP Check\\x1b[0m       \\x1b[38;2;140;155;170m│\\x1b[0m",
        "\\x1b[38;2;140;155;170m│\\x1b[0m   \\x1b[90mhost:port probe\\x1b[0m    \\x1b[38;2;140;155;170m│\\x1b[0m",
        "\\x1b[38;2;140;155;170m╰──────────────────────╯\\x1b[0m",
    },
    .{
        "\\x1b[38;2;140;155;170m╭──────────────────────╮\\x1b[0m",
        "\\x1b[38;2;140;155;170m│\\x1b[0m         \\x1b[1m\\x1b[38;2;205;212;220m[3]\\x1b[0m          \\x1b[38;2;140;155;170m│\\x1b[0m",
        "\\x1b[38;2;140;155;170m│\\x1b[0m     \\x1b[38;2;205;212;220mDNS Diagnose\\x1b[0m     \\x1b[38;2;140;155;170m│\\x1b[0m",
        "\\x1b[38;2;140;155;170m│\\x1b[0m    \\x1b[90mA/AAAA records\\x1b[0m    \\x1b[38;2;140;155;170m│\\x1b[0m",
        "\\x1b[38;2;140;155;170m╰──────────────────────╯\\x1b[0m",
    },
    .{
        "\\x1b[38;2;140;155;170m╭──────────────────────╮\\x1b[0m",
        "\\x1b[38;2;140;155;170m│\\x1b[0m         \\x1b[1m\\x1b[38;2;205;212;220m[4]\\x1b[0m          \\x1b[38;2;140;155;170m│\\x1b[0m",
        "\\x1b[38;2;140;155;170m│\\x1b[0m      \\x1b[38;2;205;212;220mInterfaces\\x1b[0m      \\x1b[38;2;140;155;170m│\\x1b[0m",
        "\\x1b[38;2;140;155;170m│\\x1b[0m     \\x1b[90mIPv4 / IPv6\\x1b[0m      \\x1b[38;2;140;155;170m│\\x1b[0m",
        "\\x1b[38;2;140;155;170m╰──────────────────────╯\\x1b[0m",
    },
    .{
        "\\x1b[38;2;140;155;170m╭──────────────────────╮\\x1b[0m",
        "\\x1b[38;2;140;155;170m│\\x1b[0m         \\x1b[1m\\x1b[38;2;205;212;220m[5]\\x1b[0m          \\x1b[38;2;140;155;170m│\\x1b[0m",
        "\\x1b[38;2;140;155;170m│\\x1b[0m    \\x1b[38;2;205;212;220mRouting Table\\x1b[0m     \\x1b[38;2;140;155;170m│\\x1b[0m",
        "\\x1b[38;2;140;155;170m│\\x1b[0m   \\x1b[90mroutes, gateway\\x1b[0m    \\x1b[38;2;140;155;170m│\\x1b[0m",
        "\\x1b[38;2;140;155;170m╰──────────────────────╯\\x1b[0m",
    },
    .{
        "\\x1b[38;2;140;155;170m╭──────────────────────╮\\x1b[0m",
        "\\x1b[38;2;140;155;170m│\\x1b[0m         \\x1b[1m\\x1b[38;2;205;212;220m[6]\\x1b[0m          \\x1b[38;2;140;155;170m│\\x1b[0m",
        "\\x1b[38;2;140;155;170m│\\x1b[0m   \\x1b[38;2;205;212;220mSecurity Policy\\x1b[0m    \\x1b[38;2;140;155;170m│\\x1b[0m",
        "\\x1b[38;2;140;155;170m│\\x1b[0m    \\x1b[90moffline rules\\x1b[0m     \\x1b[38;2;140;155;170m│\\x1b[0m",
        "\\x1b[38;2;140;155;170m╰──────────────────────╯\\x1b[0m",
    },
    .{
        "\\x1b[38;2;140;155;170m╭──────────────────────╮\\x1b[0m",
        "\\x1b[38;2;140;155;170m│\\x1b[0m         \\x1b[1m\\x1b[38;2;205;212;220m[7]\\x1b[0m          \\x1b[38;2;140;155;170m│\\x1b[0m",
        "\\x1b[38;2;140;155;170m│\\x1b[0m     \\x1b[38;2;205;212;220mPractice Lab\\x1b[0m     \\x1b[38;2;140;155;170m│\\x1b[0m",
        "\\x1b[38;2;140;155;170m│\\x1b[0m  \\x1b[90mloopback training\\x1b[0m   \\x1b[38;2;140;155;170m│\\x1b[0m",
        "\\x1b[38;2;140;155;170m╰──────────────────────╯\\x1b[0m",
    },
    .{
        "\\x1b[38;2;140;155;170m╭──────────────────────╮\\x1b[0m",
        "\\x1b[38;2;140;155;170m│\\x1b[0m         \\x1b[1m\\x1b[38;2;205;212;220m[8]\\x1b[0m          \\x1b[38;2;140;155;170m│\\x1b[0m",
        "\\x1b[38;2;140;155;170m│\\x1b[0m     \\x1b[38;2;205;212;220mCapabilities\\x1b[0m     \\x1b[38;2;140;155;170m│\\x1b[0m",
        "\\x1b[38;2;140;155;170m│\\x1b[0m   \\x1b[90mfeatures, rights\\x1b[0m   \\x1b[38;2;140;155;170m│\\x1b[0m",
        "\\x1b[38;2;140;155;170m╰──────────────────────╯\\x1b[0m",
    },
    .{
        "\\x1b[38;2;70;80;92m╭──────────────────────╮\\x1b[0m",
        "\\x1b[38;2;70;80;92m│\\x1b[0m         \\x1b[1m\\x1b[38;2;205;212;220m[0]\\x1b[0m          \\x1b[38;2;70;80;92m│\\x1b[0m",
        "\\x1b[38;2;70;80;92m│\\x1b[0m         \\x1b[38;2;205;212;220mExit\\x1b[0m         \\x1b[38;2;70;80;92m│\\x1b[0m",
        "\\x1b[38;2;70;80;92m│\\x1b[0m         \\x1b[90mquit\\x1b[0m         \\x1b[38;2;70;80;92m│\\x1b[0m",
        "\\x1b[38;2;70;80;92m╰──────────────────────╯\\x1b[0m",
    },
};

const cards_color_sel = [9][5][]const u8{
    .{
        "\\x1b[38;2;205;212;220m╭──────────────────────╮\\x1b[0m",
        "\\x1b[38;2;205;212;220m│\\x1b[0m        \\x1b[48;2;58;68;80m\\x1b[1m\\x1b[38;2;205;212;220m [1] \\x1b[0m         \\x1b[38;2;205;212;220m│\\x1b[0m",
        "\\x1b[38;2;205;212;220m│\\x1b[0m    \\x1b[1m\\x1b[38;2;205;212;220mAudit Exposure\\x1b[0m    \\x1b[38;2;205;212;220m│\\x1b[0m",
        "\\x1b[38;2;205;212;220m│\\x1b[0m   \\x1b[90mports, listeners\\x1b[0m   \\x1b[38;2;205;212;220m│\\x1b[0m",
        "\\x1b[38;2;205;212;220m╰──────────────────────╯\\x1b[0m",
    },
    .{
        "\\x1b[38;2;205;212;220m╭──────────────────────╮\\x1b[0m",
        "\\x1b[38;2;205;212;220m│\\x1b[0m        \\x1b[48;2;58;68;80m\\x1b[1m\\x1b[38;2;205;212;220m [2] \\x1b[0m         \\x1b[38;2;205;212;220m│\\x1b[0m",
        "\\x1b[38;2;205;212;220m│\\x1b[0m      \\x1b[1m\\x1b[38;2;205;212;220mTCP Check\\x1b[0m       \\x1b[38;2;205;212;220m│\\x1b[0m",
        "\\x1b[38;2;205;212;220m│\\x1b[0m   \\x1b[90mhost:port probe\\x1b[0m    \\x1b[38;2;205;212;220m│\\x1b[0m",
        "\\x1b[38;2;205;212;220m╰──────────────────────╯\\x1b[0m",
    },
    .{
        "\\x1b[38;2;205;212;220m╭──────────────────────╮\\x1b[0m",
        "\\x1b[38;2;205;212;220m│\\x1b[0m        \\x1b[48;2;58;68;80m\\x1b[1m\\x1b[38;2;205;212;220m [3] \\x1b[0m         \\x1b[38;2;205;212;220m│\\x1b[0m",
        "\\x1b[38;2;205;212;220m│\\x1b[0m     \\x1b[1m\\x1b[38;2;205;212;220mDNS Diagnose\\x1b[0m     \\x1b[38;2;205;212;220m│\\x1b[0m",
        "\\x1b[38;2;205;212;220m│\\x1b[0m    \\x1b[90mA/AAAA records\\x1b[0m    \\x1b[38;2;205;212;220m│\\x1b[0m",
        "\\x1b[38;2;205;212;220m╰──────────────────────╯\\x1b[0m",
    },
    .{
        "\\x1b[38;2;205;212;220m╭──────────────────────╮\\x1b[0m",
        "\\x1b[38;2;205;212;220m│\\x1b[0m        \\x1b[48;2;58;68;80m\\x1b[1m\\x1b[38;2;205;212;220m [4] \\x1b[0m         \\x1b[38;2;205;212;220m│\\x1b[0m",
        "\\x1b[38;2;205;212;220m│\\x1b[0m      \\x1b[1m\\x1b[38;2;205;212;220mInterfaces\\x1b[0m      \\x1b[38;2;205;212;220m│\\x1b[0m",
        "\\x1b[38;2;205;212;220m│\\x1b[0m     \\x1b[90mIPv4 / IPv6\\x1b[0m      \\x1b[38;2;205;212;220m│\\x1b[0m",
        "\\x1b[38;2;205;212;220m╰──────────────────────╯\\x1b[0m",
    },
    .{
        "\\x1b[38;2;205;212;220m╭──────────────────────╮\\x1b[0m",
        "\\x1b[38;2;205;212;220m│\\x1b[0m        \\x1b[48;2;58;68;80m\\x1b[1m\\x1b[38;2;205;212;220m [5] \\x1b[0m         \\x1b[38;2;205;212;220m│\\x1b[0m",
        "\\x1b[38;2;205;212;220m│\\x1b[0m    \\x1b[1m\\x1b[38;2;205;212;220mRouting Table\\x1b[0m     \\x1b[38;2;205;212;220m│\\x1b[0m",
        "\\x1b[38;2;205;212;220m│\\x1b[0m   \\x1b[90mroutes, gateway\\x1b[0m    \\x1b[38;2;205;212;220m│\\x1b[0m",
        "\\x1b[38;2;205;212;220m╰──────────────────────╯\\x1b[0m",
    },
    .{
        "\\x1b[38;2;205;212;220m╭──────────────────────╮\\x1b[0m",
        "\\x1b[38;2;205;212;220m│\\x1b[0m        \\x1b[48;2;58;68;80m\\x1b[1m\\x1b[38;2;205;212;220m [6] \\x1b[0m         \\x1b[38;2;205;212;220m│\\x1b[0m",
        "\\x1b[38;2;205;212;220m│\\x1b[0m   \\x1b[1m\\x1b[38;2;205;212;220mSecurity Policy\\x1b[0m    \\x1b[38;2;205;212;220m│\\x1b[0m",
        "\\x1b[38;2;205;212;220m│\\x1b[0m    \\x1b[90moffline rules\\x1b[0m     \\x1b[38;2;205;212;220m│\\x1b[0m",
        "\\x1b[38;2;205;212;220m╰──────────────────────╯\\x1b[0m",
    },
    .{
        "\\x1b[38;2;205;212;220m╭──────────────────────╮\\x1b[0m",
        "\\x1b[38;2;205;212;220m│\\x1b[0m        \\x1b[48;2;58;68;80m\\x1b[1m\\x1b[38;2;205;212;220m [7] \\x1b[0m         \\x1b[38;2;205;212;220m│\\x1b[0m",
        "\\x1b[38;2;205;212;220m│\\x1b[0m     \\x1b[1m\\x1b[38;2;205;212;220mPractice Lab\\x1b[0m     \\x1b[38;2;205;212;220m│\\x1b[0m",
        "\\x1b[38;2;205;212;220m│\\x1b[0m  \\x1b[90mloopback training\\x1b[0m   \\x1b[38;2;205;212;220m│\\x1b[0m",
        "\\x1b[38;2;205;212;220m╰──────────────────────╯\\x1b[0m",
    },
    .{
        "\\x1b[38;2;205;212;220m╭──────────────────────╮\\x1b[0m",
        "\\x1b[38;2;205;212;220m│\\x1b[0m        \\x1b[48;2;58;68;80m\\x1b[1m\\x1b[38;2;205;212;220m [8] \\x1b[0m         \\x1b[38;2;205;212;220m│\\x1b[0m",
        "\\x1b[38;2;205;212;220m│\\x1b[0m     \\x1b[1m\\x1b[38;2;205;212;220mCapabilities\\x1b[0m     \\x1b[38;2;205;212;220m│\\x1b[0m",
        "\\x1b[38;2;205;212;220m│\\x1b[0m   \\x1b[90mfeatures, rights\\x1b[0m   \\x1b[38;2;205;212;220m│\\x1b[0m",
        "\\x1b[38;2;205;212;220m╰──────────────────────╯\\x1b[0m",
    },
    .{
        "\\x1b[38;2;205;212;220m╭──────────────────────╮\\x1b[0m",
        "\\x1b[38;2;205;212;220m│\\x1b[0m        \\x1b[48;2;58;68;80m\\x1b[1m\\x1b[38;2;205;212;220m [0] \\x1b[0m         \\x1b[38;2;205;212;220m│\\x1b[0m",
        "\\x1b[38;2;205;212;220m│\\x1b[0m         \\x1b[1m\\x1b[38;2;205;212;220mExit\\x1b[0m         \\x1b[38;2;205;212;220m│\\x1b[0m",
        "\\x1b[38;2;205;212;220m│\\x1b[0m         \\x1b[90mquit\\x1b[0m         \\x1b[38;2;205;212;220m│\\x1b[0m",
        "\\x1b[38;2;205;212;220m╰──────────────────────╯\\x1b[0m",
    },
};

const cards_plain_unsel = [9][5][]const u8{
    .{
        "╭──────────────────────╮",
        "│         [1]          │",
        "│    Audit Exposure    │",
        "│   ports, listeners   │",
        "╰──────────────────────╯",
    },
    .{
        "╭──────────────────────╮",
        "│         [2]          │",
        "│      TCP Check       │",
        "│   host:port probe    │",
        "╰──────────────────────╯",
    },
    .{
        "╭──────────────────────╮",
        "│         [3]          │",
        "│     DNS Diagnose     │",
        "│    A/AAAA records    │",
        "╰──────────────────────╯",
    },
    .{
        "╭──────────────────────╮",
        "│         [4]          │",
        "│      Interfaces      │",
        "│     IPv4 / IPv6      │",
        "╰──────────────────────╯",
    },
    .{
        "╭──────────────────────╮",
        "│         [5]          │",
        "│    Routing Table     │",
        "│   routes, gateway    │",
        "╰──────────────────────╯",
    },
    .{
        "╭──────────────────────╮",
        "│         [6]          │",
        "│   Security Policy    │",
        "│    offline rules     │",
        "╰──────────────────────╯",
    },
    .{
        "╭──────────────────────╮",
        "│         [7]          │",
        "│     Practice Lab     │",
        "│  loopback training   │",
        "╰──────────────────────╯",
    },
    .{
        "╭──────────────────────╮",
        "│         [8]          │",
        "│     Capabilities     │",
        "│   features, rights   │",
        "╰──────────────────────╯",
    },
    .{
        "╭──────────────────────╮",
        "│         [0]          │",
        "│         Exit         │",
        "│         quit         │",
        "╰──────────────────────╯",
    },
};

const cards_plain_sel = [9][5][]const u8{
    .{
        "╭──────────────────────╮",
        "│         [1]          │",
        "│    Audit Exposure    │",
        "│   ports, listeners   │",
        "╰──────────────────────╯",
    },
    .{
        "╭──────────────────────╮",
        "│         [2]          │",
        "│      TCP Check       │",
        "│   host:port probe    │",
        "╰──────────────────────╯",
    },
    .{
        "╭──────────────────────╮",
        "│         [3]          │",
        "│     DNS Diagnose     │",
        "│    A/AAAA records    │",
        "╰──────────────────────╯",
    },
    .{
        "╭──────────────────────╮",
        "│         [4]          │",
        "│      Interfaces      │",
        "│     IPv4 / IPv6      │",
        "╰──────────────────────╯",
    },
    .{
        "╭──────────────────────╮",
        "│         [5]          │",
        "│    Routing Table     │",
        "│   routes, gateway    │",
        "╰──────────────────────╯",
    },
    .{
        "╭──────────────────────╮",
        "│         [6]          │",
        "│   Security Policy    │",
        "│    offline rules     │",
        "╰──────────────────────╯",
    },
    .{
        "╭──────────────────────╮",
        "│         [7]          │",
        "│     Practice Lab     │",
        "│  loopback training   │",
        "╰──────────────────────╯",
    },
    .{
        "╭──────────────────────╮",
        "│         [8]          │",
        "│     Capabilities     │",
        "│   features, rights   │",
        "╰──────────────────────╯",
    },
    .{
        "╭──────────────────────╮",
        "│         [0]          │",
        "│         Exit         │",
        "│         quit         │",
        "╰──────────────────────╯",
    },
};

pub fn renderScreen(writer: anytype, sel_idx: usize, use_color: bool) !void {
    try Theme.printBanner(writer, use_color);

    const layout = [3][3]usize{
        .{ 0, 1, 2 },
        .{ 3, 4, 5 },
        .{ 6, 7, 8 },
    };

    inline for (layout) |row_indices| {
        inline for (0..5) |line_idx| {
            try writer.writeAll("  ");
            inline for (row_indices, 0..) |item_idx, col_pos| {
                if (col_pos > 0) try writer.writeAll("  ");
                if (use_color) {
                    if (item_idx == sel_idx) {
                        try writer.writeAll(cards_color_sel[item_idx][line_idx]);
                    } else {
                        try writer.writeAll(cards_color_unsel[item_idx][line_idx]);
                    }
                } else {
                    if (item_idx == sel_idx) {
                        try writer.writeAll(cards_plain_sel[item_idx][line_idx]);
                    } else {
                        try writer.writeAll(cards_plain_unsel[item_idx][line_idx]);
                    }
                }
            }
            try writer.writeAll("\n");
        }
    }

    if (use_color) {
        try writer.writeAll("\n  \x1b[90marrows move    enter run    1-8 jump and run    0 / q exit\x1b[0m\n");
    } else {
        try writer.writeAll("\n  arrows move    enter run    1-8 jump and run    0 / q exit\n");
    }
}

pub fn runInteractive(stdout: anytype, stderr: anytype) u8 {
    Theme.enableVirtualTerminal();
    const use_color = Theme.shouldColorize(false);

    var stdin_buf: [256]u8 = undefined;
    const stdin = std.io.getStdIn();
    const is_tty = stdin.isTty();

    if (!is_tty) {
        // Non-interactive or piped mode (e.g. echo 0 | wirescope menu)
        renderScreen(stdout, 0, use_color) catch return root.ExitCodes.operational_failure;
        stdout.writeAll("\n  Select an option [0-8]: ") catch return root.ExitCodes.operational_failure;
        const line = readLine(stdin.reader(), &stdin_buf) orelse return root.ExitCodes.success;
        if (std.mem.eql(u8, line, "0") or std.mem.eql(u8, line, "q") or std.mem.eql(u8, line, "exit")) {
            stdout.print("\n  Goodbye.\n\n", .{}) catch {};
            return root.ExitCodes.success;
        }
        if (line.len > 0 and line[0] >= '1' and line[0] <= '8') {
            const idx = line[0] - '1';
            executeItem(idx, stdin.reader(), stdout, stderr);
        }
        return root.ExitCodes.success;
    }

    // Interactive TTY mode
    const h_in = if (@import("builtin").os.tag == .windows)
        windows.kernel32.GetStdHandle(windows.STD_INPUT_HANDLE) orelse windows.INVALID_HANDLE_VALUE
    else
        windows.INVALID_HANDLE_VALUE;

    var idx: usize = 0;

    // Hide cursor
    stdout.writeAll("\x1b[?25l") catch {};
    defer {
        stdout.writeAll("\x1b[?25h\x1b[H\x1b[2J") catch {};
        stdout.print("\n  Goodbye.\n\n", .{}) catch {};
    }

    while (true) {
        // Clear screen and draw menu
        stdout.writeAll("\x1b[H\x1b[2J") catch return root.ExitCodes.operational_failure;
        renderScreen(stdout, idx, use_color) catch return root.ExitCodes.operational_failure;

        const action: KeyAction = if (h_in != windows.INVALID_HANDLE_VALUE)
            readConsoleKey(h_in)
        else blk: {
            const line = readLine(stdin.reader(), &stdin_buf) orelse break;
            if (line.len == 0) break :blk KeyAction.enter;
            if (line[0] >= '0' and line[0] <= '8') break :blk KeyAction{ .char = line[0] };
            if (line[0] == 'q' or line[0] == 'Q') break :blk KeyAction.escape;
            break :blk KeyAction.none;
        };

        const row = idx / 3;
        const col = idx % 3;

        switch (action) {
            .up => {
                const new_row = (row + 2) % 3;
                idx = new_row * 3 + col;
            },
            .down => {
                const new_row = (row + 1) % 3;
                idx = new_row * 3 + col;
            },
            .left => {
                const new_col = (col + 2) % 3;
                idx = row * 3 + new_col;
            },
            .right => {
                const new_col = (col + 1) % 3;
                idx = row * 3 + new_col;
            },
            .enter => {
                if (idx == 8) { // Item 0: Exit
                    break;
                }
                stdout.writeAll("\x1b[?25h") catch {};
                executeItem(idx, stdin.reader(), stdout, stderr);
                stdout.writeAll("\x1b[?25l") catch {};
            },
            .char => |c| {
                if (c == '0' or c == 'q' or c == 'Q') {
                    break;
                } else if (c >= '1' and c <= '8') {
                    idx = c - '1';
                    stdout.writeAll("\x1b[?25h") catch {};
                    executeItem(idx, stdin.reader(), stdout, stderr);
                    stdout.writeAll("\x1b[?25l") catch {};
                } else if (c == 'k') {
                    const new_row = (row + 2) % 3;
                    idx = new_row * 3 + col;
                } else if (c == 'j') {
                    const new_row = (row + 1) % 3;
                    idx = new_row * 3 + col;
                } else if (c == 'h') {
                    const new_col = (col + 2) % 3;
                    idx = row * 3 + new_col;
                } else if (c == 'l') {
                    const new_col = (col + 1) % 3;
                    idx = row * 3 + new_col;
                }
            },
            .escape => break,
            .none => {},
        }
    }

    return root.ExitCodes.success;
}

fn executeItem(idx: usize, reader: anytype, stdout: anytype, stderr: anytype) void {
    var target_buf: [128]u8 = undefined;

    switch (idx) {
        0 => {
            stdout.print("\n>>> Running: wirescope audit local\n\n", .{}) catch {};
            _ = root.execute(&[_][]const u8{ "wirescope", "audit", "local" }, stdout, stderr);
        },
        1 => {
            stdout.print("\nEnter target host:port [default: 127.0.0.1:80]: ", .{}) catch {};
            const input = readLine(reader, &target_buf) orelse "127.0.0.1:80";
            const target = if (input.len == 0) "127.0.0.1:80" else input;
            stdout.print("\n>>> Running: wirescope diagnose tcp {s}\n\n", .{target}) catch {};
            _ = root.execute(&[_][]const u8{ "wirescope", "diagnose", "tcp", target }, stdout, stderr);
        },
        2 => {
            stdout.print("\nEnter target domain [default: localhost]: ", .{}) catch {};
            const input = readLine(reader, &target_buf) orelse "localhost";
            const domain = if (input.len == 0) "localhost" else input;
            stdout.print("\n>>> Running: wirescope diagnose dns {s}\n\n", .{domain}) catch {};
            _ = root.execute(&[_][]const u8{ "wirescope", "diagnose", "dns", domain }, stdout, stderr);
        },
        3 => {
            stdout.print("\n>>> Running: wirescope diagnose interfaces\n\n", .{}) catch {};
            _ = root.execute(&[_][]const u8{ "wirescope", "diagnose", "interfaces" }, stdout, stderr);
        },
        4 => {
            stdout.print("\n>>> Running: wirescope diagnose routes\n\n", .{}) catch {};
            _ = root.execute(&[_][]const u8{ "wirescope", "diagnose", "routes" }, stdout, stderr);
        },
        5 => {
            stdout.print("\n>>> Running: wirescope policy check\n\n", .{}) catch {};
            _ = root.execute(&[_][]const u8{ "wirescope", "policy", "check" }, stdout, stderr);
        },
        6 => {
            stdout.print(
                \\Available Lab Scenarios:
                \\  [1] dns_failure                  (DNS NXDOMAIN vs Timeout Simulation)
                \\  [2] tcp_refusal_timeout          (TCP Connection Refusal & Bounded Timeout)
                \\  [3] unexpected_listener          (Listener Exposure vs Baseline Drift)
                \\  [4] http_security_header_violation (HTTP Header Policy Audit)
                \\Select scenario [1-4, default: 1]: 
            , .{}) catch {};
            const input = readLine(reader, &target_buf) orelse "1";
            const scenario = if (std.mem.eql(u8, input, "2"))
                "tcp_refusal_timeout"
            else if (std.mem.eql(u8, input, "3"))
                "unexpected_listener"
            else if (std.mem.eql(u8, input, "4"))
                "http_security_header_violation"
            else
                "dns_failure";

            stdout.print("\n>>> Running: wirescope lab run {s}\n\n", .{scenario}) catch {};
            _ = root.execute(&[_][]const u8{ "wirescope", "lab", "run", scenario }, stdout, stderr);
        },
        7 => {
            stdout.print("\n>>> Running: wirescope capabilities\n\n", .{}) catch {};
            _ = root.execute(&[_][]const u8{ "wirescope", "capabilities" }, stdout, stderr);
        },
        else => {},
    }

    stdout.print("\n  press any key to return to the menu...", .{}) catch {};
    _ = readLine(reader, &target_buf);
}

fn readLine(reader: anytype, buffer: []u8) ?[]const u8 {
    const line = reader.readUntilDelimiterOrEof(buffer, '\n') catch return null;
    if (line) |l| {
        return std.mem.trim(u8, l, "\r\n \t");
    }
    return null;
}

test "readLine helper tests" {
    var fbs = std.io.fixedBufferStream("hello world\r\n");
    var buf: [32]u8 = undefined;
    const res = readLine(fbs.reader(), &buf);
    try std.testing.expect(res != null);
    try std.testing.expectEqualStrings("hello world", res.?);
}

test "renderScreen smoke test" {
    var buf: [32768]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try renderScreen(fbs.writer(), 0, true);
    try std.testing.expect(fbs.getWritten().len > 0);

    fbs.reset();
    try renderScreen(fbs.writer(), 0, false);
    try std.testing.expect(fbs.getWritten().len > 0);
}
