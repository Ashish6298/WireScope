const std = @import("std");
const testing = std.testing;

pub const ReportFormat = enum {
    terminal,
    json,
    markdown,
};

pub const ReportConfig = struct {
    format: ReportFormat = .terminal,
    redact_sensitive: bool = true,
};

test "reporting definitions compile" {
    const config = ReportConfig{};
    try testing.expectEqual(ReportFormat.terminal, config.format);
}
