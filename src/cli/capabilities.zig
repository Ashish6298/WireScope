const std = @import("std");
const testing = std.testing;
const wirescope = @import("wirescope");
const OutputFormat = @import("args.zig").OutputFormat;

pub fn printCapabilities(writer: anytype, format: OutputFormat) !void {
    const plat_info = wirescope.platform.getPlatformInfo();
    const os_tag = @tagName(@import("builtin").os.tag);

    switch (format) {
        .json => {
            try writer.print(
                \\{{"version":"{s}","os":"{s}","platform_supported":{s},"capabilities":{{"dns_resolution":true,"tcp_probes":true,"tls_verification":true,"interface_inspection":true,"listener_inventory":true,"defensive_audits":true,"isolated_lab":true}},"privilege_required":"none"}}
                \\
            , .{
                wirescope.version,
                os_tag,
                if (plat_info.is_supported) "true" else "false",
            });
        },
        .terminal, .markdown => {
            try writer.print(
                \\WireScope Capability Matrix
                \\==========================
                \\WireScope Version:      {s}
                \\Host Platform:          {s} (Supported: {s})
                \\
                \\Diagnostic Capabilities:
                \\  [x] DNS A/AAAA Resolution
                \\  [x] TCP Bounded Probes & Latency Percentiles
                \\  [x] TLS Handshake & Certificate Validation
                \\  [x] Network Interface Enumeration
                \\  [x] Local Listener Inventory
                \\
                \\Defensive Capabilities:
                \\  [x] HTTP Security Configuration Audit (HSTS, CSP, Cookies)
                \\  [x] Local Exposure & Wildcard Binding Review
                \\  [x] Baseline Snapshot Diffs (New, Removed, Changed)
                \\  [x] Isolated Practice Lab (6 Loopback Scenarios)
                \\
                \\Privilege Requirement:  Non-elevated / Standard user for regular diagnostics
                \\
            , .{
                wirescope.version,
                os_tag,
                if (plat_info.is_supported) "yes" else "no",
            });
        },
    }
}

test "capabilities output compiles and prints json" {
    var buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try printCapabilities(fbs.writer(), .json);
    const output = fbs.getWritten();
    try testing.expect(output.len > 0);
    try testing.expect(std.mem.startsWith(u8, output, "{\"version\":"));
}
