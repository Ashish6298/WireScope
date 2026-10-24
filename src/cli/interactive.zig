const std = @import("std");
const theme = @import("theme.zig");
const Theme = theme.Theme;
const root = @import("root.zig");

pub fn runInteractive(stdout: anytype, stderr: anytype) u8 {
    Theme.enableVirtualTerminal();
    const use_color = Theme.shouldColorize(false);

    var stdin_buf: [256]u8 = undefined;
    const stdin = std.io.getStdIn().reader();

    while (true) {
        Theme.printBanner(stdout, use_color) catch return root.ExitCodes.operational_failure;

        if (use_color) {
            stdout.writeAll(
                "  \x1b[1m\x1b[38;2;140;155;170mINTERACTIVE CONSOLE\x1b[0m\n" ++
                "  \x1b[38;2;70;80;92m────────────────────────────────────────────────────────────────────────────\x1b[0m\n" ++
                "   \x1b[1m\x1b[38;2;205;212;220m[1]\x1b[0m Audit Local Exposure       \x1b[90mlisteners, interfaces, open ports\x1b[0m\n" ++
                "   \x1b[1m\x1b[38;2;205;212;220m[2]\x1b[0m Test TCP Port Check        \x1b[90mconnect to host:port with a timeout\x1b[0m\n" ++
                "   \x1b[1m\x1b[38;2;205;212;220m[3]\x1b[0m Diagnose DNS Resolution    \x1b[90mquery A/AAAA records, check health\x1b[0m\n" ++
                "   \x1b[1m\x1b[38;2;205;212;220m[4]\x1b[0m Inspect Interfaces         \x1b[90mlocal adapters, IPv4/IPv6 addresses\x1b[0m\n" ++
                "   \x1b[1m\x1b[38;2;205;212;220m[5]\x1b[0m Inspect Routing Table      \x1b[90mroutes and default gateway\x1b[0m\n" ++
                "   \x1b[1m\x1b[38;2;205;212;220m[6]\x1b[0m Evaluate Security Policy   \x1b[90moffline hardening rules\x1b[0m\n" ++
                "   \x1b[1m\x1b[38;2;205;212;220m[7]\x1b[0m Run Practice Lab Drill     \x1b[90mloopback-confined training scenario\x1b[0m\n" ++
                "   \x1b[1m\x1b[38;2;205;212;220m[8]\x1b[0m Capabilities Matrix        \x1b[90mplatform features and privileges\x1b[0m\n" ++
                "   \x1b[1m\x1b[38;2;205;212;220m[0]\x1b[0m Exit\n" ++
                "  \x1b[38;2;70;80;92m────────────────────────────────────────────────────────────────────────────\x1b[0m\n" ++
                "  \x1b[1m\x1b[38;2;205;212;220mSelect an option [0-8]:\x1b[0m "
            ) catch return root.ExitCodes.operational_failure;
        } else {
            stdout.writeAll(
                "  INTERACTIVE CONSOLE\n" ++
                "  ────────────────────────────────────────────────────────────────────────────\n" ++
                "   [1] Audit Local Exposure       listeners, interfaces, open ports\n" ++
                "   [2] Test TCP Port Check        connect to host:port with a timeout\n" ++
                "   [3] Diagnose DNS Resolution    query A/AAAA records, check health\n" ++
                "   [4] Inspect Interfaces         local adapters, IPv4/IPv6 addresses\n" ++
                "   [5] Inspect Routing Table      routes and default gateway\n" ++
                "   [6] Evaluate Security Policy   offline hardening rules\n" ++
                "   [7] Run Practice Lab Drill     loopback-confined training scenario\n" ++
                "   [8] Capabilities Matrix        platform features and privileges\n" ++
                "   [0] Exit\n" ++
                "  ────────────────────────────────────────────────────────────────────────────\n" ++
                "  Select an option [0-8]: "
            ) catch return root.ExitCodes.operational_failure;
        }

        const choice = readLine(stdin, &stdin_buf) orelse break;

        if (std.mem.eql(u8, choice, "0") or std.mem.eql(u8, choice, "q") or std.mem.eql(u8, choice, "exit")) {
            stdout.print("\nGoodbye!\n", .{}) catch {};
            return root.ExitCodes.success;
        } else if (std.mem.eql(u8, choice, "1")) {
            stdout.print("\n>>> Running: wirescope audit local\n\n", .{}) catch {};
            _ = root.execute(&[_][]const u8{ "wirescope", "audit", "local" }, stdout, stderr);
        } else if (std.mem.eql(u8, choice, "2")) {
            stdout.print("\nEnter target host:port [default: 127.0.0.1:80]: ", .{}) catch {};
            var target_buf: [128]u8 = undefined;
            const target_input = readLine(stdin, &target_buf) orelse "127.0.0.1:80";
            const target = if (target_input.len == 0) "127.0.0.1:80" else target_input;
            stdout.print("\n>>> Running: wirescope diagnose tcp {s}\n\n", .{target}) catch {};
            _ = root.execute(&[_][]const u8{ "wirescope", "diagnose", "tcp", target }, stdout, stderr);
        } else if (std.mem.eql(u8, choice, "3")) {
            stdout.print("\nEnter target domain [default: localhost]: ", .{}) catch {};
            var domain_buf: [128]u8 = undefined;
            const domain_input = readLine(stdin, &domain_buf) orelse "localhost";
            const domain = if (domain_input.len == 0) "localhost" else domain_input;
            stdout.print("\n>>> Running: wirescope diagnose dns {s}\n\n", .{domain}) catch {};
            _ = root.execute(&[_][]const u8{ "wirescope", "diagnose", "dns", domain }, stdout, stderr);
        } else if (std.mem.eql(u8, choice, "4")) {
            stdout.print("\n>>> Running: wirescope diagnose interfaces\n\n", .{}) catch {};
            _ = root.execute(&[_][]const u8{ "wirescope", "diagnose", "interfaces" }, stdout, stderr);
        } else if (std.mem.eql(u8, choice, "5")) {
            stdout.print("\n>>> Running: wirescope diagnose routes\n\n", .{}) catch {};
            _ = root.execute(&[_][]const u8{ "wirescope", "diagnose", "routes" }, stdout, stderr);
        } else if (std.mem.eql(u8, choice, "6")) {
            stdout.print("\n>>> Running: wirescope policy check\n\n", .{}) catch {};
            _ = root.execute(&[_][]const u8{ "wirescope", "policy", "check" }, stdout, stderr);
        } else if (std.mem.eql(u8, choice, "7")) {
            stdout.print(
                \\Available Lab Scenarios:
                \\  [1] dns_failure                  (DNS NXDOMAIN vs Timeout Simulation)
                \\  [2] tcp_refusal_timeout          (TCP Connection Refusal & Bounded Timeout)
                \\  [3] unexpected_listener          (Listener Exposure vs Baseline Drift)
                \\  [4] http_security_header_violation (HTTP Header Policy Audit)
                \\Select scenario [1-4, default: 1]: 
            , .{}) catch {};
            var lab_buf: [64]u8 = undefined;
            const lab_input = readLine(stdin, &lab_buf) orelse "1";
            const scenario = if (std.mem.eql(u8, lab_input, "2"))
                "tcp_refusal_timeout"
            else if (std.mem.eql(u8, lab_input, "3"))
                "unexpected_listener"
            else if (std.mem.eql(u8, lab_input, "4"))
                "http_security_header_violation"
            else
                "dns_failure";

            stdout.print("\n>>> Running: wirescope lab run {s}\n\n", .{scenario}) catch {};
            _ = root.execute(&[_][]const u8{ "wirescope", "lab", "run", scenario }, stdout, stderr);
        } else if (std.mem.eql(u8, choice, "8")) {
            stdout.print("\n>>> Running: wirescope capabilities\n\n", .{}) catch {};
            _ = root.execute(&[_][]const u8{ "wirescope", "capabilities" }, stdout, stderr);
        } else {
            stdout.print("\nUnknown selection. Please choose a valid option (0-8).\n", .{}) catch {};
        }

        stdout.print("\nPress Enter to continue...", .{}) catch {};
        _ = readLine(stdin, &stdin_buf);
    }

    return root.ExitCodes.success;
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
