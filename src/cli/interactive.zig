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
        // Clear or print top header
        stdout.print("\n", .{}) catch return root.ExitCodes.operational_failure;
        Theme.printBanner(stdout, use_color) catch return root.ExitCodes.operational_failure;

        if (use_color) {
            stdout.writeAll(
                "\x1b[1;96m  WIRESCOPE INTERACTIVE CONSOLE\x1b[0m\n" ++
                "  \x1b[94m===================================================================\x1b[0m\n" ++
                "  \x1b[1m[1]\x1b[0m Audit Local Exposure       \x1b[90m(Listeners, interfaces, open ports)\x1b[0m\n" ++
                "  \x1b[1m[2]\x1b[0m Test TCP Port Check        \x1b[90m(Connect to host:port with bounded timeout)\x1b[0m\n" ++
                "  \x1b[1m[3]\x1b[0m Diagnose DNS Resolution    \x1b[90m(Query A/AAAA records & check DNS health)\x1b[0m\n" ++
                "  \x1b[1m[4]\x1b[0m Inspect Interfaces         \x1b[90m(List local adapters, IPv4/IPv6 addresses)\x1b[0m\n" ++
                "  \x1b[1m[5]\x1b[0m Inspect Routing Table      \x1b[90m(View network routes & default gateway)\x1b[0m\n" ++
                "  \x1b[1m[6]\x1b[0m Evaluate Security Policy   \x1b[90m(Run offline defense hardening rules)\x1b[0m\n" ++
                "  \x1b[1m[7]\x1b[0m Run Practice Lab Drill     \x1b[90m(Safe, loopback-confined training scenario)\x1b[0m\n" ++
                "  \x1b[1m[8]\x1b[0m Capabilities Matrix        \x1b[90m(Check platform features & privileges)\x1b[0m\n" ++
                "  \x1b[1m[0]\x1b[0m Exit\n" ++
                "  \x1b[94m===================================================================\x1b[0m\n" ++
                "  \x1b[1;97mSelect an option [0-8]:\x1b[0m "
            ) catch return root.ExitCodes.operational_failure;
        } else {
            stdout.writeAll(
                "  WIRESCOPE INTERACTIVE CONSOLE\n" ++
                "  ===================================================================\n" ++
                "  [1] Audit Local Exposure       (Listeners, interfaces, open ports)\n" ++
                "  [2] Test TCP Port Check        (Connect to host:port with bounded timeout)\n" ++
                "  [3] Diagnose DNS Resolution    (Query A/AAAA records & check DNS health)\n" ++
                "  [4] Inspect Interfaces         (List local adapters, IPv4/IPv6 addresses)\n" ++
                "  [5] Inspect Routing Table      (View network routes & default gateway)\n" ++
                "  [6] Evaluate Security Policy   (Run offline defense hardening rules)\n" ++
                "  [7] Run Practice Lab Drill     (Safe, loopback-confined training scenario)\n" ++
                "  [8] Capabilities Matrix        (Check platform features & privileges)\n" ++
                "  [0] Exit\n" ++
                "  ===================================================================\n" ++
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
