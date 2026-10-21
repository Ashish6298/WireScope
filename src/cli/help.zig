const std = @import("std");
const testing = std.testing;

pub fn printRootHelp(writer: anytype) !void {
    try writer.print(
        \\WireScope — Local-First Network Diagnostics and Defensive Toolkit
        \\
        \\Usage:
        \\  wirescope <command> [subcommand] [target] [options]
        \\
        \\Commands:
        \\  diagnose      Run network diagnostics (dns, tcp, tls, interfaces, routes)
        \\  audit         Run defensive security audits (tls, http, local)
        \\  discover      Perform bounded asset discovery within explicit scope
        \\  baseline      Manage and compare baseline state snapshots
        \\  policy        Evaluate local security rules and exposure policies
        \\  lab           Execute reproducible local practice lab scenarios
        \\  capabilities  Inspect platform capabilities and supported features
        \\  version       Display WireScope version and compiler information
        \\  help          Display help information for a command
        \\
        \\Global Options:
        \\  -f, --format <term|json|md>  Output format (default: terminal)
        \\  -t, --timeout <ms>           Operation timeout in milliseconds (default: 5000)
        \\  -o, --output <path>          Save output to explicit file path
        \\  -y, --non-interactive        Disable interactive confirmation prompts
        \\      --dry-run                Preview assessment plan without sending network probes
        \\  -h, --help                   Show help for command
        \\  -v, --version                Show version information
        \\
        \\Examples:
        \\  wirescope diagnose dns example.com --format json
        \\  wirescope diagnose tcp 127.0.0.1:8080 --timeout 2000
        \\  wirescope audit http https://localhost:8443
        \\  wirescope capabilities --format json
        \\  wirescope lab run dns_failure
        \\
    , .{});
}

pub fn printSubcommandHelp(writer: anytype, cmd: []const u8) !void {
    if (std.mem.eql(u8, cmd, "diagnose")) {
        try writer.print(
            \\wirescope diagnose — Network Connectivity & Diagnostics
            \\
            \\Usage:
            \\  wirescope diagnose <subcommand> [target] [options]
            \\
            \\Subcommands:
            \\  dns <hostname>          Resolve DNS records and classify resolution outcomes
            \\  tcp <host:port>         Test TCP connection timing and refusal vs timeout
            \\  latency <host:port>     Measure repeated sample timings and compute jitter/percentiles
            \\  tls <host:port>         Validate TLS certificate chain and hostname match
            \\  interfaces              Enumerate local network interfaces and addresses
            \\  routes                  Inspect local routing table and default gateway
            \\
        , .{});
    } else if (std.mem.eql(u8, cmd, "audit")) {
        try writer.print(
            \\wirescope audit — Defensive Security Configuration Audits
            \\
            \\Usage:
            \\  wirescope audit <subcommand> [target] [options]
            \\
            \\Subcommands:
            \\  http <url>              Audit HTTP security headers (HSTS, CSP, Cookies, CORS)
            \\  tls <host:port>         Audit TLS configuration and certificate expiry
            \\  local                   Audit local listening ports for unexpected wildcard exposure
            \\
        , .{});
    } else if (std.mem.eql(u8, cmd, "discover")) {
        try writer.print(
            \\wirescope discover — Authorized Bounded Asset Reconnaissance
            \\
            \\Usage:
            \\  wirescope discover <cidr|range> --ports <ports> [options]
            \\
            \\Options:
            \\  --dry-run               Preview target operation counts before executing probes
            \\  -t, --timeout <ms>      Per-probe timeout
            \\
        , .{});
    } else if (std.mem.eql(u8, cmd, "baseline")) {
        try writer.print(
            \\wirescope baseline — Baseline Snapshot Management & Diffs
            \\
            \\Usage:
            \\  wirescope baseline <action> [options]
            \\
            \\Actions:
            \\  save <name>             Save current assessment as baseline snapshot
            \\  diff <name>             Compare current observations against named baseline
            \\  list                    List stored baseline snapshots
            \\
        , .{});
    } else if (std.mem.eql(u8, cmd, "policy")) {
        try writer.print(
            \\wirescope policy — Versioned Local Rules & Policy Engine
            \\
            \\Usage:
            \\  wirescope policy <action> [options]
            \\
            \\Actions:
            \\  check                   Evaluate local policy against current or saved observations
            \\  list                    List available built-in policy rules
            \\
        , .{});
    } else if (std.mem.eql(u8, cmd, "lab")) {
        try writer.print(
            \\wirescope lab — Isolated Practice Lab Exercises
            \\
            \\Usage:
            \\  wirescope lab <action> [scenario_id] [options]
            \\
            \\Actions:
            \\  list                    List available local practice exercises
            \\  run <scenario>          Start isolated loopback exercise (e.g. dns_failure, tcp_refusal)
            \\  verify <scenario>       Verify remediation outcome
            \\  cleanup                 Clean up any active lab loopback listeners
            \\
        , .{});
    } else {
        try printRootHelp(writer);
    }
}

test "help output prints without error" {
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try printRootHelp(fbs.writer());
    try testing.expect(fbs.getWritten().len > 0);

    fbs.reset();
    try printSubcommandHelp(fbs.writer(), "diagnose");
    try testing.expect(fbs.getWritten().len > 0);
}
