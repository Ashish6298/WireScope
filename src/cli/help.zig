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
        \\  wirescope discover 127.0.0.1 --ports 80,443 --preview
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
    } else if (std.mem.eql(u8, cmd, "tls")) {
        try writer.print(
            \\wirescope tls — TLS Certificate & Hostname Validation Probe
            \\
            \\Usage:
            \\  wirescope tls <target> [port] [options]
            \\
            \\Options:
            \\  --ca-bundle <path>      Custom trusted Certificate Authority (CA) bundle PEM file
            \\  --insecure              Explicitly bypass certificate chain and hostname verification
            \\  --server-name <sni>     Override Server Name Indication (SNI)
            \\  -t, --timeout <ms>      Handshake timeout in milliseconds (default: 5000)
            \\  -f, --format <format>   Output format: terminal, json, markdown
            \\
        , .{});
    } else if (std.mem.eql(u8, cmd, "https") or std.mem.eql(u8, cmd, "http")) {
        try writer.print(
            \\wirescope https — HTTPS Timing and Bounded Response Diagnostics
            \\
            \\Usage:
            \\  wirescope https <url> [options]
            \\
            \\Options:
            \\  --max-redirects <n>             Maximum redirect hops to follow (default: 5)
            \\  --max-response-size <bytes>     Maximum response size bound in bytes (default: 1048576)
            \\  --allow-redirect-scope-expansion Allow redirects to follow destinations outside initial host
            \\  --ca-bundle <path>              Custom trusted Certificate Authority (CA) bundle PEM file
            \\  --insecure                      Explicitly bypass TLS certificate and hostname verification
            \\  -t, --timeout <ms>              Total operation timeout in milliseconds (default: 5000)
            \\  -f, --format <format>           Output format: terminal, json, markdown
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
            \\  rules                   List versioned defensive rules and CVE disclaimer
            \\
            \\Options (audit http):
            \\  --max-redirects <n>             Maximum redirect hops to follow (default: 5)
            \\  --max-response-size <bytes>     Maximum response size bound in bytes (default: 1048576)
            \\  --allow-redirect-scope-expansion Allow redirects to follow destinations outside initial host
            \\  --ca-bundle <path>              Custom trusted Certificate Authority (CA) bundle PEM file
            \\  --insecure                      Explicitly bypass TLS certificate and hostname verification
            \\  -t, --timeout <ms>              Total operation timeout in milliseconds (default: 5000)
            \\  -f, --format <format>           Output format: terminal, json, markdown
            \\
        , .{});
    } else if (std.mem.eql(u8, cmd, "discover")) {
        try writer.print(
            \\wirescope discover — Authorized Bounded Asset Reconnaissance & Scope Preview
            \\
            \\Usage:
            \\  wirescope discover <target|cidr> [options]
            \\
            \\Options:
            \\  --ports <ports>         Target ports or ranges (e.g. '80,443' or '80-85')
            \\  --exclude <targets>     Target IPs, hostnames, or CIDRs to exclude
            \\  --confirm-authorized    Acknowledge explicit authorization for remote non-loopback targets
            \\  --preview, --dry-run    Display planned host/port/check operation count without executing
            \\  --max-hosts <n>         Maximum host cap (default: 256)
            \\  --max-ports <n>         Maximum port cap (default: 100)
            \\  --max-operations <n>    Maximum total operations cap (default: 5000)
            \\  -t, --timeout <ms>      Per-operation probe timeout in milliseconds (default: 5000)
            \\  -f, --format <format>   Output format: terminal, json, markdown
            \\
            \\Disclaimer:
            \\  WireScope cannot verify legal permission or ownership; operators bear sole
            \\  legal responsibility for ensuring explicit written authorization before assessing remote targets.
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
    } else if (std.mem.eql(u8, cmd, "assess") or std.mem.eql(u8, cmd, "assessment")) {
        try writer.print(
            \\wirescope assess — Multi-Module Assessment Runner & Orchestration
            \\
            \\Usage:
            \\  wirescope assess [profile_id] [options]
            \\
            \\Profiles:
            \\  loopback-diagnostics    Safe local loopback diagnostic checks for DNS, TCP, and listeners
            \\  local-security-audit    Defensive inspection of local listeners and HTTP security headers
            \\
            \\Options:
            \\  -p, --profile <id|path> Assessment profile to execute (default: loopback-diagnostics)
            \\  --confirm-authorized    Explicitly acknowledge authorization for remote targets
            \\  --preview, --dry-run    Preview planned execution tasks without network activity
            \\  -t, --timeout <ms>      Per-operation probe timeout in milliseconds
            \\  -f, --format <format>   Output format: terminal, json, markdown
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
    var buf: [4096]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try printRootHelp(fbs.writer());
    try testing.expect(fbs.getWritten().len > 0);

    fbs.reset();
    try printSubcommandHelp(fbs.writer(), "diagnose");
    try testing.expect(fbs.getWritten().len > 0);

    fbs.reset();
    try printSubcommandHelp(fbs.writer(), "discover");
    try testing.expect(fbs.getWritten().len > 0);
}
