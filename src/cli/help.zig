const std = @import("std");
const testing = std.testing;
const theme = @import("theme.zig");
const Theme = theme.Theme;

pub fn printRootHelp(writer: anytype) !void {
    const use_color = Theme.shouldColorize(false);
    Theme.enableVirtualTerminal();

    try Theme.printBanner(writer, use_color);

    if (use_color) {
        try writer.writeAll(
            "\x1b[1;96mUSAGE:\x1b[0m\n" ++
            "  wirescope <command> [subcommand] [target] [options]\n\n" ++
            "\x1b[1;93mQUICK START (GUIDED MODE):\x1b[0m\n" ++
            "  \x1b[1;97mwirescope menu\x1b[0m              Launch guided interactive console\n\n" ++
            "\x1b[1;96mCORE COMMANDS:\x1b[0m\n" ++
            "  \x1b[1;97mdiagnose\x1b[0m     Run network diagnostics (dns, tcp, tls, interfaces, routes)\n" ++
            "  \x1b[1;97maudit\x1b[0m        Run defensive security audits (tls, http, local)\n" ++
            "  \x1b[1;97mpolicy\x1b[0m       Evaluate local security rules and exposure policies\n" ++
            "  \x1b[1;97mbaseline\x1b[0m     Manage and compare baseline state snapshots (save, diff)\n" ++
            "  \x1b[1;97mdiscover\x1b[0m     Perform bounded asset discovery within explicit scope\n" ++
            "  \x1b[1;97mlab\x1b[0m          Execute reproducible local practice lab scenarios\n" ++
            "  \x1b[1;97mhistory\x1b[0m      Query, inspect, compare, and prune assessment history\n" ++
            "  \x1b[1;97mmanifest\x1b[0m     Verify report artifact integrity manifests and detect tampering\n" ++
            "  \x1b[1;97mreport\x1b[0m       Generate, validate, and normalize versioned reports\n" ++
            "  \x1b[1;97mcapabilities\x1b[0m Inspect platform capabilities and supported features\n" ++
            "  \x1b[1;97mversion\x1b[0m      Display WireScope version and compiler information\n" ++
            "  \x1b[1;97mhelp\x1b[0m         Display help information for a command\n\n" ++
            "\x1b[1;96mGLOBAL OPTIONS:\x1b[0m\n" ++
            "  \x1b[94m-f, --format <term|json|md>\x1b[0m  Output format (default: terminal)\n" ++
            "  \x1b[94m-t, --timeout <ms>\x1b[0m           Operation timeout in milliseconds (default: 5000)\n" ++
            "  \x1b[94m-o, --output <path>\x1b[0m          Save output to explicit file path\n" ++
            "  \x1b[94m-y, --non-interactive\x1b[0m        Disable interactive confirmation prompts\n" ++
            "  \x1b[94m    --no-color\x1b[0m               Disable ANSI color output\n" ++
            "  \x1b[94m    --dry-run\x1b[0m                Preview assessment plan without network probes\n" ++
            "  \x1b[94m-h, --help\x1b[0m                   Show help for command\n" ++
            "  \x1b[94m-v, --version\x1b[0m                Show version information\n\n" ++
            "\x1b[1;96mEXAMPLES:\x1b[0m\n" ++
            "  \x1b[92m$\x1b[0m wirescope menu\n" ++
            "  \x1b[92m$\x1b[0m wirescope audit local\n" ++
            "  \x1b[92m$\x1b[0m wirescope diagnose tcp 127.0.0.1:8080 --timeout 2000\n" ++
            "  \x1b[92m$\x1b[0m wirescope diagnose dns example.com --format json\n" ++
            "  \x1b[92m$\x1b[0m wirescope policy check\n" ++
            "  \x1b[92m$\x1b[0m wirescope lab run dns_failure\n\n"
        );
    } else {
        try writer.print(
            \\Usage:
            \\  wirescope <command> [subcommand] [target] [options]
            \\
            \\Quick Start (Guided Mode):
            \\  wirescope menu              Launch guided interactive console
            \\
            \\Commands:
            \\  diagnose      Run network diagnostics (dns, tcp, tls, interfaces, routes)
            \\  audit         Run defensive security audits (tls, http, local)
            \\  policy        Evaluate local security rules and exposure policies
            \\  baseline      Manage and compare baseline state snapshots
            \\  discover      Perform bounded asset discovery within explicit scope
            \\  lab           Execute reproducible local practice lab scenarios
            \\  history       Query, inspect, compare, and prune assessment history
            \\  manifest      Verify report artifact integrity manifests and detect tampering
            \\  report        Generate, validate, and normalize versioned reports
            \\  capabilities  Inspect platform capabilities and supported features
            \\  version       Display WireScope version and compiler information
            \\  help          Display help information for a command
            \\
            \\Global Options:
            \\  -f, --format <term|json|md>  Output format (default: terminal)
            \\  -t, --timeout <ms>           Operation timeout in milliseconds (default: 5000)
            \\  -o, --output <path>          Save output to explicit file path
            \\  -y, --non-interactive        Disable interactive confirmation prompts
            \\      --no-color               Disable ANSI color output
            \\      --dry-run                Preview assessment plan without network probes
            \\  -h, --help                   Show help for command
            \\  -v, --version                Show version information
            \\
            \\Examples:
            \\  $ wirescope menu
            \\  $ wirescope audit local
            \\  $ wirescope diagnose tcp 127.0.0.1:8080 --timeout 2000
            \\  $ wirescope diagnose dns example.com --format json
            \\  $ wirescope policy check
            \\  $ wirescope lab run dns_failure
            \\
        , .{});
    }
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
            \\wirescope audit — Defensive Security Audits
            \\
            \\Usage:
            \\  wirescope audit <target_type> [target] [options]
            \\
            \\Audit Types:
            \\  local                   Audit local system listeners and exposure risks
            \\  http <url>              Audit HTTP security headers, TLS posture, and redirects
            \\  tls <host:port>         Audit TLS configuration against security policy
            \\
            \\Options:
            \\  -f, --format <format>   Output format: terminal, json, markdown
            \\  -o, --output <path>     Save audit results to file
            \\      --max-redirects <n> Maximum HTTP redirects to follow (default: 5)
            \\      --max-size <bytes>  Maximum HTTP response body size (default: 1 MB)
            \\
        , .{});
    } else if (std.mem.eql(u8, cmd, "discover")) {
        try writer.print(
            \\wirescope discover — Bounded Target Reconnaissance
            \\
            \\Usage:
            \\  wirescope discover <target_spec> [options]
            \\
            \\Target Specifications:
            \\  Single IP:              192.168.1.100
            \\  CIDR Range:             192.168.1.0/24 (prefixes between /24 and /32 only)
            \\  Hostname:               internal-host.local
            \\
            \\Options:
            \\  --ports <ports>         Target ports: single (80), list (80,443), range (80-90)
            \\  --exclude <targets>     Comma-separated IPs or subnets to strictly exclude
            \\  --confirm-authorized    Explicitly acknowledge authorization for remote targets
            \\  --preview               Preview assessment plan without network activity
            \\  --max-hosts <n>         Host cap (default: 256)
            \\  --max-ports <n>         Port cap (default: 100)
            \\  --max-operations <n>    Total operation cap (default: 5000)
            \\  --concurrency <n>       Concurrent probes (default: 4, max: 16)
            \\
            \\Safety Invariants:
            \\  - Loopback targets execute without authorization flag
            \\  - Remote targets require explicit --confirm-authorized
            \\  - Broad CIDRs (< /24) are prohibited
            \\
        , .{});
    } else if (std.mem.eql(u8, cmd, "baseline")) {
        try writer.print(
            \\wirescope baseline — Exposure Baseline Management & Drift Detection
            \\
            \\Usage:
            \\  wirescope baseline <action> [options]
            \\
            \\Actions:
            \\  save                    Capture current local listeners into baseline snapshot
            \\  diff                    Compare current state against saved baseline snapshot
            \\
            \\Options:
            \\  -o, --output <path>     Snapshot storage path (default: .wirescope/baseline.json)
            \\      --diff <path>       Compare against specific baseline snapshot file
            \\      --force             Overwrite existing baseline snapshot without prompting
            \\  -f, --format <format>   Output format: terminal, json, markdown
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
            \\Options:
            \\  -f, --format <format>   Output format: terminal, json, markdown
            \\  -p, --profile <path>    Custom security policy file path
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
    } else if (std.mem.eql(u8, cmd, "history")) {
        try writer.print(
            \\wirescope history — Assessment History Queries, Retention & Recovery
            \\
            \\Usage:
            \\  wirescope history <action> [target] [options]
            \\
            \\Actions:
            \\  list                    List historical assessment runs (default)
            \\  inspect <id>            Inspect a specific assessment record
            \\  compare <id1> <id2>     Compare two historical assessment runs
            \\  delete <id>             Delete an assessment record safely
            \\  prune                   Prune oldest assessment records according to retention policy
            \\  recover                 Recover from interrupted writes and clean up orphaned temporary files
            \\
            \\Options:
            \\  -f, --format <format>   Output format: terminal, json, markdown
            \\
        , .{});
    } else if (std.mem.eql(u8, cmd, "manifest")) {
        try writer.print(
            \\wirescope manifest — Report Artifact Integrity & Verification
            \\
            \\Usage:
            \\  wirescope manifest <action> [target] [options]
            \\
            \\Actions:
            \\  verify <manifest_path>  Verify report artifacts against cryptographic SHA-256 manifest
            \\  inspect <manifest_path> Inspect manifest metadata, referenced artifacts, and hashes
            \\
            \\Options:
            \\  -f, --format <format>   Output format: terminal, json, markdown
            \\
            \\Notice:
            \\  SHA-256 digests verify local integrity and detect modified/missing files.
            \\  A local hash alone does NOT prove author identity or protect against
            \\  an adversary with write access to both report and manifest.
            \\
        , .{});
    } else if (std.mem.eql(u8, cmd, "report")) {
        try writer.print(
            \\wirescope report — Assessment Reporting, Markdown & Terminal Generation
            \\
            \\Usage:
            \\  wirescope report <action> [target] [options]
            \\
            \\Actions:
            \\  validate <file.json>    Validate JSON report against versioned schema
            \\  normalize <file.json>   Normalize volatile fields in report for golden testing
            \\  markdown <file.json>    Render readable GitHub Flavored Markdown report
            \\  terminal <file.json>    Render formatted terminal summary report
            \\  export <file.json>      Export report in specified --format (terminal, json, markdown)
            \\
            \\Options:
            \\  -f, --format <format>   Output format: terminal, json, markdown
            \\  -o, --output <path>     Write output to specified file path (safe atomic write)
            \\      --force             Allow overwriting existing output file
            \\      --redact            Redact credentials and sensitive patterns
            \\
            \\Notes:
            \\  Redaction reduces report reproducibility during audit verification.
            \\  Observations are strictly distinguished from security findings.
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
