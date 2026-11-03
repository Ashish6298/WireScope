const std = @import("std");
const testing = std.testing;
const theme = @import("theme.zig");
const Theme = theme.Theme;

pub fn printHub(writer: anytype) !void {
    const use_color = Theme.shouldColorize(false);
    Theme.enableVirtualTerminal();

    try Theme.printBanner(writer, use_color);

    if (use_color) {
        try writer.writeAll(
            "  \x1b[1m\x1b[38;2;140;155;170mGET STARTED\x1b[0m\n\n" ++
            "    \x1b[38;2;70;80;92m$\x1b[0m \x1b[1m\x1b[38;2;205;212;220mwirescope menu\x1b[0m            \x1b[90mguided interactive console\x1b[0m\n" ++
            "    \x1b[38;2;70;80;92m$\x1b[0m \x1b[1m\x1b[38;2;205;212;220mwirescope audit local\x1b[0m     \x1b[90mcheck what this machine exposes\x1b[0m\n" ++
            "    \x1b[38;2;70;80;92m$\x1b[0m \x1b[1m\x1b[38;2;205;212;220mwirescope diagnose dns\x1b[0m example.com\n\n" ++
            "  \x1b[1m\x1b[38;2;140;155;170mWHAT IT DOES\x1b[0m\n\n" ++
            "    \x1b[38;2;140;155;170m▸\x1b[0m Diagnoses DNS, TCP, TLS, interfaces and routes\n" ++
            "    \x1b[38;2;140;155;170m▸\x1b[0m Audits local exposure and security policy, read-only\n" ++
            "    \x1b[38;2;140;155;170m▸\x1b[0m Saves baselines and reports you can verify later\n\n" ++
            "  \x1b[38;2;70;80;92m────────────────────────────────────────────────────────────────────────────\x1b[0m\n" ++
            "  \x1b[90mv1.0.0  ·  run \x1b[0m\x1b[1m\x1b[38;2;205;212;220mwirescope help\x1b[0m\x1b[90m for every command\x1b[0m\n\n"
        );
    } else {
        try writer.writeAll(
            "  GET STARTED\n\n" ++
            "    $ wirescope menu            guided interactive console\n" ++
            "    $ wirescope audit local     check what this machine exposes\n" ++
            "    $ wirescope diagnose dns example.com\n\n" ++
            "  WHAT IT DOES\n\n" ++
            "    ▸ Diagnoses DNS, TCP, TLS, interfaces and routes\n" ++
            "    ▸ Audits local exposure and security policy, read-only\n" ++
            "    ▸ Saves baselines and reports you can verify later\n\n" ++
            "  ────────────────────────────────────────────────────────────────────────────\n" ++
            "  v1.0.0  ·  run wirescope help for every command\n\n"
        );
    }
}

pub fn printRootHelp(writer: anytype) !void {
    const use_color = Theme.shouldColorize(false);
    Theme.enableVirtualTerminal();

    try Theme.printBanner(writer, use_color);

    if (use_color) {
        try writer.writeAll(
            "  \x1b[1m\x1b[38;2;205;212;220mwirescope\x1b[0m \x1b[38;2;140;155;170m<command>\x1b[0m \x1b[90m[subcommand] [target] [options]\x1b[0m\n" ++
            "\n" ++
            "  \x1b[38;2;70;80;92m╭─\x1b[0m \x1b[1m\x1b[38;2;140;155;170massess\x1b[0m \x1b[38;2;70;80;92m─────────────────────────────────────────────────────────────────╮\x1b[0m\n" ++
            "  \x1b[38;2;70;80;92m│\x1b[0m \x1b[1m\x1b[38;2;205;212;220mdiagnose      \x1b[0m\x1b[90mRun network diagnostics (dns, tcp, tls, interfaces, routes)\x1b[0m\x1b[38;2;70;80;92m│\x1b[0m\n" ++
            "  \x1b[38;2;70;80;92m│\x1b[0m \x1b[1m\x1b[38;2;205;212;220maudit         \x1b[0m\x1b[90mRun defensive security audits (tls, http, local)\x1b[0m           \x1b[38;2;70;80;92m│\x1b[0m\n" ++
            "  \x1b[38;2;70;80;92m│\x1b[0m \x1b[1m\x1b[38;2;205;212;220mpolicy        \x1b[0m\x1b[90mEvaluate local security rules and exposure policies\x1b[0m        \x1b[38;2;70;80;92m│\x1b[0m\n" ++
            "  \x1b[38;2;70;80;92m│\x1b[0m \x1b[1m\x1b[38;2;205;212;220mdiscover      \x1b[0m\x1b[90mBounded asset discovery within explicit scope\x1b[0m              \x1b[38;2;70;80;92m│\x1b[0m\n" ++
            "  \x1b[38;2;70;80;92m╰──────────────────────────────────────────────────────────────────────────╯\x1b[0m\n" ++
            "\n" ++
            "  \x1b[38;2;70;80;92m╭─\x1b[0m \x1b[1m\x1b[38;2;140;155;170mtrack\x1b[0m \x1b[38;2;70;80;92m──────────────────────────────────────────────────────────────────╮\x1b[0m\n" ++
            "  \x1b[38;2;70;80;92m│\x1b[0m \x1b[1m\x1b[38;2;205;212;220mbaseline      \x1b[0m\x1b[90mSave and compare baseline state snapshots\x1b[0m                  \x1b[38;2;70;80;92m│\x1b[0m\n" ++
            "  \x1b[38;2;70;80;92m│\x1b[0m \x1b[1m\x1b[38;2;205;212;220mhistory       \x1b[0m\x1b[90mQuery, inspect, compare and prune history\x1b[0m                  \x1b[38;2;70;80;92m│\x1b[0m\n" ++
            "  \x1b[38;2;70;80;92m│\x1b[0m \x1b[1m\x1b[38;2;205;212;220mmanifest      \x1b[0m\x1b[90mVerify report integrity manifests\x1b[0m                          \x1b[38;2;70;80;92m│\x1b[0m\n" ++
            "  \x1b[38;2;70;80;92m│\x1b[0m \x1b[1m\x1b[38;2;205;212;220mreport        \x1b[0m\x1b[90mGenerate, validate and normalize reports\x1b[0m                   \x1b[38;2;70;80;92m│\x1b[0m\n" ++
            "  \x1b[38;2;70;80;92m╰──────────────────────────────────────────────────────────────────────────╯\x1b[0m\n" ++
            "\n" ++
            "  \x1b[38;2;70;80;92m╭─\x1b[0m \x1b[1m\x1b[38;2;140;155;170mpractice\x1b[0m \x1b[38;2;70;80;92m───────────────────────────────────────────────────────────────╮\x1b[0m\n" ++
            "  \x1b[38;2;70;80;92m│\x1b[0m \x1b[1m\x1b[38;2;205;212;220mlab           \x1b[0m\x1b[90mRun reproducible local practice scenarios\x1b[0m                  \x1b[38;2;70;80;92m│\x1b[0m\n" ++
            "  \x1b[38;2;70;80;92m╰──────────────────────────────────────────────────────────────────────────╯\x1b[0m\n" ++
            "\n" ++
            "  \x1b[38;2;70;80;92m╭─\x1b[0m \x1b[1m\x1b[38;2;140;155;170msystem\x1b[0m \x1b[38;2;70;80;92m─────────────────────────────────────────────────────────────────╮\x1b[0m\n" ++
            "  \x1b[38;2;70;80;92m│\x1b[0m \x1b[1m\x1b[38;2;205;212;220mcapabilities  \x1b[0m\x1b[90mInspect platform capabilities\x1b[0m                              \x1b[38;2;70;80;92m│\x1b[0m\n" ++
            "  \x1b[38;2;70;80;92m│\x1b[0m \x1b[1m\x1b[38;2;205;212;220mversion       \x1b[0m\x1b[90mShow version and compiler information\x1b[0m                      \x1b[38;2;70;80;92m│\x1b[0m\n" ++
            "  \x1b[38;2;70;80;92m│\x1b[0m \x1b[1m\x1b[38;2;205;212;220mhelp          \x1b[0m\x1b[90mShow help for a command\x1b[0m                                    \x1b[38;2;70;80;92m│\x1b[0m\n" ++
            "  \x1b[38;2;70;80;92m╰──────────────────────────────────────────────────────────────────────────╯\x1b[0m\n" ++
            "\n" ++
            "  \x1b[38;2;70;80;92m╭─\x1b[0m \x1b[1m\x1b[38;2;140;155;170moptions\x1b[0m \x1b[38;2;70;80;92m────────────────────────────────────────────────────────────────╮\x1b[0m\n" ++
            "  \x1b[38;2;70;80;92m│\x1b[0m \x1b[38;2;140;155;170m-f, --format <term|json|md>   \x1b[0m\x1b[90mOutput format\x1b[0m                              \x1b[38;2;70;80;92m│\x1b[0m\n" ++
            "  \x1b[38;2;70;80;92m│\x1b[0m \x1b[38;2;140;155;170m-t, --timeout <ms>            \x1b[0m\x1b[90mOperation timeout (5000)\x1b[0m                   \x1b[38;2;70;80;92m│\x1b[0m\n" ++
            "  \x1b[38;2;70;80;92m│\x1b[0m \x1b[38;2;140;155;170m-o, --output <path>           \x1b[0m\x1b[90mSave output to a file\x1b[0m                      \x1b[38;2;70;80;92m│\x1b[0m\n" ++
            "  \x1b[38;2;70;80;92m│\x1b[0m \x1b[38;2;140;155;170m-y, --non-interactive         \x1b[0m\x1b[90mSkip confirmation prompts\x1b[0m                  \x1b[38;2;70;80;92m│\x1b[0m\n" ++
            "  \x1b[38;2;70;80;92m│\x1b[0m \x1b[38;2;140;155;170m    --no-color                \x1b[0m\x1b[90mDisable ANSI colors\x1b[0m                        \x1b[38;2;70;80;92m│\x1b[0m\n" ++
            "  \x1b[38;2;70;80;92m│\x1b[0m \x1b[38;2;140;155;170m    --dry-run                 \x1b[0m\x1b[90mPreview plan, no probes\x1b[0m                    \x1b[38;2;70;80;92m│\x1b[0m\n" ++
            "  \x1b[38;2;70;80;92m│\x1b[0m \x1b[38;2;140;155;170m-h, --help                    \x1b[0m\x1b[90mShow help\x1b[0m                                  \x1b[38;2;70;80;92m│\x1b[0m\n" ++
            "  \x1b[38;2;70;80;92m│\x1b[0m \x1b[38;2;140;155;170m-v, --version                 \x1b[0m\x1b[90mShow version\x1b[0m                               \x1b[38;2;70;80;92m│\x1b[0m\n" ++
            "  \x1b[38;2;70;80;92m╰──────────────────────────────────────────────────────────────────────────╯\x1b[0m\n" ++
            "\n" ++
            "  \x1b[90mStart here\x1b[0m  \x1b[1m\x1b[38;2;205;212;220mwirescope menu\x1b[0m\n"
        );
    } else {
        try writer.writeAll(
            "  wirescope <command> [subcommand] [target] [options]\n" ++
            "\n" ++
            "  ╭─ assess ─────────────────────────────────────────────────────────────────╮\n" ++
            "  │ diagnose      Run network diagnostics (dns, tcp, tls, interfaces, routes)│\n" ++
            "  │ audit         Run defensive security audits (tls, http, local)           │\n" ++
            "  │ policy        Evaluate local security rules and exposure policies        │\n" ++
            "  │ discover      Bounded asset discovery within explicit scope              │\n" ++
            "  ╰──────────────────────────────────────────────────────────────────────────╯\n" ++
            "\n" ++
            "  ╭─ track ──────────────────────────────────────────────────────────────────╮\n" ++
            "  │ baseline      Save and compare baseline state snapshots                  │\n" ++
            "  │ history       Query, inspect, compare and prune history                  │\n" ++
            "  │ manifest      Verify report integrity manifests                          │\n" ++
            "  │ report        Generate, validate and normalize reports                   │\n" ++
            "  ╰──────────────────────────────────────────────────────────────────────────╯\n" ++
            "\n" ++
            "  ╭─ practice ───────────────────────────────────────────────────────────────╮\n" ++
            "  │ lab           Run reproducible local practice scenarios                  │\n" ++
            "  ╰──────────────────────────────────────────────────────────────────────────╯\n" ++
            "\n" ++
            "  ╭─ system ─────────────────────────────────────────────────────────────────╮\n" ++
            "  │ capabilities  Inspect platform capabilities                              │\n" ++
            "  │ version       Show version and compiler information                      │\n" ++
            "  │ help          Show help for a command                                    │\n" ++
            "  ╰──────────────────────────────────────────────────────────────────────────╯\n" ++
            "\n" ++
            "  ╭─ options ────────────────────────────────────────────────────────────────╮\n" ++
            "  │ -f, --format <term|json|md>   Output format                              │\n" ++
            "  │ -t, --timeout <ms>            Operation timeout (5000)                   │\n" ++
            "  │ -o, --output <path>           Save output to a file                      │\n" ++
            "  │ -y, --non-interactive         Skip confirmation prompts                  │\n" ++
            "  │     --no-color                Disable ANSI colors                        │\n" ++
            "  │     --dry-run                 Preview plan, no probes                    │\n" ++
            "  │ -h, --help                    Show help                                  │\n" ++
            "  │ -v, --version                 Show version                               │\n" ++
            "  ╰──────────────────────────────────────────────────────────────────────────╯\n" ++
            "\n" ++
            "  Start here  wirescope menu\n"
        );
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
    var buf: [32768]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try printRootHelp(fbs.writer());
    try testing.expect(fbs.getWritten().len > 0);

    fbs.reset();
    try printHub(fbs.writer());
    try testing.expect(fbs.getWritten().len > 0);

    fbs.reset();
    try printSubcommandHelp(fbs.writer(), "diagnose");
    try testing.expect(fbs.getWritten().len > 0);

    fbs.reset();
    try printSubcommandHelp(fbs.writer(), "discover");
    try testing.expect(fbs.getWritten().len > 0);
}
