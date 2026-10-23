const std = @import("std");
const testing = std.testing;
const synthetic = @import("synthetic.zig");

pub const LAB_SCENARIO_SCHEMA_VERSION: u32 = 1;

pub const LabScenarioId = enum {
    dns_failure,
    tcp_refusal_timeout,
    tls_cert_issues,
    unexpected_listener,
    http_security_header_violation,
    remediation_verification,

    pub fn fromString(str: []const u8) ?LabScenarioId {
        if (std.mem.eql(u8, str, "dns_failure") or std.mem.eql(u8, str, "dns")) return .dns_failure;
        if (std.mem.eql(u8, str, "tcp_refusal_timeout") or std.mem.eql(u8, str, "tcp") or std.mem.eql(u8, str, "tcp_refusal")) return .tcp_refusal_timeout;
        if (std.mem.eql(u8, str, "tls_cert_issues") or std.mem.eql(u8, str, "tls") or std.mem.eql(u8, str, "cert_issues")) return .tls_cert_issues;
        if (std.mem.eql(u8, str, "unexpected_listener") or std.mem.eql(u8, str, "listener") or std.mem.eql(u8, str, "exposure")) return .unexpected_listener;
        if (std.mem.eql(u8, str, "http_security_header_violation") or std.mem.eql(u8, str, "http") or std.mem.eql(u8, str, "headers")) return .http_security_header_violation;
        if (std.mem.eql(u8, str, "remediation_verification") or std.mem.eql(u8, str, "remediation") or std.mem.eql(u8, str, "verify")) return .remediation_verification;
        return null;
    }

    pub fn asString(self: LabScenarioId) []const u8 {
        return switch (self) {
            .dns_failure => "dns_failure",
            .tcp_refusal_timeout => "tcp_refusal_timeout",
            .tls_cert_issues => "tls_cert_issues",
            .unexpected_listener => "unexpected_listener",
            .http_security_header_violation => "http_security_header_violation",
            .remediation_verification => "remediation_verification",
        };
    }
};

pub const ExpectedObservation = struct {
    kind: []const u8,
    target: []const u8,
    description: []const u8,
    expected_finding_id: ?[]const u8 = null,
};

pub const LabScenario = struct {
    id: LabScenarioId,
    id_str: []const u8,
    title: []const u8,
    category: []const u8,
    difficulty: []const u8,
    description: []const u8,
    objective: []const u8,
    instructions: []const []const u8,
    hints: []const []const u8,
    expected_observations: []const ExpectedObservation,
    verification_steps: []const []const u8,
    cleanup_strategy: []const u8,
    requires_service: bool = false,
    default_bind_ip: []const u8 = "127.0.0.1",
    default_port: u16 = 0, // 0 indicates ephemeral port
    target_synthetic: []const u8,
    is_synthetic: bool = true,
    schema_version: u32 = LAB_SCENARIO_SCHEMA_VERSION,
};

pub const SCENARIO_REGISTRY = [_]LabScenario{
    .{
        .id = .dns_failure,
        .id_str = "dns_failure",
        .title = "DNS Resolution No-Answer and Timeout Simulation",
        .category = "DNS Diagnostics",
        .difficulty = "Beginner",
        .description = "Simulate and diagnose DNS failure conditions (unresolvable synthetic domain names and simulated timeouts) without sending queries to external root servers.",
        .objective = "Practice identifying NXDOMAIN errors versus resolver timeouts and verifying deterministic query outcome classifications.",
        .instructions = &.{
            "Execute a diagnostic DNS query against the synthetic lab domain 'unresolvable-lab.test'.",
            "Observe the failure outcome and classify whether it is NXDOMAIN, No Answer, or Timeout.",
            "Run 'wirescope lab verify dns_failure' to evaluate your diagnostic output.",
        },
        .hints = &.{
            "RFC 6761 reserves '.test' for testing and will never resolve on public resolvers.",
            "Use '--format json' to inspect machine-readable failure details.",
        },
        .expected_observations = &.{
            .{
                .kind = "dns_nxdomain_or_timeout",
                .target = "unresolvable-lab.test",
                .description = "Simulated non-existent domain returns NXDOMAIN or unresolvable error code",
                .expected_finding_id = "WS-FINDING-DNS-FAILURE",
            },
        },
        .verification_steps = &.{
            "Verify that DNS query to synthetic test domain failed safely.",
            "Verify that no external root or public DNS resolver was contacted.",
            "Confirm that failure category is preserved in assessment record.",
        },
        .cleanup_strategy = "No persistent background listeners; cleans up temporary diagnostic records.",
        .requires_service = false,
        .target_synthetic = "unresolvable-lab.test",
    },
    .{
        .id = .tcp_refusal_timeout,
        .id_str = "tcp_refusal_timeout",
        .title = "TCP Connection Refusal and Bounded Timeout",
        .category = "TCP Probes",
        .difficulty = "Beginner",
        .description = "Distinguish active TCP RST/connection refusal on closed loopback ports from non-responding endpoints that cause bounded timeouts.",
        .objective = "Learn to reliably differentiate between 'Connection Refused' (service down/closed port) and 'Connection Timeout' (silent drop/unreachable).",
        .instructions = &.{
            "Set up the scenario to allocate a closed loopback test endpoint.",
            "Run a TCP diagnostic probe against '127.0.0.1:<port>'.",
            "Verify that the outcome is classified as 'refusal' rather than 'timeout'.",
        },
        .hints = &.{
            "Loopback OS sockets return WSAECONNREFUSED / ECONNREFUSED almost instantaneously.",
            "Do not confuse TCP connect latency with ICMP ping.",
        },
        .expected_observations = &.{
            .{
                .kind = "tcp_refusal",
                .target = "127.0.0.1:0",
                .description = "Connection refused error on closed loopback port",
                .expected_finding_id = "WS-FINDING-TCP-REFUSAL",
            },
        },
        .verification_steps = &.{
            "Check that socket connection attempt terminated within bounded timeout.",
            "Ensure refusal outcome category matches the OS socket error.",
            "Confirm no public endpoints were touched.",
        },
        .cleanup_strategy = "Releases ephemeral loopback port and resets active state.",
        .requires_service = false,
        .target_synthetic = "127.0.0.1:0",
    },
    .{
        .id = .tls_cert_issues,
        .id_str = "tls_cert_issues",
        .title = "TLS Certificate Expiry and Hostname Mismatch",
        .category = "TLS & HTTPS",
        .difficulty = "Intermediate",
        .description = "Evaluate simulated TLS certificate anomalies using isolated synthetic fixtures without altering system-wide trust stores.",
        .objective = "Detect expired certificates and SAN (Subject Alternative Name) hostname mismatches and generate structured findings.",
        .instructions = &.{
            "Start the TLS lab service using 'wirescope lab setup tls_cert_issues'.",
            "Diagnose the loopback HTTPS/TLS endpoint on the allocated port.",
            "Inspect the finding explaining the hostname mismatch or expiration.",
            "Verify your findings with 'wirescope lab verify tls_cert_issues'.",
        },
        .hints = &.{
            "WireScope does not silently disable certificate verification in diagnostic mode.",
            "Compare the requested SNI hostname against the certificate's SAN extension.",
        },
        .expected_observations = &.{
            .{
                .kind = "tls_hostname_mismatch",
                .target = "https://127.0.0.1:0",
                .description = "Target certificate SAN does not match requested loopback host",
                .expected_finding_id = "WS-FINDING-TLS-SAN-MISMATCH",
            },
        },
        .verification_steps = &.{
            "Verify detection of TLS certificate SAN mismatch or expiration.",
            "Ensure trust store was not permanently modified.",
        },
        .cleanup_strategy = "Terminates loopback TLS mock service and cleans isolated cert files.",
        .requires_service = true,
        .target_synthetic = "https://127.0.0.1:0",
    },
    .{
        .id = .unexpected_listener,
        .id_str = "unexpected_listener",
        .title = "Unexpected Local Listener Exposure versus Baseline",
        .category = "Defensive Exposure",
        .difficulty = "Intermediate",
        .description = "Spawn a controlled loopback listener and compare local listening service inventory against an approved baseline.",
        .objective = "Detect unexpected open ports and newly introduced listening daemons using deterministic baseline diffing.",
        .instructions = &.{
            "Establish an initial exposure baseline of approved local listening services.",
            "Activate the scenario listener with 'wirescope lab setup unexpected_listener'.",
            "Perform an exposure audit and generate a baseline comparison diff.",
            "Confirm that the newly exposed port is flagged as an unexpected listener.",
        },
        .hints = &.{
            "Use 'wirescope baseline' to capture and compare local listener sets.",
            "Notice that loopback listeners present less external exposure than wildcard listeners.",
        },
        .expected_observations = &.{
            .{
                .kind = "unexpected_listener_detected",
                .target = "127.0.0.1:0",
                .description = "Listening port observed that was absent in baseline",
                .expected_finding_id = "WS-FINDING-LISTENER-UNAPPROVED",
            },
        },
        .verification_steps = &.{
            "Detect new listener present in current state but absent in baseline.",
            "Verify that diff identifies the port and protocol accurately.",
        },
        .cleanup_strategy = "Closes loopback listener socket and deletes temporary scenario baseline.",
        .requires_service = true,
        .target_synthetic = "127.0.0.1:0",
    },
    .{
        .id = .http_security_header_violation,
        .id_str = "http_security_header_violation",
        .title = "HTTP Security Header Policy Violation",
        .category = "Defensive Audits",
        .difficulty = "Beginner",
        .description = "Audit an active loopback HTTP service missing required defensive headers (HSTS, CSP, X-Frame-Options) and evaluate against security policy.",
        .objective = "Identify missing HTTP defensive security headers and generate policy failure reports without accessing external servers.",
        .instructions = &.{
            "Launch the mock HTTP service using 'wirescope lab setup http_security_header_violation'.",
            "Run an HTTP audit against the assigned loopback endpoint.",
            "Evaluate observations against the default security policy.",
            "Observe the policy failure outcomes for missing CSP and HSTS.",
        },
        .hints = &.{
            "Review the default security policy rules for HTTP headers.",
            "Use 'wirescope audit http http://127.0.0.1:<port>' to collect headers.",
        },
        .expected_observations = &.{
            .{
                .kind = "missing_csp_and_hsts",
                .target = "http://127.0.0.1:0",
                .description = "Response missing Content-Security-Policy and HSTS headers",
                .expected_finding_id = "WS-FINDING-HTTP-MISSING-SECURITY-HEADERS",
            },
        },
        .verification_steps = &.{
            "Check that HTTP audit captured available response headers safely.",
            "Confirm policy evaluation flagged missing headers as policy failures.",
        },
        .cleanup_strategy = "Terminates mock loopback HTTP listener and clears runtime state.",
        .requires_service = true,
        .target_synthetic = "http://127.0.0.1:0",
    },
    .{
        .id = .remediation_verification,
        .id_str = "remediation_verification",
        .title = "Defensive Remediation and Diff Verification",
        .category = "Remediation & Diffing",
        .difficulty = "Advanced",
        .description = "Remediate a non-compliant service configuration (e.g. inject security headers and restrict binding) and verify compliance in a second assessment.",
        .objective = "Demonstrate closed-loop security posture improvement by capturing before-and-after assessments and validating remediation resolution.",
        .instructions = &.{
            "Setup the initial vulnerable service state.",
            "Run baseline assessment capturing the initial findings.",
            "Apply the lab remediation to harden the loopback service configuration.",
            "Run a second assessment and verify that the diff confirms remediation.",
        },
        .hints = &.{
            "A successful remediation resolves previously flagged findings in subsequent diffs.",
            "Check both policy evaluation pass status and finding resolution history.",
        },
        .expected_observations = &.{
            .{
                .kind = "remediation_success",
                .target = "http://127.0.0.1:0",
                .description = "Remediated service satisfies policy and shows zero new findings",
                .expected_finding_id = null,
            },
        },
        .verification_steps = &.{
            "Verify that post-remediation assessment passes all policy checks.",
            "Verify that diff against prior baseline marks initial findings as resolved.",
        },
        .cleanup_strategy = "Shuts down remediated service, resets baseline, and removes lab artifacts.",
        .requires_service = true,
        .target_synthetic = "http://127.0.0.1:0",
    },
};

pub fn getAllScenarios() []const LabScenario {
    return &SCENARIO_REGISTRY;
}

pub fn findScenario(id_str: []const u8) ?LabScenario {
    for (SCENARIO_REGISTRY) |scenario| {
        if (std.mem.eql(u8, scenario.id_str, id_str) or
            std.mem.eql(u8, @tagName(scenario.id), id_str))
        {
            return scenario;
        }
    }
    // Also check aliases via LabScenarioId
    if (LabScenarioId.fromString(id_str)) |id| {
        for (SCENARIO_REGISTRY) |scenario| {
            if (scenario.id == id) return scenario;
        }
    }
    return null;
}

pub fn formatScenarioTerminal(scenario: LabScenario, writer: anytype) !void {
    try writer.print("\n=== WireScope Practice Lab Scenario: {s} ===\n", .{scenario.title});
    try writer.print("ID:           {s}\n", .{scenario.id_str});
    try writer.print("Category:     {s}\n", .{scenario.category});
    try writer.print("Difficulty:   {s}\n", .{scenario.difficulty});
    try writer.print("Synthetic:    {s} (Loopback/Isolated)\n", .{synthetic.SYNTHETIC_DATA_BADGE});
    try writer.print("Schema Ver:   v{d}\n", .{scenario.schema_version});
    try writer.print("\nObjective:\n  {s}\n", .{scenario.objective});
    try writer.print("\nDescription:\n  {s}\n", .{scenario.description});

    try writer.print("\nStep-by-Step Instructions:\n", .{});
    for (scenario.instructions, 1..) |inst, i| {
        try writer.print("  {d}. {s}\n", .{ i, inst });
    }

    try writer.print("\nDiagnostic Hints:\n", .{});
    for (scenario.hints) |hint| {
        try writer.print("  * {s}\n", .{hint});
    }

    try writer.print("\nExpected Evidence / Observations:\n", .{});
    for (scenario.expected_observations) |obs| {
        try writer.print("  - Kind:   {s}\n", .{obs.kind});
        try writer.print("    Target: {s}\n", .{obs.target});
        try writer.print("    Detail: {s}\n", .{obs.description});
        if (obs.expected_finding_id) |fid| {
            try writer.print("    Expected Finding: {s}\n", .{fid});
        }
    }

    try writer.print("\nVerification Criteria:\n", .{});
    for (scenario.verification_steps) |step| {
        try writer.print("  [x] {s}\n", .{step});
    }

    try writer.print("\nCleanup Strategy:\n  {s}\n", .{scenario.cleanup_strategy});
    try writer.print("\nNote: {s}\n\n", .{synthetic.SYNTHETIC_ORIGIN_NOTICE});
}

pub fn formatScenarioMarkdown(scenario: LabScenario, writer: anytype) !void {
    try writer.print("# Practice Lab Scenario: {s}\n\n", .{scenario.title});
    try writer.print("> **Synthetic Status**: `{s}` — All fixtures and network targets are strictly loopback/isolated.\n\n", .{synthetic.SYNTHETIC_DATA_BADGE});
    try writer.print("| Metadata | Value |\n|---|---|\n", .{});
    try writer.print("| **Scenario ID** | `{s}` |\n", .{scenario.id_str});
    try writer.print("| **Category** | {s} |\n", .{scenario.category});
    try writer.print("| **Difficulty** | {s} |\n", .{scenario.difficulty});
    try writer.print("| **Schema Version** | v{d} |\n", .{scenario.schema_version});
    try writer.print("| **Synthetic Provenance** | `{s}` |\n\n", .{synthetic.SYNTHETIC_PROVENANCE});

    try writer.print("## Objective\n{s}\n\n", .{scenario.objective});
    try writer.print("## Description\n{s}\n\n", .{scenario.description});

    try writer.print("## Step-by-Step Instructions\n", .{});
    for (scenario.instructions, 1..) |inst, i| {
        try writer.print("{d}. {s}\n", .{ i, inst });
    }

    try writer.print("\n## Diagnostic Hints\n", .{});
    for (scenario.hints) |hint| {
        try writer.print("- {s}\n", .{hint});
    }

    try writer.print("\n## Expected Observations\n", .{});
    for (scenario.expected_observations) |obs| {
        try writer.print("- **{s}** on `{s}`: {s}\n", .{ obs.kind, obs.target, obs.description });
    }

    try writer.print("\n## Verification Criteria\n", .{});
    for (scenario.verification_steps) |step| {
        try writer.print("- [ ] {s}\n", .{step});
    }

    try writer.print("\n## Cleanup Strategy\n{s}\n\n", .{scenario.cleanup_strategy});
    try writer.print("> [!NOTE]\n> {s}\n", .{synthetic.SYNTHETIC_ORIGIN_NOTICE});
}

pub fn formatScenarioJson(scenario: LabScenario, writer: anytype) !void {
    try writer.print(
        \\{{
        \\  "schema_version": {d},
        \\  "is_synthetic": true,
        \\  "provenance": "{s}",
        \\  "id": "{s}",
        \\  "title": "{s}",
        \\  "category": "{s}",
        \\  "difficulty": "{s}",
        \\  "description": "{s}",
        \\  "objective": "{s}",
        \\  "target_synthetic": "{s}",
        \\  "requires_service": {s},
        \\  "instructions": [
    , .{
        scenario.schema_version,
        synthetic.SYNTHETIC_PROVENANCE,
        scenario.id_str,
        scenario.title,
        scenario.category,
        scenario.difficulty,
        scenario.description,
        scenario.objective,
        scenario.target_synthetic,
        if (scenario.requires_service) "true" else "false",
    });

    for (scenario.instructions, 0..) |inst, i| {
        try writer.print("    \"{s}\"{s}\n", .{ inst, if (i + 1 < scenario.instructions.len) "," else "" });
    }

    try writer.print(
        \\  ],
        \\  "hints": [
    , .{});

    for (scenario.hints, 0..) |hint, i| {
        try writer.print("    \"{s}\"{s}\n", .{ hint, if (i + 1 < scenario.hints.len) "," else "" });
    }

    try writer.print(
        \\  ],
        \\  "expected_observations": [
    , .{});

    for (scenario.expected_observations, 0..) |obs, i| {
        try writer.print(
            \\    {{
            \\      "kind": "{s}",
            \\      "target": "{s}",
            \\      "description": "{s}",
            \\      "expected_finding_id": {s}
            \\    }}{s}
            \\
        , .{
            obs.kind,
            obs.target,
            obs.description,
            if (obs.expected_finding_id) |fid| fid else "null",
            if (i + 1 < scenario.expected_observations.len) "," else "",
        });
    }

    try writer.print(
        \\  ],
        \\  "cleanup_strategy": "{s}"
        \\}}
        \\
    , .{scenario.cleanup_strategy});
}

pub fn formatScenarioListTerminal(writer: anytype) !void {
    try writer.print("\n=== WireScope Practice Lab Exercises ({s}) ===\n", .{synthetic.SYNTHETIC_DATA_BADGE});
    try writer.print("{s:<28} {s:<22} {s:<14} {s}\n", .{ "Scenario ID", "Category", "Difficulty", "Title" });
    try writer.print("{s:-<28} {s:-<22} {s:-<14} {s:-<30}\n", .{ "", "", "", "" });

    for (SCENARIO_REGISTRY) |scenario| {
        try writer.print("{s:<28} {s:<22} {s:<14} {s}\n", .{
            scenario.id_str,
            scenario.category,
            scenario.difficulty,
            scenario.title,
        });
    }
    try writer.print("\nRun 'wirescope lab inspect <id>' for full scenario details and setup instructions.\n\n", .{});
}

pub fn formatScenarioListMarkdown(writer: anytype) !void {
    try writer.print("# WireScope Practice Lab Scenarios\n\n", .{});
    try writer.print("> All exercises operate strictly in local/loopback isolation (`{s}`).\n\n", .{synthetic.SYNTHETIC_DATA_BADGE});
    try writer.print("| Scenario ID | Category | Difficulty | Title |\n|---|---|---|---|\n", .{});

    for (SCENARIO_REGISTRY) |scenario| {
        try writer.print("| `{s}` | {s} | {s} | {s} |\n", .{
            scenario.id_str,
            scenario.category,
            scenario.difficulty,
            scenario.title,
        });
    }
}

pub fn formatScenarioListJson(writer: anytype) !void {
    try writer.print(
        \\{{
        \\  "schema_version": {d},
        \\  "is_synthetic": true,
        \\  "provenance": "{s}",
        \\  "scenarios": [
        \\
    , .{ LAB_SCENARIO_SCHEMA_VERSION, synthetic.SYNTHETIC_PROVENANCE });

    for (SCENARIO_REGISTRY, 0..) |scenario, i| {
        try writer.print(
            \\    {{
            \\      "id": "{s}",
            \\      "title": "{s}",
            \\      "category": "{s}",
            \\      "difficulty": "{s}",
            \\      "requires_service": {s},
            \\      "target_synthetic": "{s}"
            \\    }}{s}
            \\
        , .{
            scenario.id_str,
            scenario.title,
            scenario.category,
            scenario.difficulty,
            if (scenario.requires_service) "true" else "false",
            scenario.target_synthetic,
            if (i + 1 < SCENARIO_REGISTRY.len) "," else "",
        });
    }

    try writer.print(
        \\  ]
        \\}}
        \\
    , .{});
}

test "scenario: registry contains exactly 6 scenarios" {
    const list = getAllScenarios();
    try testing.expectEqual(@as(usize, 6), list.len);
}

test "scenario: findScenario resolves by string and alias" {
    try testing.expect(findScenario("dns_failure") != null);
    try testing.expect(findScenario("dns") != null);
    try testing.expect(findScenario("tcp_refusal_timeout") != null);
    try testing.expect(findScenario("tcp") != null);
    try testing.expect(findScenario("tls_cert_issues") != null);
    try testing.expect(findScenario("unexpected_listener") != null);
    try testing.expect(findScenario("http_security_header_violation") != null);
    try testing.expect(findScenario("remediation_verification") != null);
    try testing.expect(findScenario("non_existent_scenario") == null);
}

test "scenario: format functions output valid text" {
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    const s = findScenario("dns_failure").?;
    try formatScenarioJson(s, fbs.writer());
    try testing.expect(fbs.getWritten().len > 0);
    try testing.expect(std.mem.indexOf(u8, fbs.getWritten(), "dns_failure") != null);
}
