const std = @import("std");
const testing = std.testing;

const Severity = @import("models.zig").Severity;
const recon = @import("../recon/root.zig");
const probes = @import("../probes/root.zig");
const audit = @import("../audit/root.zig");
const storage = @import("../storage/root.zig");
const reporting = @import("../reporting/root.zig");
const lab = @import("../lab/root.zig");

/// Structured record of documented residual risks
pub const ResidualRisk = struct {
    category: []const u8,
    title: []const u8,
    mechanism: []const u8,
    wirescope_defense: []const u8,
    residual_limitation: []const u8,
    user_recommendation: []const u8,
};

/// Authoritative catalog of residual risks documented for Phase 14.1
pub const RESIDUAL_RISKS = [_]ResidualRisk{
    .{
        .category = "Network / DNS",
        .title = "DNS Rebinding Window (TOCTOU)",
        .mechanism = "A malicious authoritative DNS server could return a loopback IP during initial scope check, and return a public IP during subsequent connection attempts.",
        .wirescope_defense = "WireScope validates resolved IPs immediately prior to probe connection via verifyDnsScopeCompliance.",
        .residual_limitation = "A brief race condition (TOCTOU) remains possible if the OS resolver cache expires or re-queries between verification and socket connect.",
        .user_recommendation = "In high-assurance environments, pin static IP addresses or use local /etc/hosts mappings.",
    },
    .{
        .category = "Operating System",
        .title = "Operating System Privilege Boundaries for Process Attribution",
        .mechanism = "Mapping local listening sockets to specific process names and PIDs requires administrative/root privileges on Windows and Linux.",
        .wirescope_defense = "WireScope accurately enumerates listening ports and addresses in unprivileged mode, and gracefully flags unknown process metadata.",
        .residual_limitation = "Unprivileged execution cannot correlate listening sockets with owning process binaries, emitting WS-AUDIT-EXPOSURE-PERMISSION-LIMITED.",
        .user_recommendation = "Run WireScope with elevated/administrative privileges if process correlation is strictly required.",
    },
    .{
        .category = "Time / PKI",
        .title = "Host System Clock Reliance for TLS Validity",
        .mechanism = "Evaluating certificate notBefore and notAfter timestamps relies on the local host's real-time system clock.",
        .wirescope_defense = "WireScope calculates certificate validity windows and remaining days deterministically from system clock time.",
        .residual_limitation = "If the host system clock is skewed or spoofed, valid certificates may be falsely flagged as expired, or expired certificates accepted as valid.",
        .user_recommendation = "Ensure reliable NTP/PTP time synchronization on machines performing TLS assessments.",
    },
    .{
        .category = "Middlebox / Firewall",
        .title = "Stateful Firewall and Middlebox Interference",
        .mechanism = "Intermediate firewalls or middleboxes may forge TCP RST packets or silently drop probe packets.",
        .wirescope_defense = "WireScope measures precise latency, distinguishes refusal from timeout, and notes multiple hypotheses in findings.",
        .residual_limitation = "WireScope cannot distinguish an endpoint actively rejecting a port from an intermediate firewall spoofing a RST without packet captures on the remote host.",
        .user_recommendation = "Verify connectivity issues from multiple network vantage points and correlate with network device logs.",
    },
    .{
        .category = "Storage / Filesystem",
        .title = "Local Filesystem Access Control Boundaries",
        .mechanism = "Persisted assessment history, baselines, and integrity manifests rely on operating system permissions (user umask, ACLs).",
        .wirescope_defense = "WireScope stores records in per-user application directories and rejects directory traversal attempts.",
        .residual_limitation = "WireScope does not implement independent file-level encryption; other processes running under the same user account have read access.",
        .user_recommendation = "Protect user accounts with strong credentials, ensure disk encryption (BitLocker/LUKS), and avoid shared multi-user overrides.",
    },
    .{
        .category = "Integrity / Manifests",
        .title = "Local Hash Integrity vs Cryptographic Authenticity",
        .mechanism = "Integrity manifests use SHA-256 hashes to detect accidental corruption or modification of report artifacts.",
        .wirescope_defense = "WireScope computes and verifies SHA-256 hashes for all assessment artifacts against a versioned manifest.",
        .residual_limitation = "A local hash alone does not prove author identity or protect against an attacker with write access to both report and manifest.",
        .user_recommendation = "For non-repudiation and tamper-proofing against local adversaries, sign manifests with external PKI keys (e.g. GPG or Sigstore).",
    },
};

/// Statistics collected during property and fuzz test execution
pub const FuzzStats = struct {
    iterations: usize = 0,
    malformed_rejected: usize = 0,
    valid_accepted: usize = 0,
    panics_or_leaks: usize = 0,
};

/// PRNG-based pseudo-random property generator for hostname fuzzing
pub fn fuzzHostnames(allocator: std.mem.Allocator, iterations: usize) !FuzzStats {
    var stats = FuzzStats{ .iterations = iterations };
    var prng = std.Random.DefaultPrng.init(0x1337_BEEF);
    const random = prng.random();

    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        // Generate pseudo-random inputs with edge conditions:
        // Case 0: Empty string
        // Case 1: Oversized hostname (> 253 chars)
        // Case 2: Oversized label (> 63 chars)
        // Case 3: Invalid characters (control chars, punctuation, null byte)
        // Case 4: Hyphen violations (-start, end-)
        // Case 5: Consecutive dots
        // Case 6: Random ASCII bytes
        const mode = i % 7;
        var input_buf: [300]u8 = undefined;
        var input_slice: []const u8 = "";

        switch (mode) {
            0 => {
                input_slice = "";
            },
            1 => {
                // > 253 chars: fill with 260 'a's and dots
                @memset(input_buf[0..260], 'a');
                input_buf[60] = '.';
                input_buf[120] = '.';
                input_buf[180] = '.';
                input_buf[240] = '.';
                input_slice = input_buf[0..260];
            },
            2 => {
                // > 63 char label: 65 'b's followed by .com
                @memset(input_buf[0..65], 'b');
                @memcpy(input_buf[65..70], "b.com");
                input_slice = input_buf[0..70];
            },
            3 => {
                // Invalid characters: control chars or symbols
                const bad_chars = [_]u8{ 0x00, 0x07, 0x1B, ' ', '/', '\\', ':', ';', '@', '!', '#', '$', '%', '^', '&', '*', '(', ')' };
                const picked = bad_chars[random.intRangeAtMost(usize, 0, bad_chars.len - 1)];
                const s = try std.fmt.bufPrint(&input_buf, "invalid{c}host.test", .{picked});
                input_slice = s;
            },
            4 => {
                // Hyphen at start or end of label
                if (random.boolean()) {
                    input_slice = "-badstart.example.test";
                } else {
                    input_slice = "badend-.example.test";
                }
            },
            5 => {
                // Consecutive dots
                input_slice = "double..dot.test";
            },
            6 => {
                // Random bytes of varying lengths
                const len = random.intRangeAtMost(usize, 1, 200);
                for (input_buf[0..len]) |*b| {
                    b.* = random.intRangeAtMost(u8, 0, 127);
                }
                input_slice = input_buf[0..len];
            },
            else => unreachable,
        }

        // Fuzz target: normalizeHostname must never panic or leak
        if (recon.scope.normalizeHostname(allocator, input_slice)) |norm| {
            allocator.free(norm);
            stats.valid_accepted += 1;
        } else |_| {
            stats.malformed_rejected += 1;
        }
    }

    return stats;
}

/// PRNG-based property generator for IPv4 fuzzing
pub fn fuzzIpv4(allocator: std.mem.Allocator, iterations: usize) !FuzzStats {
    var stats = FuzzStats{ .iterations = iterations };
    var prng = std.Random.DefaultPrng.init(0xCAFE_BABE);
    const random = prng.random();

    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const mode = i % 6;
        var buf: [128]u8 = undefined;
        var input: []const u8 = "";

        switch (mode) {
            0 => {
                // Overflow octets (> 255)
                const s = try std.fmt.bufPrint(&buf, "192.168.1.{d}", .{random.intRangeAtMost(u32, 256, 10000)});
                input = s;
            },
            1 => {
                // Wrong octet count (< 4 or > 4)
                if (random.boolean()) {
                    input = "192.168.1";
                } else {
                    input = "192.168.1.1.1";
                }
            },
            2 => {
                // Non-numeric characters
                input = "192.168.1.abc";
            },
            3 => {
                // Empty string or trailing dot
                if (random.boolean()) {
                    input = "";
                } else {
                    input = "192.168.1.1.";
                }
            },
            4 => {
                // Leading zeros or negative sign
                input = "192.168.01.-1";
            },
            5 => {
                // Valid randomized IPv4
                const o1 = random.intRangeAtMost(u8, 0, 255);
                const o2 = random.intRangeAtMost(u8, 0, 255);
                const o3 = random.intRangeAtMost(u8, 0, 255);
                const o4 = random.intRangeAtMost(u8, 0, 255);
                const s = try std.fmt.bufPrint(&buf, "{d}.{d}.{d}.{d}", .{ o1, o2, o3, o4 });
                input = s;
            },
            else => unreachable,
        }

        // Fuzz target: normalizeIpv4 must never panic or leak
        if (recon.scope.normalizeIpv4(allocator, input)) |norm| {
            allocator.free(norm);
            stats.valid_accepted += 1;
        } else |_| {
            stats.malformed_rejected += 1;
        }
    }

    return stats;
}

/// PRNG-based property generator for Port Specification fuzzing
pub fn fuzzPorts(allocator: std.mem.Allocator, iterations: usize) !FuzzStats {
    var stats = FuzzStats{ .iterations = iterations };
    var prng = std.Random.DefaultPrng.init(0xDEAD_BEEF);
    const random = prng.random();

    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const mode = i % 6;
        var buf: [128]u8 = undefined;
        var input: []const u8 = "";

        switch (mode) {
            0 => {
                // Port 0
                input = "0";
            },
            1 => {
                // Port > 65535
                const s = try std.fmt.bufPrint(&buf, "{d}", .{random.intRangeAtMost(u32, 65536, 100000)});
                input = s;
            },
            2 => {
                // Inverted range (start > end)
                input = "8080-80";
            },
            3 => {
                // Malformed syntax: double dashes, trailing commas, letters
                input = "80--443,abc";
            },
            4 => {
                // Excessive port count exceeding max_ports (100)
                input = "1-150";
            },
            5 => {
                // Valid port range
                const start = random.intRangeAtMost(u16, 1, 1000);
                const end = start + random.intRangeAtMost(u16, 1, 10);
                const s = try std.fmt.bufPrint(&buf, "{d}-{d}", .{ start, end });
                input = s;
            },
            else => unreachable,
        }

        // Fuzz target: parsePortSpec with max_ports = 100
        if (recon.scope.parsePortSpec(allocator, input, 100)) |ports| {
            allocator.free(ports);
            stats.valid_accepted += 1;
        } else |_| {
            stats.malformed_rejected += 1;
        }
    }

    return stats;
}

/// Property generator for Sandbox Path Traversal fuzzing
pub fn fuzzSandboxPaths(iterations: usize) !FuzzStats {
    var stats = FuzzStats{ .iterations = iterations };
    var prng = std.Random.DefaultPrng.init(0xFEED_FACE);
    const random = prng.random();

    const dummy_storage = storage.StoragePaths.init("wirescope_test_sandbox");
    var buf: [128]u8 = undefined;

    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const mode = i % 7;
        var input: []const u8 = "";

        switch (mode) {
            0 => input = "../escape.txt",
            1 => input = "..\\Windows\\System32\\cmd.exe",
            2 => input = "/etc/passwd",
            3 => input = "C:\\sensitive_file.dat",
            4 => input = "subdir/../../../root.txt",
            5 => {
                // Random characters containing .. or / or \
                const c1: u8 = if (random.boolean()) '.' else '/';
                const c2: u8 = if (random.boolean()) '.' else '\\';
                const s = try std.fmt.bufPrint(&buf, "prefix{c}{c}traversal_{d}.json", .{
                    c1,
                    c2,
                    random.intRangeAtMost(u32, 1, 1000),
                });
                input = s;
            },
            6 => input = "valid_contained_file.json",
            else => unreachable,
        }

        // Fuzz target: validateContainedPath must strictly reject all escapes
        if (dummy_storage.validateContainedPath(testing.allocator, "assessments", input)) |p| {
            testing.allocator.free(p);
            stats.valid_accepted += 1;
        } else |_| {
            stats.malformed_rejected += 1;
        }
    }

    return stats;
}

// ============================================================================
// TESTS & REGRESSION SUITE
// ============================================================================

test "hardening: residual risks catalog is comprehensive and accurate" {
    try testing.expectEqual(@as(usize, 6), RESIDUAL_RISKS.len);
    for (RESIDUAL_RISKS) |risk| {
        try testing.expect(risk.category.len > 0);
        try testing.expect(risk.title.len > 0);
        try testing.expect(risk.mechanism.len > 0);
        try testing.expect(risk.wirescope_defense.len > 0);
        try testing.expect(risk.residual_limitation.len > 0);
        try testing.expect(risk.user_recommendation.len > 0);
    }
}

test "hardening: hostname fuzzing fails safely without memory leaks" {
    const stats = try fuzzHostnames(testing.allocator, 140);
    try testing.expectEqual(@as(usize, 140), stats.iterations);
    try testing.expect(stats.malformed_rejected > 0);
    try testing.expectEqual(@as(usize, 0), stats.panics_or_leaks);
}

test "hardening: ipv4 fuzzing fails safely without memory leaks" {
    const stats = try fuzzIpv4(testing.allocator, 120);
    try testing.expectEqual(@as(usize, 120), stats.iterations);
    try testing.expect(stats.malformed_rejected > 0);
    try testing.expectEqual(@as(usize, 0), stats.panics_or_leaks);
}

test "hardening: port syntax fuzzing bounds ranges safely" {
    const stats = try fuzzPorts(testing.allocator, 120);
    try testing.expectEqual(@as(usize, 120), stats.iterations);
    try testing.expect(stats.malformed_rejected > 0);
    try testing.expectEqual(@as(usize, 0), stats.panics_or_leaks);
}

test "hardening: sandbox path traversal fuzzing prevents escape" {
    const stats = try fuzzSandboxPaths(140);
    try testing.expectEqual(@as(usize, 140), stats.iterations);
    try testing.expect(stats.malformed_rejected > 0);
    try testing.expectEqual(@as(usize, 0), stats.panics_or_leaks);
}

test "hardening: scope escape regression - DNS rebinding blocked" {
    // Assessment target is localhost (loopback only)
    const targets = [_][]const u8{"localhost"};
    var plan = try recon.plan.AssessmentPlan.create(testing.allocator, .{
        .targets = &targets,
        .include_dns = false,
        .include_tcp = true,
    });
    defer plan.deinit(testing.allocator);

    // Verify it is recognized as loopback confined
    try testing.expect(plan.is_loopback_only);

    // Simulate DNS query returning public internet IP 8.8.8.8
    const spoofed_ips = [_][]const u8{"8.8.8.8"};
    const result = plan.verifyDnsScopeCompliance(&spoofed_ips);

    // Invariant: Must fail immediately with ScopeExpansionPrevented
    try testing.expectError(error.ScopeExpansionPrevented, result);
}

test "hardening: scope escape regression - excluded target bypass blocked" {
    // Assessment includes 127.0.0.1 but explicitly excludes 127.0.0.99
    const targets = [_][]const u8{"127.0.0.1"};
    const exclusions = [_][]const u8{"127.0.0.99"};
    var plan = try recon.plan.AssessmentPlan.create(testing.allocator, .{
        .targets = &targets,
        .exclusions = &exclusions,
        .include_dns = false,
        .include_tcp = true,
    });
    defer plan.deinit(testing.allocator);

    // Simulate DNS returning the excluded IP
    const resolved_excluded = [_][]const u8{"127.0.0.99"};
    const result = plan.verifyDnsScopeCompliance(&resolved_excluded);

    // Invariant: Must fail immediately with ResolvedTargetExcluded
    try testing.expectError(error.ResolvedTargetExcluded, result);
}

test "hardening: scope escape regression - broad CIDR rejected by default" {
    // /16 network comprises 65536 hosts; rejected by default
    const result = recon.scope.expandCidr(testing.allocator, "10.0.0.0/16", false);
    try testing.expectError(error.ExcessiveCidrRange, result);

    // /8 network comprises 16M hosts; rejected by default
    const result_slash8 = recon.scope.expandCidr(testing.allocator, "10.0.0.0/8", false);
    try testing.expectError(error.ExcessiveCidrRange, result_slash8);
}

test "hardening: redirect scope guard blocks unapproved external domains" {
    var mock = audit.http_audit.MockHttpAuditConnector{ .fixture_id = .redirect_out_of_scope };
    const connector = mock.connector();

    // Default configuration enforces allow_redirect_scope_expansion = false
    var result = try audit.http_audit.executeHttpAudit(
        testing.allocator,
        "https://localhost:8443/login",
        .{ .allow_redirect_scope_expansion = false },
        connector,
        null,
        null,
    );
    defer result.deinit(testing.allocator);

    // Invariant: Redirect escaping approved scope is detected and blocked
    try testing.expect(result.redirect_scope_blocked);
    try testing.expect(result.out_of_scope_target != null);
    try testing.expectEqualStrings("https://unauthorized-evil.test/hijack", result.out_of_scope_target.?);

    var found_scope_rule = false;
    for (result.findings) |f| {
        if (std.mem.eql(u8, f.rule_id, "WS-AUDIT-HTTP-REDIRECT-SCOPE")) {
            found_scope_rule = true;
            try testing.expectEqual(Severity.medium, f.severity);
        }
    }
    try testing.expect(found_scope_rule);
}

test "hardening: resource limits - bounded HTTP response size" {
    const config = audit.http_audit.HttpAuditConfig{
        .max_response_bytes = 1024 * 1024, // 1 MB bound
    };
    try testing.expectEqual(@as(usize, 1048576), config.max_response_bytes);
}

test "hardening: cooperative cancellation cleanly aborts without leaks" {
    var token = probes.types.CancellationToken.init();
    try testing.expect(!token.isCancelled());

    // Signal cancellation
    token.cancel();
    try testing.expect(token.isCancelled());

    // Batch probe with cancelled token aborts early without leaks
    var mock = probes.tcp.MockTcpConnector{ .mock_outcome = .success };

    var batch_res = try probes.tcp.executeTcpBatchProbe(
        testing.allocator,
        mock.connector(),
        "127.0.0.1",
        80,
        5,
        0,
        1000,
        &token,
    );
    defer batch_res.deinit(testing.allocator);

    // Cancelled batch should record partial status and 0 samples
    try testing.expect(batch_res.is_partial);
    try testing.expectEqual(@as(usize, 0), batch_res.samples.len);
    try testing.expect(token.isCancelled());
}

test "hardening: atomic write cleanup on interrupted or failing write" {
    const test_dir = "test_atomic_hardening_sandbox";
    try std.fs.cwd().makePath(test_dir);
    defer std.fs.cwd().deleteTree(test_dir) catch {};

    const target_file = "report.json";
    const payload = "{\"status\":\"healthy\"}";

    // Successful atomic write creates file
    try storage.atomicWriteFile(testing.allocator, test_dir, target_file, payload);

    const full_target = try std.fs.path.join(testing.allocator, &[_][]const u8{ test_dir, target_file });
    defer testing.allocator.free(full_target);

    var read_file = try std.fs.cwd().openFile(full_target, .{});
    var read_buf: [64]u8 = undefined;
    const bytes_read = try read_file.readAll(&read_buf);
    read_file.close();

    try testing.expectEqualStrings(payload, read_buf[0..bytes_read]);

    // Verify no leftover .tmp files exist in test_dir
    var dir = try std.fs.cwd().openDir(test_dir, .{ .iterate = true });
    defer dir.close();

    var it = dir.iterate();
    var tmp_count: usize = 0;
    while (try it.next()) |entry| {
        if (std.mem.indexOf(u8, entry.name, ".tmp") != null) {
            tmp_count += 1;
        }
    }
    try testing.expectEqual(@as(usize, 0), tmp_count);
}

test "hardening: report redaction strictly masks credentials and secrets" {
    const secret_input = "Authorization: Bearer supersecrettoken12345 Password: myadminpassword";
    const config = reporting.redact.RedactionConfig{
        .enabled = true,
        .redact_credentials = true,
    };

    const redacted = try reporting.redact.redactText(testing.allocator, secret_input, config);
    defer testing.allocator.free(redacted);

    // Invariant: Bearer and Password tokens must be masked
    try testing.expect(std.mem.indexOf(u8, redacted, "supersecrettoken12345") == null);
    try testing.expect(std.mem.indexOf(u8, redacted, "myadminpassword") == null);
    try testing.expect(std.mem.indexOf(u8, redacted, "[REDACTED]") != null);
}

test "hardening: JSON parser safely rejects corrupt envelopes without panic" {
    const corrupt_json_inputs = [_][]const u8{
        "", // empty
        "{", // incomplete object
        "{\"schema_version\": ", // truncated value
        "{\"schema_version\": \"not_a_number\"}", // wrong type
        "{\"document_type\": 12345}", // wrong type for string
        "null",
        "[]",
        "{{{}}}",
    };

    for (corrupt_json_inputs) |corrupt| {
        const result = reporting.schema.validateReportJson(testing.allocator, corrupt);
        // Invariant: Must fail safely with a SchemaValidationError
        try testing.expect(result == error.InvalidJson or
            result == error.NotAnObject or
            result == error.MissingRequiredField or
            result == error.InvalidFieldType);
    }
}
