const std = @import("std");
const testing = std.testing;

const tls = @import("tls.zig");
const core = @import("../core/root.zig");

const TlsFailureCategory = tls.TlsFailureCategory;
const TlsProbeResult = tls.TlsProbeResult;

/// Diagnostic troubleshooting guidance separating observed facts from unverified hypotheses
pub const TlsTroubleshooting = struct {
    summary: []const u8,
    observed_facts: []const []const u8,
    hypotheses: []const []const u8,
    recommended_actions: []const []const u8,
    context_notes: ?[]const u8 = null,

    pub fn toJson(self: TlsTroubleshooting, writer: anytype) !void {
        try writer.print("{{\"summary\":\"{s}\",\"observed_facts\":[", .{self.summary});
        for (self.observed_facts, 0..) |fact, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.print("\"{s}\"", .{fact});
        }
        try writer.writeAll("],\"hypotheses\":[");
        for (self.hypotheses, 0..) |hyp, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.print("\"{s}\"", .{hyp});
        }
        try writer.writeAll("],\"recommended_actions\":[");
        for (self.recommended_actions, 0..) |act, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.print("\"{s}\"", .{act});
        }
        try writer.writeAll("],\"context_notes\":");
        if (self.context_notes) |n| {
            try writer.print("\"{s}\"", .{n});
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll("}");
    }

    pub fn toTerminal(self: TlsTroubleshooting, writer: anytype) !void {
        try writer.writeAll("Troubleshooting Guidance:\n");
        try writer.print("  Summary: {s}\n", .{self.summary});

        if (self.observed_facts.len > 0) {
            try writer.writeAll("  Observed Facts:\n");
            for (self.observed_facts) |fact| {
                try writer.print("    * {s}\n", .{fact});
            }
        }

        if (self.hypotheses.len > 0) {
            try writer.writeAll("  Possible Causes (Hypotheses):\n");
            for (self.hypotheses) |hyp| {
                try writer.print("    - {s}\n", .{hyp});
            }
        }

        if (self.recommended_actions.len > 0) {
            try writer.writeAll("  Recommended Actions:\n");
            for (self.recommended_actions) |act| {
                try writer.print("    > {s}\n", .{act});
            }
        }

        if (self.context_notes) |notes| {
            try writer.print("  Context: {s}\n", .{notes});
        }
        try writer.writeAll("\n");
    }
};

/// Generates diagnostic guidance for a TLS probe outcome
pub fn generateTlsTroubleshooting(result: *const TlsProbeResult) TlsTroubleshooting {
    if (result.verification_bypassed) {
        return .{
            .summary = "TLS connection established with certificate verification bypassed.",
            .observed_facts = &.{
                "TLS session was established without validating certificate chain or hostname.",
                "Security validation was explicitly skipped via --insecure flag.",
            },
            .hypotheses = &.{
                "Hypothesis 1: The remote endpoint identity is unverified and susceptible to impersonation.",
                "Hypothesis 2: An on-path attacker could intercept or inspect traffic undetected.",
            },
            .recommended_actions = &.{
                "Avoid using --insecure in production or security-critical environments.",
                "Configure a trusted CA bundle using '--ca-bundle <path>' instead of bypassing verification.",
            },
            .context_notes = "Verification bypass is intended only for development and controlled debugging.",
        };
    }

    return switch (result.failure_category) {
        .success => .{
            .summary = "TLS handshake and certificate chain validation completed successfully.",
            .observed_facts = &.{
                "TLS session negotiated and established with remote server.",
                "Server certificate Subject/SAN matches requested hostname.",
                "Certificate chain verified to a trusted root Certificate Authority.",
                "Certificate is within active validity period.",
            },
            .hypotheses = &.{},
            .recommended_actions = &.{
                "Endpoint is ready for secure encrypted application protocols.",
            },
            .context_notes = null,
        },
        .hostname_mismatch => .{
            .summary = "TLS certificate does not match requested hostname.",
            .observed_facts = &.{
                "Server presented a certificate whose Subject/SAN does not match target host.",
                "Connection was aborted to prevent impersonation or man-in-the-middle attack.",
            },
            .hypotheses = &.{
                "Hypothesis 1: Target host is an IP address or alias not covered in certificate SAN.",
                "Hypothesis 2: Server virtual host or SNI routing is misconfigured, returning default certificate.",
                "Hypothesis 3: DNS record directs to an unexpected host or CDN endpoint.",
            },
            .recommended_actions = &.{
                "Verify the exact hostname requested matches certificate Subject Alternative Names.",
                "Check server SNI and virtual host configuration.",
                "Run 'wirescope dns <hostname>' to verify DNS resolution target.",
            },
            .context_notes = "RFC 6125 requires exact or valid wildcard match in Subject Alternative Name (SAN).",
        },
        .certificate_expired => .{
            .summary = "TLS certificate has expired.",
            .observed_facts = &.{
                "Evaluation timestamp is past the certificate notAfter date.",
                "Validation was rejected by trust engine due to certificate expiration.",
            },
            .hypotheses = &.{
                "Hypothesis 1: Remote server certificate has not been renewed.",
                "Hypothesis 2: Automated certificate renewal (ACME / Certbot) failed or stalled.",
                "Hypothesis 3: Local system clock is skewed into the future.",
            },
            .recommended_actions = &.{
                "Verify local system clock and timezone against an NTP reference.",
                "Renew or replace expired certificate on the remote web server.",
            },
            .context_notes = "X.509 RFC 5280 requires strict validity period enforcement.",
        },
        .certificate_not_yet_valid => .{
            .summary = "TLS certificate is not yet valid.",
            .observed_facts = &.{
                "Evaluation timestamp precedes certificate notBefore date.",
            },
            .hypotheses = &.{
                "Hypothesis 1: Local system clock is skewed into the past.",
                "Hypothesis 2: Newly issued certificate has a future validity start time.",
            },
            .recommended_actions = &.{
                "Check and synchronize local system clock via NTP.",
                "Verify remote certificate activation timestamp.",
            },
            .context_notes = null,
        },
        .untrusted_chain => .{
            .summary = "TLS certificate chain could not be verified against trusted root store.",
            .observed_facts = &.{
                "No trusted Certificate Authority (CA) found that signed presented certificate.",
                "Handshake aborted due to untrusted or unverifiable trust chain.",
            },
            .hypotheses = &.{
                "Hypothesis 1: Server uses a self-signed certificate not installed in system trust store.",
                "Hypothesis 2: Intermediate CA certificate is missing from server certificate response.",
                "Hypothesis 3: Organization uses an internal private PKI whose root CA is not imported.",
                "Hypothesis 4: Upstream firewall or proxy is intercepting traffic with an unrecognized root.",
            },
            .recommended_actions = &.{
                "Provide private or organization CA bundle with '--ca-bundle <path>'.",
                "Ensure remote web server sends full certificate chain including intermediates.",
                "Verify OS root certificate bundle is up to date.",
            },
            .context_notes = "Root certificates must be present in the platform trust store or explicitly supplied.",
        },
        .handshake_failure => .{
            .summary = "TLS handshake failed during protocol negotiation.",
            .observed_facts = &.{
                "Cryptographic negotiation was terminated by remote server or client.",
            },
            .hypotheses = &.{
                "Hypothesis 1: Remote server does not support TLS 1.3 or modern cipher suites.",
                "Hypothesis 2: Server rejected client handshake parameters, SNI, or ALPN.",
                "Hypothesis 3: Middlebox or network appliance terminated TLS connection.",
            },
            .recommended_actions = &.{
                "Confirm remote port is dedicated to TLS (e.g. 443) and not plaintext.",
                "Check server TLS version and cipher suite support.",
                "Inspect firewall and security appliance inspection logs.",
            },
            .context_notes = "WireScope uses pinned Zig standard library TLS 1.3 client implementation.",
        },
        .inability_to_verify => .{
            .summary = "Unable to verify certificate due to unsupported cryptographic algorithm.",
            .observed_facts = &.{
                "Certificate signature algorithm or elliptic curve is not supported.",
            },
            .hypotheses = &.{
                "Hypothesis 1: Certificate uses a legacy algorithm (e.g. MD5, DSA) or unsupported curve.",
                "Hypothesis 2: Experimental or custom cryptographic parameters were used.",
            },
            .recommended_actions = &.{
                "Re-issue certificate using standard RSA (2048+) or ECDSA (P-256 / P-384).",
                "Check platform cryptographic compatibility.",
            },
            .context_notes = null,
        },
        .tcp_connection_failed => .{
            .summary = "TCP connection failed before TLS handshake could start.",
            .observed_facts = &.{
                "Underlying TCP 3-way handshake could not be completed.",
            },
            .hypotheses = &.{
                "Hypothesis 1: Remote port is closed or listening service is stopped.",
                "Hypothesis 2: Firewall or network access control dropped SYN packet.",
            },
            .recommended_actions = &.{
                "Run 'wirescope tcp <target>' to diagnose TCP transport reachability.",
                "Verify target IP, port, and security group rules.",
            },
            .context_notes = null,
        },
        .cancelled => .{
            .summary = "TLS probe was cancelled before completion.",
            .observed_facts = &.{
                "Cancellation signal was triggered during probe execution.",
            },
            .hypotheses = &.{
                "Hypothesis 1: User interrupted operation or assessment deadline expired.",
            },
            .recommended_actions = &.{
                "Increase timeout with '--timeout <ms>' or retry operation.",
            },
            .context_notes = null,
        },
        .malformed_input => .{
            .summary = "Invalid target, port, or option syntax.",
            .observed_facts = &.{
                "Provided target hostname or port is invalid.",
            },
            .hypotheses = &.{
                "Hypothesis 1: Port is outside valid range (1-65535) or target format is malformed.",
            },
            .recommended_actions = &.{
                "Specify target as 'hostname' or 'hostname:port' (default port 443).",
            },
            .context_notes = null,
        },
        .operational_failure => .{
            .summary = "Operational failure occurred during TLS probe.",
            .observed_facts = &.{
                "Internal error or system call failure occurred.",
            },
            .hypotheses = &.{
                "Hypothesis 1: Operating system resource exhaustion or trust store read failure.",
            },
            .recommended_actions = &.{
                "Check available memory and file permissions.",
            },
            .context_notes = null,
        },
    };
}

test "generate tls troubleshooting for all failure categories" {
    const categories = [_]TlsFailureCategory{
        .success,
        .hostname_mismatch,
        .certificate_expired,
        .certificate_not_yet_valid,
        .untrusted_chain,
        .handshake_failure,
        .inability_to_verify,
        .tcp_connection_failed,
        .cancelled,
        .malformed_input,
        .operational_failure,
    };

    for (categories) |cat| {
        const dummy_res = TlsProbeResult{
            .host = "test.local",
            .port = 443,
            .is_handshake_successful = (cat == .success),
            .failure_category = cat,
            .elapsed_ns = 1_000_000,
            .protocol_version = "TLSv1.3",
            .cipher_suite = "TLS_AES_128_GCM_SHA256",
            .subject = "test.local",
            .issuer = "Test CA",
            .not_before = 0,
            .not_after = 2000000000,
            .hostname_matched = (cat == .success),
            .chain_valid = (cat == .success),
            .trust_store_source = .system,
        };

        const tb = generateTlsTroubleshooting(&dummy_res);
        try testing.expect(tb.summary.len > 0);
        try testing.expect(tb.observed_facts.len > 0);
        try testing.expect(tb.recommended_actions.len > 0);

        var buf = std.ArrayList(u8).init(testing.allocator);
        defer buf.deinit();
        try tb.toJson(buf.writer());
        try testing.expect(buf.items.len > 0);

        buf.clearRetainingCapacity();
        try tb.toTerminal(buf.writer());
        try testing.expect(buf.items.len > 0);
    }
}
