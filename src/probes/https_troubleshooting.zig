const std = @import("std");
const testing = std.testing;

const https = @import("https.zig");
const core = @import("../core/root.zig");

const HttpsFailureCategory = https.HttpsFailureCategory;
const HttpsProbeResult = https.HttpsProbeResult;

/// Diagnostic troubleshooting guidance separating observed facts from unverified hypotheses for HTTPS probes
pub const HttpsTroubleshooting = struct {
    summary: []const u8,
    observed_facts: []const []const u8,
    hypotheses: []const []const u8,
    recommended_actions: []const []const u8,
    context_notes: ?[]const u8 = null,

    pub fn toJson(self: HttpsTroubleshooting, writer: anytype) !void {
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

    pub fn toTerminal(self: HttpsTroubleshooting, writer: anytype) !void {
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

/// Generates diagnostic guidance for an HTTPS probe outcome
pub fn generateHttpsTroubleshooting(result: *const HttpsProbeResult) HttpsTroubleshooting {
    if (result.verification_bypassed) {
        return .{
            .summary = "HTTPS request succeeded with TLS verification explicitly bypassed.",
            .observed_facts = &.{
                "HTTP request was completed over an unverified TLS transport.",
                "Certificate and hostname validation was disabled via --insecure flag.",
            },
            .hypotheses = &.{
                "Hypothesis 1: The remote endpoint identity is unverified and susceptible to man-in-the-middle attacks.",
            },
            .recommended_actions = &.{
                "Never disable TLS verification in production or assessment profiles.",
                "Provide an explicit trusted CA bundle using '--ca-bundle <path>'.",
            },
            .context_notes = "Insecure mode is reserved exclusively for development and testing fixtures.",
        };
    }

    return switch (result.failure_category) {
        .success => .{
            .summary = "HTTPS probe completed and valid HTTP response was received.",
            .observed_facts = &.{
                "TCP connection and TLS session established within deadlines.",
                "HTTP response headers parsed within configured size bounds.",
                "Response body was bounded and discarded without local persistence.",
            },
            .hypotheses = &.{},
            .recommended_actions = &.{
                "Inspect response status and security headers (HSTS, CSP, X-Content-Type-Options).",
            },
            .context_notes = null,
        },
        .redirect_out_of_scope => .{
            .summary = "HTTP redirect destination escapes approved assessment scope.",
            .observed_facts = &.{
                "Server returned a redirect (3xx) pointing to a target outside the approved scope.",
                "Redirect following was halted by the WireScope Scope Guard.",
            },
            .hypotheses = &.{
                "Hypothesis 1: Target web application redirects authentication to an external OAuth/SSO provider (e.g. auth0, okta, google).",
                "Hypothesis 2: Site redirects to an external CDN, canonical domain, or partner portal.",
                "Hypothesis 3: Open redirect vulnerability or unexpected third-party redirect link.",
            },
            .recommended_actions = &.{
                "If the destination domain is authorized, add it to your profile targets list.",
                "Use '--allow-redirect-scope-expansion' if ad-hoc out-of-scope inspection is intended.",
                "Verify whether the redirection is an intended authentication flow or an open redirect.",
            },
            .context_notes = "WireScope strictly enforces scope boundaries and will never silently follow redirects outside approved scope.",
        },
        .redirect_loop => .{
            .summary = "HTTP redirect loop detected.",
            .observed_facts = &.{
                "A repeated URL was encountered in the redirection sequence.",
                "Execution halted to avoid infinite request recursion.",
            },
            .hypotheses = &.{
                "Hypothesis 1: Circular redirect rule between HTTP and HTTPS (e.g., http->https->http).",
                "Hypothesis 2: Reverse proxy misconfiguration forwarding wrong X-Forwarded-Proto header.",
                "Hypothesis 3: Missing session cookie or authentication token causing repetitive login loop.",
            },
            .recommended_actions = &.{
                "Inspect redirect hops with 'wirescope https <url>'.",
                "Check web server / reverse proxy SSL termination configuration.",
                "Verify X-Forwarded-Proto headers and upstream port mappings.",
            },
            .context_notes = "RFC 9110 specifies that clients must detect and terminate redirect loops.",
        },
        .redirect_limit_exceeded => .{
            .summary = "Maximum HTTP redirect limit exceeded.",
            .observed_facts = &.{
                "Redirection chain exceeded the configured --max-redirects threshold.",
            },
            .hypotheses = &.{
                "Hypothesis 1: Deep or cascading redirect chains across multiple microservices or regional portals.",
                "Hypothesis 2: Inadvertent routing ping-pong across gateway layers.",
            },
            .recommended_actions = &.{
                "Increase redirect limit with '--max-redirects <n>' if deep chains are expected.",
                "Inspect intermediate redirect hops in the response timeline.",
            },
            .context_notes = "Default redirect threshold is 5 hops to prevent resource exhaustion.",
        },
        .response_size_exceeded => .{
            .summary = "HTTP response exceeded configured maximum size limit.",
            .observed_facts = &.{
                "Incoming response bytes exceeded --max-response-size bound.",
                "Data stream was immediately terminated to preserve local memory.",
            },
            .hypotheses = &.{
                "Hypothesis 1: Target endpoint returned a large binary asset, video, or data archive.",
                "Hypothesis 2: Target is attempting a decompression bomb (gzip/deflate bomb).",
            },
            .recommended_actions = &.{
                "Increase maximum response size bound with '--max-response-size <bytes>' if necessary.",
                "Target lightweight diagnostic endpoints (e.g. /health, /api/v1/status) instead of binary downloads.",
            },
            .context_notes = "WireScope bounds all response consumption to ensure predictable resource utilization.",
        },
        .http_protocol_error => .{
            .summary = "Malformed or unparseable HTTP response.",
            .observed_facts = &.{
                "Response stream did not conform to RFC 9112 / HTTP 1.1 syntax.",
            },
            .hypotheses = &.{
                "Hypothesis 1: Remote service is a non-HTTP binary protocol (e.g., SSH, SMTP, custom daemon).",
                "Hypothesis 2: Upstream proxy truncated or corrupted the HTTP response header block.",
            },
            .recommended_actions = &.{
                "Verify target service protocol using 'wirescope tcp <target>'.",
                "Inspect raw service banner with diagnostic tools.",
            },
            .context_notes = null,
        },
        .tls_certificate_expired => .{
            .summary = "HTTPS handshake aborted: Server certificate has expired.",
            .observed_facts = &.{
                "TLS handshake was rejected during certificate chain validation.",
                "The server certificate validity period has elapsed.",
            },
            .hypotheses = &.{
                "Hypothesis 1: Remote certificate renewal stalled or failed.",
                "Hypothesis 2: Local system clock is skewed into the future.",
            },
            .recommended_actions = &.{
                "Check local clock synchronization via NTP.",
                "Inspect certificate validity dates using 'wirescope tls <target>'.",
            },
            .context_notes = null,
        },
        .tls_certificate_not_yet_valid => .{
            .summary = "HTTPS handshake aborted: Server certificate is not yet valid.",
            .observed_facts = &.{
                "Current evaluation time precedes certificate notBefore timestamp.",
            },
            .hypotheses = &.{
                "Hypothesis 1: Local clock is set into the past.",
                "Hypothesis 2: Newly issued certificate has future activation date.",
            },
            .recommended_actions = &.{
                "Synchronize system time via NTP.",
            },
            .context_notes = null,
        },
        .tls_hostname_mismatch => .{
            .summary = "HTTPS handshake aborted: Certificate Subject/SAN does not match requested hostname.",
            .observed_facts = &.{
                "Server presented certificate whose Subject Alternative Names do not match target hostname.",
            },
            .hypotheses = &.{
                "Hypothesis 1: Target host accessed by IP address rather than FQDN.",
                "Hypothesis 2: SNI routing misconfigured on server, returning default host certificate.",
            },
            .recommended_actions = &.{
                "Access service using the exact FQDN listed in the certificate SAN.",
                "Run 'wirescope tls <target>' to view presented certificate details.",
            },
            .context_notes = null,
        },
        .tls_untrusted_chain => .{
            .summary = "HTTPS handshake aborted: Certificate chain is untrusted.",
            .observed_facts = &.{
                "Certificate was not signed by any Certificate Authority in the trusted bundle.",
            },
            .hypotheses = &.{
                "Hypothesis 1: Self-signed certificate or private organizational CA.",
                "Hypothesis 2: Missing intermediate CA certificates in server chain response.",
            },
            .recommended_actions = &.{
                "Specify trusted private root with '--ca-bundle <path>'.",
                "Ensure server transmits full certificate bundle (fullchain.pem).",
            },
            .context_notes = null,
        },
        .tls_handshake_failed => .{
            .summary = "HTTPS handshake failed during TLS negotiation.",
            .observed_facts = &.{
                "TLS session negotiation terminated before completion.",
            },
            .hypotheses = &.{
                "Hypothesis 1: Incompatible TLS protocol version or cipher suites.",
                "Hypothesis 2: Server aborted handshake with TLS alert.",
            },
            .recommended_actions = &.{
                "Check remote server TLS version support (WireScope uses TLS 1.3).",
            },
            .context_notes = null,
        },
        .tcp_connection_failed => .{
            .summary = "TCP connection failed before HTTP/HTTPS request could start.",
            .observed_facts = &.{
                "Unable to establish TCP transport to target port.",
            },
            .hypotheses = &.{
                "Hypothesis 1: Target port closed or service daemon offline.",
                "Hypothesis 2: Firewall dropping SYN packets.",
            },
            .recommended_actions = &.{
                "Diagnose TCP reachability using 'wirescope tcp <target>'.",
            },
            .context_notes = null,
        },
        .timeout => .{
            .summary = "HTTPS probe timed out before response was received.",
            .observed_facts = &.{
                "Total elapsed time exceeded configured --timeout deadline.",
            },
            .hypotheses = &.{
                "Hypothesis 1: Target server processing latency exceeds timeout.",
                "Hypothesis 2: Network congestion or packet loss during data transfer.",
            },
            .recommended_actions = &.{
                "Increase timeout with '--timeout <ms>'.",
            },
            .context_notes = null,
        },
        .cancelled => .{
            .summary = "HTTPS probe was cancelled before completion.",
            .observed_facts = &.{
                "Cancellation token was signaled during execution.",
            },
            .hypotheses = &.{
                "Hypothesis 1: Assessment deadline expired or user interrupted operation.",
            },
            .recommended_actions = &.{
                "Retry operation without cancellation.",
            },
            .context_notes = null,
        },
        .malformed_input => .{
            .summary = "Invalid HTTPS target URL or port syntax.",
            .observed_facts = &.{
                "URL parser could not parse target address.",
            },
            .hypotheses = &.{
                "Hypothesis 1: Missing host, invalid port number, or malformed URI scheme.",
            },
            .recommended_actions = &.{
                "Provide URL in format 'https://host[:port][/path]'.",
            },
            .context_notes = null,
        },
        .operational_failure => .{
            .summary = "Internal operational failure occurred during HTTPS probe.",
            .observed_facts = &.{
                "OS socket or memory allocation failure occurred.",
            },
            .hypotheses = &.{
                "Hypothesis 1: System resource exhaustion.",
            },
            .recommended_actions = &.{
                "Check system resources and permissions.",
            },
            .context_notes = null,
        },
    };
}

test "generate https troubleshooting for all failure categories" {
    const categories = [_]HttpsFailureCategory{
        .success,
        .redirect_out_of_scope,
        .redirect_loop,
        .redirect_limit_exceeded,
        .response_size_exceeded,
        .http_protocol_error,
        .tls_certificate_expired,
        .tls_certificate_not_yet_valid,
        .tls_hostname_mismatch,
        .tls_untrusted_chain,
        .tls_handshake_failed,
        .tcp_connection_failed,
        .timeout,
        .cancelled,
        .malformed_input,
        .operational_failure,
    };

    for (categories) |cat| {
        const dummy = HttpsProbeResult{
            .target_url = "https://example.com/",
            .effective_url = "https://example.com/",
            .host = "example.com",
            .port = 443,
            .scheme = "https",
            .status_code = if (cat == .success) 200 else 0,
            .status_line = if (cat == .success) "HTTP/1.1 200 OK" else "none",
            .failure_category = cat,
            .elapsed_ns = 5_000_000,
            .timing_stages = .{},
        };

        const tb = generateHttpsTroubleshooting(&dummy);
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
