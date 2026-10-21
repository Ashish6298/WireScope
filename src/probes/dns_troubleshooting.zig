const std = @import("std");
const testing = std.testing;

/// Structured troubleshooting guidance tied directly to observed DNS outcomes
pub const DnsTroubleshooting = struct {
    summary: []const u8,
    possible_causes: []const []const u8,
    recommended_actions: []const []const u8,
    context_notes: ?[]const u8 = null,

    pub fn toJson(self: DnsTroubleshooting, writer: anytype) !void {
        try writer.print("{{\"summary\":\"{s}\",\"possible_causes\":[", .{self.summary});
        for (self.possible_causes, 0..) |cause, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.print("\"{s}\"", .{cause});
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
};

/// Generates concise troubleshooting advice tied to the observed resolution failure category
pub fn generateTroubleshooting(category_name: []const u8, answers_count: usize) DnsTroubleshooting {
    if (std.mem.eql(u8, category_name, "success")) {
        return .{
            .summary = "Domain resolved successfully with active IP addresses.",
            .possible_causes = &.{},
            .recommended_actions = &.{
                "Proceed with TCP/TLS connectivity diagnostics against resolved endpoints.",
            },
            .context_notes = if (answers_count > 1)
                "Multiple IP addresses observed; round-robin DNS or multi-region anycast routing may be active."
            else
                null,
        };
    } else if (std.mem.eql(u8, category_name, "nxdomain")) {
        return .{
            .summary = "Domain does not exist on the queried DNS resolver (NXDOMAIN).",
            .possible_causes = &.{
                "Typographical error in the target hostname.",
                "Domain registration has expired or has not yet been provisioned.",
                "Internal/private hostname queried against a public resolver without proper search domain suffixes.",
                "Recent DNS zone modifications have not propagated through authoritative nameservers.",
            },
            .recommended_actions = &.{
                "Verify spelling and fully-qualified domain name (FQDN).",
                "Check domain registration status and authoritative WHOIS records.",
                "If querying an internal corporate or lab service, ensure VPN or internal DNS resolver is configured.",
            },
            .context_notes = "Authoritative negative response cached according to SOA minimum TTL.",
        };
    } else if (std.mem.eql(u8, category_name, "timeout")) {
        return .{
            .summary = "Resolver query timed out without receiving a response.",
            .possible_causes = &.{
                "Configured DNS resolver is unreachable or unresponsive.",
                "Local network connectivity or default gateway is down.",
                "Firewall or intermediate security appliance is filtering UDP/TCP port 53 traffic.",
                "Severe network congestion or packet loss along the path to the resolver.",
            },
            .recommended_actions = &.{
                "Inspect local interfaces and routes ('wirescope interfaces', 'wirescope routes').",
                "Verify outbound UDP/TCP port 53 access on the local firewall.",
                "Test connectivity with an alternate or internal resolver.",
            },
            .context_notes = "Timeouts indicate network or service unreachability, not domain non-existence.",
        };
    } else if (std.mem.eql(u8, category_name, "no_answer")) {
        return .{
            .summary = "Domain exists (NOERROR) but returned no IP addresses for the requested record type.",
            .possible_causes = &.{
                "The target domain only has IPv4 (A) records, but IPv6 (AAAA) was exclusively requested.",
                "The target domain only has IPv6 (AAAA) records, but IPv4 (A) was exclusively requested.",
                "The record type has not been provisioned by the domain administrator.",
            },
            .recommended_actions = &.{
                "Query dual-stack records ('both' A and AAAA) to check for alternative address families.",
                "Verify zone configuration with the authoritative DNS provider.",
            },
            .context_notes = "NOERROR with 0 answers confirms the domain exists, but the specific record family is absent.",
        };
    } else if (std.mem.eql(u8, category_name, "malformed_input")) {
        return .{
            .summary = "Hostname violates standard DNS naming specifications (RFC 1035 / RFC 1123).",
            .possible_causes = &.{
                "Hostname contains invalid characters (allowed: a-z, 0-9, hyphen).",
                "Hostname contains empty labels (consecutive dots '..').",
                "A label starts or ends with a hyphen ('-').",
                "Hostname exceeds 253 characters or an individual label exceeds 63 characters.",
            },
            .recommended_actions = &.{
                "Correct the hostname syntax before submitting queries.",
                "Ensure hostname labels are alphanumeric and separated by single dots.",
            },
            .context_notes = "Query was rejected locally before any network activity was initiated.",
        };
    } else {
        return .{
            .summary = "Local OS socket or resolver transport subsystem reported an operational error.",
            .possible_causes = &.{
                "Local network stack is uninitialized or disabled.",
                "Operating system DNS client daemon is stopped or unresponsive.",
                "Socket descriptor or ephemeral port exhaustion on the host.",
            },
            .recommended_actions = &.{
                "Verify host network adapter state ('wirescope interfaces').",
                "Check OS DNS client service status ('Dnscache' on Windows, 'systemd-resolved' on Linux).",
            },
            .context_notes = "Operational failures reflect host or OS environment constraints.",
        };
    }
}

/// Generates neutral, evidence-driven explanation for differing answers across resolvers
pub fn explainDisagreement(resolver_a: []const u8, resolver_b: []const u8) []const u8 {
    _ = resolver_a;
    _ = resolver_b;
    return "Differing answers across resolvers are a normal operational occurrence and do NOT indicate DNS poisoning or hijacking. Common architectural reasons include: (1) Split-horizon (split-view) DNS where internal resolvers return private RFC 1918 IPs while external resolvers return public IPs or NXDOMAIN; (2) CDN Anycast and Geo-DNS routing directing users to geographically nearest edge proxies; (3) DNS caching and remaining TTL variations across recursive caches; (4) Resolver policy filtering (e.g., ad-blocking, malware protection, or parental control sinkholing to 0.0.0.0).";
}

test "generate troubleshooting for all failure categories" {
    const success_tb = generateTroubleshooting("success", 1);
    try testing.expect(std.mem.indexOf(u8, success_tb.summary, "resolved successfully") != null);
    try testing.expectEqual(@as(usize, 0), success_tb.possible_causes.len);

    const nx_tb = generateTroubleshooting("nxdomain", 0);
    try testing.expect(nx_tb.possible_causes.len >= 3);
    try testing.expect(nx_tb.recommended_actions.len >= 2);
    try testing.expect(std.mem.indexOf(u8, nx_tb.summary, "NXDOMAIN") != null);

    const timeout_tb = generateTroubleshooting("timeout", 0);
    try testing.expect(std.mem.indexOf(u8, timeout_tb.summary, "timed out") != null);
    try testing.expect(timeout_tb.possible_causes.len >= 3);

    const malformed_tb = generateTroubleshooting("malformed_input", 0);
    try testing.expect(std.mem.indexOf(u8, malformed_tb.summary, "RFC 1035") != null);

    const noans_tb = generateTroubleshooting("no_answer", 0);
    try testing.expect(std.mem.indexOf(u8, noans_tb.summary, "NOERROR") != null);
}

test "explain disagreement provides neutral architectural context" {
    const explanation = explainDisagreement("127.0.0.1", "1.1.1.1");
    // Strictly verify no security conclusions or poisoning accusations are made
    try testing.expect(std.mem.indexOf(u8, explanation, "do NOT indicate DNS poisoning or hijacking") != null);
    try testing.expect(std.mem.indexOf(u8, explanation, "Split-horizon") != null);
    try testing.expect(std.mem.indexOf(u8, explanation, "CDN Anycast") != null);
    try testing.expect(std.mem.indexOf(u8, explanation, "TTL variations") != null);
}
