const std = @import("std");
const testing = std.testing;

pub const LabScenarioId = enum {
    dns_failure,
    tcp_refusal_timeout,
    tls_cert_issues,
    unexpected_listener,
    http_security_header_violation,
    remediation_verification,
};

pub const ScenarioConfig = struct {
    bind_address: []const u8 = "127.0.0.1",
    port: u16 = 0,
};

test "lab definitions compile" {
    const scenario = LabScenarioId.dns_failure;
    try testing.expectEqual(LabScenarioId.dns_failure, scenario);
}
