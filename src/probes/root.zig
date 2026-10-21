const std = @import("std");
const testing = std.testing;
const core = @import("../core/root.zig");

pub const types = @import("types.zig");
pub const engine = @import("engine.zig");
pub const dns = @import("dns.zig");

pub const ProbeEngine = engine.ProbeEngine;
pub const EngineConfig = types.EngineConfig;
pub const EngineMetrics = types.EngineMetrics;
pub const CancellationToken = types.CancellationToken;
pub const WorkStatus = types.WorkStatus;
pub const TaskDescriptor = types.TaskDescriptor;
pub const TaskRecord = types.TaskRecord;
pub const TaskFn = types.TaskFn;

pub const DnsRecordType = dns.DnsRecordType;
pub const DnsFailureCategory = dns.DnsFailureCategory;
pub const DnsResolutionResult = dns.DnsResolutionResult;
pub const DnsTroubleshooting = dns.DnsTroubleshooting;
pub const ResolverComparisonEntry = dns.ResolverComparisonEntry;
pub const ResolverComparisonResult = dns.ResolverComparisonResult;
pub const compareResolvers = dns.compareResolvers;
pub const validateHostname = dns.validateHostname;
pub const Resolver = dns.Resolver;
pub const SystemResolver = dns.SystemResolver;
pub const CustomUdpResolver = dns.CustomUdpResolver;
pub const MockResolver = dns.MockResolver;

pub const ProbeType = enum {
    dns,
    tcp,
    tls,
    http,
};

pub const ProbeConfig = struct {
    timeout_ms: u32 = 5000,
    max_retries: u8 = 1,
};

test "probes root exports engine and types" {
    _ = types;
    _ = engine;
    _ = dns;
    const config = ProbeConfig{};
    try testing.expectEqual(@as(u32, 5000), config.timeout_ms);
}
