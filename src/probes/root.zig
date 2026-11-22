const std = @import("std");
const testing = std.testing;
const core = @import("../core/root.zig");

pub const types = @import("types.zig");
pub const engine = @import("engine.zig");
pub const dns = @import("dns.zig");
pub const tcp = @import("tcp.zig");
pub const tcp_troubleshooting = @import("tcp_troubleshooting.zig");
pub const tls = @import("tls.zig");
pub const tls_troubleshooting = @import("tls_troubleshooting.zig");
pub const tls_fixtures = @import("tls_fixtures.zig");
pub const https = @import("https.zig");
pub const https_troubleshooting = @import("https_troubleshooting.zig");
pub const https_fixtures = @import("https_fixtures.zig");

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

pub const TcpFailureCategory = tcp.TcpFailureCategory;
pub const TargetSpec = tcp.TargetSpec;
pub const parseTargetAndPort = tcp.parseTargetAndPort;
pub const validatePort = tcp.validatePort;
pub const TcpProbeResult = tcp.TcpProbeResult;
pub const TcpConnector = tcp.TcpConnector;
pub const RealTcpConnector = tcp.RealTcpConnector;
pub const MockTcpConnector = tcp.MockTcpConnector;
pub const executeTcpProbeWithEngine = tcp.executeTcpProbeWithEngine;
pub const FailureBreakdown = tcp.FailureBreakdown;
pub const TcpSampleRecord = tcp.TcpSampleRecord;
pub const TcpBatchProbeResult = tcp.TcpBatchProbeResult;
pub const executeTcpBatchProbe = tcp.executeTcpBatchProbe;
pub const TcpTroubleshooting = tcp_troubleshooting.TcpTroubleshooting;
pub const generateSingleTroubleshooting = tcp_troubleshooting.generateSingleTroubleshooting;
pub const generateBatchTroubleshooting = tcp_troubleshooting.generateBatchTroubleshooting;

pub const TlsFailureCategory = tls.TlsFailureCategory;
pub const TrustStoreSource = tls.TrustStoreSource;
pub const TlsConfig = tls.TlsConfig;
pub const TlsProbeResult = tls.TlsProbeResult;
pub const loadTrustBundle = tls.loadTrustBundle;
pub const TlsConnector = tls.TlsConnector;
pub const RealTlsConnector = tls.RealTlsConnector;
pub const MockTlsConnector = tls.MockTlsConnector;
pub const validateCertificate = tls.validateCertificate;
pub const executeTlsProbe = tls.executeTlsProbe;
pub const TlsTroubleshooting = tls_troubleshooting.TlsTroubleshooting;
pub const generateTlsTroubleshooting = tls_troubleshooting.generateTlsTroubleshooting;

pub const HttpsFailureCategory = https.HttpsFailureCategory;
pub const HttpsConfig = https.HttpsConfig;
pub const RedirectHop = https.RedirectHop;
pub const HttpsProbeResult = https.HttpsProbeResult;
pub const ParsedUrl = https.ParsedUrl;
pub const parseUrl = https.parseUrl;
pub const isRedirectPermitted = https.isRedirectPermitted;
pub const HttpsConnector = https.HttpsConnector;
pub const RealHttpsConnector = https.RealHttpsConnector;
pub const MockHttpsConnector = https.MockHttpsConnector;
pub const executeHttpsProbe = https.executeHttpsProbe;
pub const HttpsTroubleshooting = https_troubleshooting.HttpsTroubleshooting;
pub const generateHttpsTroubleshooting = https_troubleshooting.generateHttpsTroubleshooting;

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
    _ = tcp;
    _ = tcp_troubleshooting;
    _ = tls;
    _ = tls_troubleshooting;
    _ = tls_fixtures;
    _ = https;
    _ = https_troubleshooting;
    _ = https_fixtures;
    const config = ProbeConfig{};
    try testing.expectEqual(@as(u32, 5000), config.timeout_ms);
}
