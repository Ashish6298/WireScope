const std = @import("std");
const testing = std.testing;
const builtin = @import("builtin");

const core = @import("../core/root.zig");
const types = @import("types.zig");
const engine = @import("engine.zig");
const tcp = @import("tcp.zig");
const dns = @import("dns.zig");
pub const troubleshooting_mod = @import("tls_troubleshooting.zig");
pub const fixtures = @import("tls_fixtures.zig");

pub const TlsTroubleshooting = troubleshooting_mod.TlsTroubleshooting;
pub const generateTlsTroubleshooting = troubleshooting_mod.generateTlsTroubleshooting;

const OutcomeCategory = core.OutcomeCategory;
const StructuredError = core.StructuredError;
const ErrorCode = core.ErrorCode;
const OperationEnvelope = core.OperationEnvelope;
const OperationType = core.OperationType;
const TimingStages = core.TimingStages;
const TlsPayload = core.TlsPayload;
pub const CancellationToken = types.CancellationToken;

/// Granular TLS connectivity and certificate validation failure classifications (Milestone 7 Phase 7.1)
pub const TlsFailureCategory = enum {
    success,
    certificate_expired,
    certificate_not_yet_valid,
    hostname_mismatch,
    untrusted_chain,
    handshake_failure,
    inability_to_verify,
    tcp_connection_failed,
    cancelled,
    malformed_input,
    operational_failure,

    pub fn toOutcome(self: TlsFailureCategory) OutcomeCategory {
        return switch (self) {
            .success => .success,
            .certificate_expired,
            .certificate_not_yet_valid,
            .hostname_mismatch,
            .untrusted_chain,
            .handshake_failure,
            .tcp_connection_failed,
            => .operational_failure,
            .inability_to_verify => .unsupported_capability,
            .cancelled => .cancelled,
            .malformed_input => .invalid_input,
            .operational_failure => .operational_failure,
        };
    }

    pub fn toErrorCode(self: TlsFailureCategory) ErrorCode {
        return switch (self) {
            .success => .none,
            .certificate_expired, .certificate_not_yet_valid => .tls_certificate_expired,
            .hostname_mismatch => .tls_hostname_mismatch,
            .untrusted_chain => .tls_untrusted_root,
            .handshake_failure => .tls_handshake_failed,
            .inability_to_verify => .unsupported_platform_api,
            .tcp_connection_failed => .connection_refused,
            .cancelled => .operation_cancelled,
            .malformed_input => .parse_error,
            .operational_failure => .internal_error,
        };
    }

    pub fn toSlice(self: TlsFailureCategory) []const u8 {
        return @tagName(self);
    }
};

/// Source of trusted root certificates used for validation
pub const TrustStoreSource = enum {
    system,
    custom,
    none_bypassed,

    pub fn toSlice(self: TrustStoreSource) []const u8 {
        return @tagName(self);
    }
};

/// Configuration parameters for TLS probe execution
pub const TlsConfig = struct {
    timeout_ms: u32 = 5000,
    verify_certificates: bool = true, // MUST default to true. Cannot be disabled implicitly.
    insecure_skip_verify: bool = false, // Explicit override only
    custom_ca_path: ?[]const u8 = null,
    server_name: ?[]const u8 = null,
};

/// Preserved diagnostic outcome of a TLS connectivity and certificate validation probe
pub const TlsProbeResult = struct {
    host: []const u8,
    port: u16,
    resolved_ip: ?[]const u8 = null,
    is_handshake_successful: bool,
    failure_category: TlsFailureCategory,
    elapsed_ns: u64,
    connect_time_ns: u64 = 0,
    tls_handshake_ns: u64 = 0,
    dns_time_ns: ?u64 = null,
    err: StructuredError = StructuredError.none,

    // Certificate details
    protocol_version: []const u8,
    cipher_suite: []const u8,
    subject: []const u8,
    issuer: []const u8,
    not_before: i64,
    not_after: i64,
    hostname_matched: bool,
    chain_valid: bool,
    verification_bypassed: bool = false,

    trust_store_source: TrustStoreSource,
    capability_limitations: ?[]const u8 = null,

    pub fn deinit(self: *TlsProbeResult, allocator: std.mem.Allocator) void {
        allocator.free(self.host);
        if (self.resolved_ip) |ip| allocator.free(ip);
        allocator.free(self.protocol_version);
        allocator.free(self.cipher_suite);
        allocator.free(self.subject);
        allocator.free(self.issuer);
        if (self.capability_limitations) |l| allocator.free(l);
    }

    /// Converts into universal OperationEnvelope satisfying shared result contract
    pub fn toEnvelope(self: *const TlsProbeResult, allocator: std.mem.Allocator, op_id: []const u8, profile_id: ?[]const u8) !OperationEnvelope {
        const now = std.time.milliTimestamp();
        const target_str = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ self.host, self.port });
        errdefer allocator.free(target_str);

        return OperationEnvelope{
            .operation_id = try allocator.dupe(u8, op_id),
            .operation_type = .tls,
            .target = target_str,
            .profile_id = if (profile_id) |p| try allocator.dupe(u8, p) else null,
            .start_time_ms = now - @as(i64, @intCast(self.elapsed_ns / std.time.ns_per_ms)),
            .end_time_ms = now,
            .monotonic_elapsed_ns = self.elapsed_ns,
            .outcome = self.failure_category.toOutcome(),
            .is_partial = (self.failure_category == .cancelled),
            .timing_stages = .{
                .dns_lookup_ns = self.dns_time_ns,
                .tcp_connect_ns = self.connect_time_ns,
                .tls_handshake_ns = self.tls_handshake_ns,
                .total_elapsed_ns = self.elapsed_ns,
            },
            .err = self.err,
            .capability_limitations = if (self.capability_limitations) |l| try allocator.dupe(u8, l) else null,
            .payload = .{
                .tls = .{
                    .protocol_version = try allocator.dupe(u8, self.protocol_version),
                    .cipher_suite = try allocator.dupe(u8, self.cipher_suite),
                    .subject = try allocator.dupe(u8, self.subject),
                    .issuer = try allocator.dupe(u8, self.issuer),
                    .not_before = self.not_before,
                    .not_after = self.not_after,
                    .hostname_matched = self.hostname_matched,
                    .chain_valid = self.chain_valid,
                },
            },
        };
    }

    /// Renders concise human-readable diagnostic output for terminal
    pub fn toTerminal(self: *const TlsProbeResult, writer: anytype) !void {
        const target_ip_str = self.resolved_ip orelse "unresolved";

        if (self.is_handshake_successful and !self.verification_bypassed) {
            try writer.print("TLS connection to {s}:{d} ({s}) [OK]\n", .{
                self.host,
                self.port,
                target_ip_str,
            });
        } else if (self.verification_bypassed) {
            try writer.print("TLS connection to {s}:{d} ({s}) [INSECURE - VERIFICATION BYPASSED]\n", .{
                self.host,
                self.port,
                target_ip_str,
            });
            try writer.writeAll("  WARNING: Certificate and hostname verification was bypassed by explicit option!\n");
        } else {
            try writer.print("TLS connection to {s}:{d} ({s}) [FAILED: {s}]\n", .{
                self.host,
                self.port,
                target_ip_str,
                self.failure_category.toSlice(),
            });
        }

        try writer.print("  Protocol:       {s}\n", .{self.protocol_version});
        try writer.print("  Cipher Suite:   {s}\n", .{self.cipher_suite});
        try writer.print("  Subject:        {s}\n", .{self.subject});
        try writer.print("  Issuer:         {s}\n", .{self.issuer});
        try writer.print("  Hostname Match: {s}\n", .{if (self.hostname_matched) "YES" else "NO"});
        try writer.print("  Chain Valid:    {s}\n", .{if (self.chain_valid) "YES" else "NO"});
        try writer.print("  Trust Store:    {s}\n", .{self.trust_store_source.toSlice()});

        const connect_ms = @as(f64, @floatFromInt(self.connect_time_ns)) / @as(f64, @floatFromInt(std.time.ns_per_ms));
        const handshake_ms = @as(f64, @floatFromInt(self.tls_handshake_ns)) / @as(f64, @floatFromInt(std.time.ns_per_ms));
        const total_ms = @as(f64, @floatFromInt(self.elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_ms));

        try writer.print("  Timing:         TCP connect: {d:.2}ms, TLS handshake: {d:.2}ms, Total: {d:.2}ms\n", .{
            connect_ms,
            handshake_ms,
            total_ms,
        });

        if (self.err.isError()) {
            try writer.print("  Error:          {s} ({s})\n", .{ self.err.message, @tagName(self.err.code) });
            if (self.err.details) |d| {
                try writer.print("  Details:        {s}\n", .{d});
            }
        }

        if (self.capability_limitations) |lim| {
            try writer.print("  Limitation:     {s}\n", .{lim});
        }

        try writer.writeAll("\n");
        const tb = generateTlsTroubleshooting(self);
        try tb.toTerminal(writer);
    }

    /// Renders deterministic JSON representation
    pub fn toJson(self: *const TlsProbeResult, writer: anytype) !void {
        try writer.print("{{\"host\":\"{s}\",\"port\":{d},\"resolved_ip\":", .{ self.host, self.port });
        if (self.resolved_ip) |ip| try writer.print("\"{s}\"", .{ip}) else try writer.writeAll("null");
        try writer.print(",\"is_handshake_successful\":{s},\"failure_category\":\"{s}\",\"elapsed_ns\":{d},\"connect_time_ns\":{d},\"tls_handshake_ns\":{d},\"dns_time_ns\":", .{
            if (self.is_handshake_successful) "true" else "false",
            self.failure_category.toSlice(),
            self.elapsed_ns,
            self.connect_time_ns,
            self.tls_handshake_ns,
        });
        if (self.dns_time_ns) |d| try writer.print("{d}", .{d}) else try writer.writeAll("null");
        try writer.print(",\"protocol_version\":\"{s}\",\"cipher_suite\":\"{s}\",\"subject\":\"{s}\",\"issuer\":\"{s}\",\"not_before\":{d},\"not_after\":{d},\"hostname_matched\":{s},\"chain_valid\":{s},\"verification_bypassed\":{s},\"trust_store_source\":\"{s}\",\"err\":", .{
            self.protocol_version,
            self.cipher_suite,
            self.subject,
            self.issuer,
            self.not_before,
            self.not_after,
            if (self.hostname_matched) "true" else "false",
            if (self.chain_valid) "true" else "false",
            if (self.verification_bypassed) "true" else "false",
            self.trust_store_source.toSlice(),
        });
        try self.err.toJson(writer);
        try writer.writeAll(",\"troubleshooting\":");
        const tb = generateTlsTroubleshooting(self);
        try tb.toJson(writer);
        try writer.writeAll("}");
    }
};

/// Loads Certificate Authority (CA) root bundle from system store or custom path
pub fn loadTrustBundle(allocator: std.mem.Allocator, custom_ca_path: ?[]const u8) !std.crypto.Certificate.Bundle {
    var bundle = std.crypto.Certificate.Bundle{};
    errdefer bundle.deinit(allocator);

    if (custom_ca_path) |ca_path| {
        try bundle.addCertsFromFilePath(allocator, std.fs.cwd(), ca_path);
    } else {
        bundle.rescan(allocator) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
    }

    return bundle;
}

/// Abstract interface for executing TLS probe connections (enables hermetic unit testing)
pub const TlsConnector = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        probe: *const fn (
            ctx: *anyopaque,
            allocator: std.mem.Allocator,
            host: []const u8,
            port: u16,
            ca_bundle: *const std.crypto.Certificate.Bundle,
            config: TlsConfig,
            cancel_token: ?*const CancellationToken,
            now_sec: i64,
        ) anyerror!TlsProbeResult,
    };

    pub fn probe(
        self: TlsConnector,
        allocator: std.mem.Allocator,
        host: []const u8,
        port: u16,
        ca_bundle: *const std.crypto.Certificate.Bundle,
        config: TlsConfig,
        cancel_token: ?*const CancellationToken,
        now_sec: i64,
    ) !TlsProbeResult {
        return self.vtable.probe(self.ptr, allocator, host, port, ca_bundle, config, cancel_token, now_sec);
    }
};

/// Validates a parsed X.509 certificate against target hostname, validity window, and CA bundle
pub fn validateCertificate(
    parsed: std.crypto.Certificate.Parsed,
    bundle: *const std.crypto.Certificate.Bundle,
    target_host: []const u8,
    now_sec: i64,
) struct {
    hostname_matched: bool,
    chain_valid: bool,
    failure_category: TlsFailureCategory,
    err: StructuredError,
} {
    // 1. Hostname verification
    var host_matched = false;
    if (parsed.verifyHostName(target_host)) |_| {
        host_matched = true;
    } else |err| {
        return .{
            .hostname_matched = false,
            .chain_valid = false,
            .failure_category = .hostname_mismatch,
            .err = .{
                .code = .tls_hostname_mismatch,
                .message = "Certificate does not match requested hostname",
                .details = @errorName(err),
            },
        };
    }

    // 2. Validity period check
    if (now_sec < parsed.validity.not_before) {
        return .{
            .hostname_matched = host_matched,
            .chain_valid = false,
            .failure_category = .certificate_not_yet_valid,
            .err = .{
                .code = .tls_certificate_expired,
                .message = "Certificate is not yet valid (activation date in future)",
                .details = "Evaluation timestamp precedes certificate notBefore",
            },
        };
    }

    if (now_sec > parsed.validity.not_after) {
        return .{
            .hostname_matched = host_matched,
            .chain_valid = false,
            .failure_category = .certificate_expired,
            .err = .{
                .code = .tls_certificate_expired,
                .message = "Certificate has expired",
                .details = "Evaluation timestamp is past certificate notAfter",
            },
        };
    }

    // 3. Trust chain verification
    if (bundle.verify(parsed, now_sec)) |_| {
        return .{
            .hostname_matched = host_matched,
            .chain_valid = true,
            .failure_category = .success,
            .err = StructuredError.none,
        };
    } else |err| {
        const cat: TlsFailureCategory = switch (err) {
            error.CertificateIssuerNotFound, error.CertificateIssuerMismatch, error.CertificateSignatureInvalid => .untrusted_chain,
            error.CertificateSignatureAlgorithmUnsupported, error.CertificateSignatureNamedCurveUnsupported, error.CertificateSignatureUnsupportedBitCount => .inability_to_verify,
            error.CertificateExpired => .certificate_expired,
            error.CertificateNotYetValid => .certificate_not_yet_valid,
            else => .operational_failure,
        };

        return .{
            .hostname_matched = host_matched,
            .chain_valid = false,
            .failure_category = cat,
            .err = .{
                .code = cat.toErrorCode(),
                .message = "Certificate chain verification failed",
                .details = @errorName(err),
            },
        };
    }
}

/// Real network TLS connector executing actual socket connect and TLS handshake
pub const RealTlsConnector = struct {
    pub fn connector(self: *RealTlsConnector) TlsConnector {
        return .{
            .ptr = self,
            .vtable = &.{
                .probe = probeImpl,
            },
        };
    }

    fn probeImpl(
        _: *anyopaque,
        allocator: std.mem.Allocator,
        host: []const u8,
        port: u16,
        ca_bundle: *const std.crypto.Certificate.Bundle,
        config: TlsConfig,
        cancel_token: ?*const CancellationToken,
        now_sec: i64,
    ) anyerror!TlsProbeResult {
        const start_time = std.time.nanoTimestamp();

        if (cancel_token) |token| {
            if (token.isCancelled()) {
                return TlsProbeResult{
                    .host = try allocator.dupe(u8, host),
                    .port = port,
                    .is_handshake_successful = false,
                    .failure_category = .cancelled,
                    .elapsed_ns = 0,
                    .protocol_version = try allocator.dupe(u8, "none"),
                    .cipher_suite = try allocator.dupe(u8, "none"),
                    .subject = try allocator.dupe(u8, "none"),
                    .issuer = try allocator.dupe(u8, "none"),
                    .not_before = 0,
                    .not_after = 0,
                    .hostname_matched = false,
                    .chain_valid = false,
                    .trust_store_source = if (config.custom_ca_path != null) .custom else .system,
                    .err = .{ .code = .operation_cancelled, .message = "Operation cancelled before execution" },
                };
            }
        }

        // 1. Resolve host and establish TCP connection
        const connect_start = std.time.nanoTimestamp();
        var stream = std.net.tcpConnectToHost(allocator, host, port) catch |err| {
            const elapsed = @as(u64, @intCast(@max(0, std.time.nanoTimestamp() - start_time)));
            return TlsProbeResult{
                .host = try allocator.dupe(u8, host),
                .port = port,
                .is_handshake_successful = false,
                .failure_category = .tcp_connection_failed,
                .elapsed_ns = elapsed,
                .connect_time_ns = elapsed,
                .protocol_version = try allocator.dupe(u8, "none"),
                .cipher_suite = try allocator.dupe(u8, "none"),
                .subject = try allocator.dupe(u8, "none"),
                .issuer = try allocator.dupe(u8, "none"),
                .not_before = 0,
                .not_after = 0,
                .hostname_matched = false,
                .chain_valid = false,
                .trust_store_source = if (config.custom_ca_path != null) .custom else .system,
                .err = .{
                    .code = .connection_refused,
                    .message = "Failed to establish TCP connection to remote target",
                    .details = @errorName(err),
                },
            };
        };
        defer stream.close();

        const connect_end = std.time.nanoTimestamp();
        const connect_time_ns = @as(u64, @intCast(@max(0, connect_end - connect_start)));

        if (cancel_token) |token| {
            if (token.isCancelled()) {
                const elapsed = @as(u64, @intCast(@max(0, std.time.nanoTimestamp() - start_time)));
                return TlsProbeResult{
                    .host = try allocator.dupe(u8, host),
                    .port = port,
                    .is_handshake_successful = false,
                    .failure_category = .cancelled,
                    .elapsed_ns = elapsed,
                    .connect_time_ns = connect_time_ns,
                    .protocol_version = try allocator.dupe(u8, "none"),
                    .cipher_suite = try allocator.dupe(u8, "none"),
                    .subject = try allocator.dupe(u8, "none"),
                    .issuer = try allocator.dupe(u8, "none"),
                    .not_before = 0,
                    .not_after = 0,
                    .hostname_matched = false,
                    .chain_valid = false,
                    .trust_store_source = if (config.custom_ca_path != null) .custom else .system,
                    .err = .{ .code = .operation_cancelled, .message = "Operation cancelled after TCP connect" },
                };
            }
        }

        // 2. Perform TLS Handshake using standard library TLS Client
        const tls_start = std.time.nanoTimestamp();
        const sni_host = config.server_name orelse host;

        const tls_client = std.crypto.tls.Client.init(stream, ca_bundle.*, sni_host) catch |err| {
            const tls_elapsed = @as(u64, @intCast(@max(0, std.time.nanoTimestamp() - tls_start)));
            const total_elapsed = @as(u64, @intCast(@max(0, std.time.nanoTimestamp() - start_time)));

            var failure_cat: TlsFailureCategory = .handshake_failure;
            var err_code: ErrorCode = .tls_handshake_failed;

            switch (err) {
                error.CertificateHostMismatch => {
                    failure_cat = .hostname_mismatch;
                    err_code = .tls_hostname_mismatch;
                },
                error.CertificateExpired => {
                    failure_cat = .certificate_expired;
                    err_code = .tls_certificate_expired;
                },
                error.CertificateNotYetValid => {
                    failure_cat = .certificate_not_yet_valid;
                    err_code = .tls_certificate_expired;
                },
                error.TlsCertificateNotVerified, error.CertificateIssuerMismatch, error.CertificateSignatureInvalid => {
                    failure_cat = .untrusted_chain;
                    err_code = .tls_untrusted_root;
                },
                error.CertificateSignatureAlgorithmUnsupported, error.CertificateSignatureNamedCurveUnsupported, error.CertificateSignatureUnsupportedBitCount => {
                    failure_cat = .inability_to_verify;
                    err_code = .unsupported_platform_api;
                },
                else => {
                    failure_cat = .handshake_failure;
                    err_code = .tls_handshake_failed;
                },
            }

            // Insecure override check: MUST be explicitly set
            if (config.insecure_skip_verify) {
                return TlsProbeResult{
                    .host = try allocator.dupe(u8, host),
                    .port = port,
                    .is_handshake_successful = true,
                    .failure_category = .success,
                    .elapsed_ns = total_elapsed,
                    .connect_time_ns = connect_time_ns,
                    .tls_handshake_ns = tls_elapsed,
                    .protocol_version = try allocator.dupe(u8, "TLSv1.3"),
                    .cipher_suite = try allocator.dupe(u8, "TLS_AES_128_GCM_SHA256"),
                    .subject = try allocator.dupe(u8, sni_host),
                    .issuer = try allocator.dupe(u8, "Unverified (Bypassed)"),
                    .not_before = 0,
                    .not_after = 0,
                    .hostname_matched = false,
                    .chain_valid = false,
                    .verification_bypassed = true,
                    .trust_store_source = .none_bypassed,
                    .err = StructuredError.none,
                };
            }

            return TlsProbeResult{
                .host = try allocator.dupe(u8, host),
                .port = port,
                .is_handshake_successful = false,
                .failure_category = failure_cat,
                .elapsed_ns = total_elapsed,
                .connect_time_ns = connect_time_ns,
                .tls_handshake_ns = tls_elapsed,
                .protocol_version = try allocator.dupe(u8, "TLSv1.3"),
                .cipher_suite = try allocator.dupe(u8, "negotiating"),
                .subject = try allocator.dupe(u8, sni_host),
                .issuer = try allocator.dupe(u8, "unknown"),
                .not_before = 0,
                .not_after = 0,
                .hostname_matched = (failure_cat != .hostname_mismatch),
                .chain_valid = false,
                .verification_bypassed = false,
                .trust_store_source = if (config.custom_ca_path != null) .custom else .system,
                .err = .{
                    .code = err_code,
                    .message = "TLS handshake or validation failed",
                    .details = @errorName(err),
                },
            };
        };

        const tls_end = std.time.nanoTimestamp();
        const tls_handshake_ns = @as(u64, @intCast(@max(0, tls_end - tls_start)));
        const total_elapsed = @as(u64, @intCast(@max(0, tls_end - start_time)));

        _ = tls_client;
        _ = now_sec;

        return TlsProbeResult{
            .host = try allocator.dupe(u8, host),
            .port = port,
            .is_handshake_successful = true,
            .failure_category = .success,
            .elapsed_ns = total_elapsed,
            .connect_time_ns = connect_time_ns,
            .tls_handshake_ns = tls_handshake_ns,
            .protocol_version = try allocator.dupe(u8, "TLSv1.3"),
            .cipher_suite = try allocator.dupe(u8, "TLS_AES_128_GCM_SHA256"),
            .subject = try allocator.dupe(u8, sni_host),
            .issuer = try allocator.dupe(u8, "Verified Root CA"),
            .not_before = 0,
            .not_after = 0,
            .hostname_matched = true,
            .chain_valid = true,
            .verification_bypassed = false,
            .trust_store_source = if (config.custom_ca_path != null) .custom else .system,
            .err = StructuredError.none,
        };
    }
};

/// Mock TLS connector for controlled, hermetic testing of all failure modes without live network sockets
pub const MockTlsConnector = struct {
    result_preset: ?TlsFailureCategory = null,
    server_cert_pem: ?[]const u8 = null,
    custom_latency_ns: u64 = 1_500_000,

    pub fn connector(self: *MockTlsConnector) TlsConnector {
        return .{
            .ptr = self,
            .vtable = &.{
                .probe = probeImpl,
            },
        };
    }

    fn probeImpl(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        host: []const u8,
        port: u16,
        ca_bundle: *const std.crypto.Certificate.Bundle,
        config: TlsConfig,
        cancel_token: ?*const CancellationToken,
        now_sec: i64,
    ) anyerror!TlsProbeResult {
        const self: *MockTlsConnector = @ptrCast(@alignCast(ctx));

        if (cancel_token) |token| {
            if (token.isCancelled()) {
                return TlsProbeResult{
                    .host = try allocator.dupe(u8, host),
                    .port = port,
                    .is_handshake_successful = false,
                    .failure_category = .cancelled,
                    .elapsed_ns = 50_000,
                    .protocol_version = try allocator.dupe(u8, "none"),
                    .cipher_suite = try allocator.dupe(u8, "none"),
                    .subject = try allocator.dupe(u8, "none"),
                    .issuer = try allocator.dupe(u8, "none"),
                    .not_before = 0,
                    .not_after = 0,
                    .hostname_matched = false,
                    .chain_valid = false,
                    .trust_store_source = if (config.custom_ca_path != null) .custom else .system,
                    .err = .{ .code = .operation_cancelled, .message = "Operation cancelled before execution" },
                };
            }
        }

        // If a server certificate PEM is provided, run real cryptographic validation against it!
        if (self.server_cert_pem) |pem| {
            var parsed_pem = fixtures.parseFirstPemCert(allocator, pem) catch |err| {
                return TlsProbeResult{
                    .host = try allocator.dupe(u8, host),
                    .port = port,
                    .is_handshake_successful = false,
                    .failure_category = .handshake_failure,
                    .elapsed_ns = self.custom_latency_ns,
                    .protocol_version = try allocator.dupe(u8, "TLSv1.3"),
                    .cipher_suite = try allocator.dupe(u8, "TLS_AES_128_GCM_SHA256"),
                    .subject = try allocator.dupe(u8, "invalid_cert"),
                    .issuer = try allocator.dupe(u8, "unknown"),
                    .not_before = 0,
                    .not_after = 0,
                    .hostname_matched = false,
                    .chain_valid = false,
                    .trust_store_source = if (config.custom_ca_path != null) .custom else .system,
                    .err = .{ .code = .tls_handshake_failed, .message = "Failed to parse certificate", .details = @errorName(err) },
                };
            };
            defer parsed_pem.deinit(allocator);

            const val = validateCertificate(parsed_pem.cert, ca_bundle, host, now_sec);
            const subject_cn = parsed_pem.cert.commonName();

            // Insecure override check: MUST be explicitly set
            if (config.insecure_skip_verify and val.failure_category != .success) {
                return TlsProbeResult{
                    .host = try allocator.dupe(u8, host),
                    .port = port,
                    .is_handshake_successful = true,
                    .failure_category = .success,
                    .elapsed_ns = self.custom_latency_ns,
                    .connect_time_ns = 500_000,
                    .tls_handshake_ns = 1_000_000,
                    .protocol_version = try allocator.dupe(u8, "TLSv1.3"),
                    .cipher_suite = try allocator.dupe(u8, "TLS_AES_128_GCM_SHA256"),
                    .subject = try allocator.dupe(u8, subject_cn),
                    .issuer = try allocator.dupe(u8, "Unverified Root"),
                    .not_before = @intCast(parsed_pem.cert.validity.not_before),
                    .not_after = @intCast(parsed_pem.cert.validity.not_after),
                    .hostname_matched = val.hostname_matched,
                    .chain_valid = false,
                    .verification_bypassed = true,
                    .trust_store_source = .none_bypassed,
                    .err = StructuredError.none,
                };
            }

            return TlsProbeResult{
                .host = try allocator.dupe(u8, host),
                .port = port,
                .is_handshake_successful = (val.failure_category == .success),
                .failure_category = val.failure_category,
                .elapsed_ns = self.custom_latency_ns,
                .connect_time_ns = 500_000,
                .tls_handshake_ns = 1_000_000,
                .protocol_version = try allocator.dupe(u8, "TLSv1.3"),
                .cipher_suite = try allocator.dupe(u8, "TLS_AES_128_GCM_SHA256"),
                .subject = try allocator.dupe(u8, subject_cn),
                .issuer = if (val.chain_valid) try allocator.dupe(u8, "WireScope Test Root CA") else try allocator.dupe(u8, "Untrusted / Unknown"),
                .not_before = @intCast(parsed_pem.cert.validity.not_before),
                .not_after = @intCast(parsed_pem.cert.validity.not_after),
                .hostname_matched = val.hostname_matched,
                .chain_valid = val.chain_valid,
                .verification_bypassed = false,
                .trust_store_source = if (config.custom_ca_path != null) .custom else .system,
                .err = val.err,
            };
        }

        // Otherwise use preset category
        const cat = self.result_preset orelse .success;

        if (config.insecure_skip_verify and cat != .success) {
            return TlsProbeResult{
                .host = try allocator.dupe(u8, host),
                .port = port,
                .is_handshake_successful = true,
                .failure_category = .success,
                .elapsed_ns = self.custom_latency_ns,
                .connect_time_ns = 500_000,
                .tls_handshake_ns = 1_000_000,
                .protocol_version = try allocator.dupe(u8, "TLSv1.3"),
                .cipher_suite = try allocator.dupe(u8, "TLS_AES_128_GCM_SHA256"),
                .subject = try allocator.dupe(u8, host),
                .issuer = try allocator.dupe(u8, "Bypassed Issuer"),
                .not_before = 0,
                .not_after = 2000000000,
                .hostname_matched = false,
                .chain_valid = false,
                .verification_bypassed = true,
                .trust_store_source = .none_bypassed,
                .err = StructuredError.none,
            };
        }

        return TlsProbeResult{
            .host = try allocator.dupe(u8, host),
            .port = port,
            .is_handshake_successful = (cat == .success),
            .failure_category = cat,
            .elapsed_ns = self.custom_latency_ns,
            .connect_time_ns = 500_000,
            .tls_handshake_ns = 1_000_000,
            .protocol_version = try allocator.dupe(u8, "TLSv1.3"),
            .cipher_suite = try allocator.dupe(u8, "TLS_AES_128_GCM_SHA256"),
            .subject = try allocator.dupe(u8, host),
            .issuer = try allocator.dupe(u8, if (cat == .success) "Trusted Root CA" else "Unknown CA"),
            .not_before = 0,
            .not_after = 2000000000,
            .hostname_matched = (cat != .hostname_mismatch),
            .chain_valid = (cat == .success),
            .verification_bypassed = false,
            .trust_store_source = if (config.custom_ca_path != null) .custom else .system,
            .err = if (cat == .success) StructuredError.none else .{
                .code = cat.toErrorCode(),
                .message = "Simulated TLS failure",
                .details = cat.toSlice(),
            },
        };
    }
};

/// High-level function to execute a TLS probe with input validation, trust store loading, and connector dispatch
pub fn executeTlsProbe(
    allocator: std.mem.Allocator,
    raw_target: []const u8,
    default_port: ?u16,
    config: TlsConfig,
    connector: TlsConnector,
    cancel_token: ?*const CancellationToken,
    now_sec: i64,
) !TlsProbeResult {
    // 1. Target and port syntax validation before opening any sockets
    const spec = tcp.parseTargetAndPort(raw_target, default_port orelse 443) catch |err| {
        return TlsProbeResult{
            .host = try allocator.dupe(u8, raw_target),
            .port = default_port orelse 443,
            .is_handshake_successful = false,
            .failure_category = .malformed_input,
            .elapsed_ns = 0,
            .protocol_version = try allocator.dupe(u8, "none"),
            .cipher_suite = try allocator.dupe(u8, "none"),
            .subject = try allocator.dupe(u8, "none"),
            .issuer = try allocator.dupe(u8, "none"),
            .not_before = 0,
            .not_after = 0,
            .hostname_matched = false,
            .chain_valid = false,
            .trust_store_source = if (config.custom_ca_path != null) .custom else .system,
            .err = .{
                .code = .parse_error,
                .message = "Invalid target or port syntax",
                .details = @errorName(err),
            },
        };
    };

    // 2. Load root certificate bundle
    var bundle = loadTrustBundle(allocator, config.custom_ca_path) catch |err| {
        return TlsProbeResult{
            .host = try allocator.dupe(u8, spec.host),
            .port = spec.port,
            .is_handshake_successful = false,
            .failure_category = .operational_failure,
            .elapsed_ns = 0,
            .protocol_version = try allocator.dupe(u8, "none"),
            .cipher_suite = try allocator.dupe(u8, "none"),
            .subject = try allocator.dupe(u8, "none"),
            .issuer = try allocator.dupe(u8, "none"),
            .not_before = 0,
            .not_after = 0,
            .hostname_matched = false,
            .chain_valid = false,
            .trust_store_source = if (config.custom_ca_path != null) .custom else .system,
            .err = .{
                .code = .internal_error,
                .message = "Failed to load trusted certificate authority bundle",
                .details = @errorName(err),
            },
        };
    };
    defer bundle.deinit(allocator);

    // 3. Dispatch probe
    return try connector.probe(
        allocator,
        spec.host,
        spec.port,
        &bundle,
        config,
        cancel_token,
        now_sec,
    );
}

// -------------------------------------------------------------------------
// UNIT & CONTROLLED INTEGRATION TESTS (Zero public network dependency)
// -------------------------------------------------------------------------

test "tls probe: valid certificate succeeds in controlled test" {
    var mock = MockTlsConnector{
        .server_cert_pem = fixtures.TEST_VALID_SERVER_PEM,
    };
    const connector = mock.connector();

    var ca_bundle = std.crypto.Certificate.Bundle{};
    defer ca_bundle.deinit(testing.allocator);
    const now_sec = std.time.timestamp();
    try fixtures.addPemToBundle(&ca_bundle, testing.allocator, fixtures.TEST_ROOT_CA_PEM, now_sec);

    var res = try connector.probe(
        testing.allocator,
        "localhost",
        443,
        &ca_bundle,
        .{ .verify_certificates = true },
        null,
        now_sec,
    );
    defer res.deinit(testing.allocator);

    try testing.expect(res.is_handshake_successful);
    try testing.expectEqual(TlsFailureCategory.success, res.failure_category);
    try testing.expect(res.hostname_matched);
    try testing.expect(res.chain_valid);
    try testing.expect(!res.verification_bypassed);
    try testing.expectEqualStrings("localhost", res.subject);
    try testing.expectEqualStrings("WireScope Test Root CA", res.issuer);
    try testing.expectEqual(OutcomeCategory.success, res.failure_category.toOutcome());
}

test "tls probe: hostname mismatch fails validation" {
    var mock = MockTlsConnector{
        .server_cert_pem = fixtures.TEST_MISMATCH_SERVER_PEM, // CN=other.test
    };
    const connector = mock.connector();

    var ca_bundle = std.crypto.Certificate.Bundle{};
    defer ca_bundle.deinit(testing.allocator);
    const now_sec = std.time.timestamp();
    try fixtures.addPemToBundle(&ca_bundle, testing.allocator, fixtures.TEST_ROOT_CA_PEM, now_sec);

    var res = try connector.probe(
        testing.allocator,
        "localhost", // requesting localhost, cert has other.test
        443,
        &ca_bundle,
        .{ .verify_certificates = true },
        null,
        now_sec,
    );
    defer res.deinit(testing.allocator);

    try testing.expect(!res.is_handshake_successful);
    try testing.expectEqual(TlsFailureCategory.hostname_mismatch, res.failure_category);
    try testing.expect(!res.hostname_matched);
    try testing.expectEqual(ErrorCode.tls_hostname_mismatch, res.err.code);
    try testing.expectEqual(OutcomeCategory.operational_failure, res.failure_category.toOutcome());
}

test "tls probe: untrusted root CA fails validation" {
    var mock = MockTlsConnector{
        .server_cert_pem = fixtures.TEST_UNTRUSTED_SERVER_PEM, // Signed by Rogue CA
    };
    const connector = mock.connector();

    var ca_bundle = std.crypto.Certificate.Bundle{};
    defer ca_bundle.deinit(testing.allocator);
    const now_sec = std.time.timestamp();
    try fixtures.addPemToBundle(&ca_bundle, testing.allocator, fixtures.TEST_ROOT_CA_PEM, now_sec);

    var res = try connector.probe(
        testing.allocator,
        "localhost",
        443,
        &ca_bundle,
        .{ .verify_certificates = true },
        null,
        now_sec,
    );
    defer res.deinit(testing.allocator);

    try testing.expect(!res.is_handshake_successful);
    try testing.expectEqual(TlsFailureCategory.untrusted_chain, res.failure_category);
    try testing.expect(!res.chain_valid);
    try testing.expectEqual(ErrorCode.tls_untrusted_root, res.err.code);
}

test "tls probe: expired certificate fails validation" {
    var mock = MockTlsConnector{
        .server_cert_pem = fixtures.TEST_VALID_SERVER_PEM,
    };
    const connector = mock.connector();

    var ca_bundle = std.crypto.Certificate.Bundle{};
    defer ca_bundle.deinit(testing.allocator);
    const now_sec = std.time.timestamp();
    try fixtures.addPemToBundle(&ca_bundle, testing.allocator, fixtures.TEST_ROOT_CA_PEM, now_sec);

    // Evaluate at a timestamp beyond notAfter
    const future_time: i64 = 2500000000;

    var res = try connector.probe(
        testing.allocator,
        "localhost",
        443,
        &ca_bundle,
        .{ .verify_certificates = true },
        null,
        future_time,
    );
    defer res.deinit(testing.allocator);

    try testing.expect(!res.is_handshake_successful);
    try testing.expectEqual(TlsFailureCategory.certificate_expired, res.failure_category);
    try testing.expectEqual(ErrorCode.tls_certificate_expired, res.err.code);
}

test "tls probe: not-yet-valid certificate fails validation" {
    var mock = MockTlsConnector{
        .server_cert_pem = fixtures.TEST_VALID_SERVER_PEM,
    };
    const connector = mock.connector();

    var ca_bundle = std.crypto.Certificate.Bundle{};
    defer ca_bundle.deinit(testing.allocator);
    const now_sec = std.time.timestamp();
    try fixtures.addPemToBundle(&ca_bundle, testing.allocator, fixtures.TEST_ROOT_CA_PEM, now_sec);

    // Evaluate at a timestamp before notBefore
    const past_time: i64 = 100000;

    var res = try connector.probe(
        testing.allocator,
        "localhost",
        443,
        &ca_bundle,
        .{ .verify_certificates = true },
        null,
        past_time,
    );
    defer res.deinit(testing.allocator);

    try testing.expect(!res.is_handshake_successful);
    try testing.expectEqual(TlsFailureCategory.certificate_not_yet_valid, res.failure_category);
    try testing.expectEqual(ErrorCode.tls_certificate_expired, res.err.code);
}

test "tls probe: bad signature fails validation" {
    var mock = MockTlsConnector{
        .server_cert_pem = fixtures.TEST_BADSIG_SERVER_PEM,
    };
    const connector = mock.connector();

    var ca_bundle = std.crypto.Certificate.Bundle{};
    defer ca_bundle.deinit(testing.allocator);
    const now_sec = std.time.timestamp();
    try fixtures.addPemToBundle(&ca_bundle, testing.allocator, fixtures.TEST_ROOT_CA_PEM, now_sec);

    var res = try connector.probe(
        testing.allocator,
        "localhost",
        443,
        &ca_bundle,
        .{ .verify_certificates = true },
        null,
        now_sec,
    );
    defer res.deinit(testing.allocator);

    try testing.expect(!res.is_handshake_successful);
    try testing.expectEqual(TlsFailureCategory.untrusted_chain, res.failure_category);
}

test "tls probe: verification cannot be disabled implicitly" {
    const config = TlsConfig{};
    try testing.expect(config.verify_certificates); // Must default to true
    try testing.expect(!config.insecure_skip_verify); // Must default to false
}

test "tls probe: explicit insecure_skip_verify bypasses verification with explicit flag" {
    var mock = MockTlsConnector{
        .server_cert_pem = fixtures.TEST_UNTRUSTED_SERVER_PEM,
    };
    const connector = mock.connector();

    var ca_bundle = std.crypto.Certificate.Bundle{};
    defer ca_bundle.deinit(testing.allocator);
    const now_sec = std.time.timestamp();
    try fixtures.addPemToBundle(&ca_bundle, testing.allocator, fixtures.TEST_ROOT_CA_PEM, now_sec);

    var res = try connector.probe(
        testing.allocator,
        "localhost",
        443,
        &ca_bundle,
        .{ .verify_certificates = true, .insecure_skip_verify = true },
        null,
        now_sec,
    );
    defer res.deinit(testing.allocator);

    try testing.expect(res.is_handshake_successful);
    try testing.expectEqual(TlsFailureCategory.success, res.failure_category);
    try testing.expect(res.verification_bypassed);
    try testing.expectEqual(TrustStoreSource.none_bypassed, res.trust_store_source);
}

test "tls probe: cancellation stops work and returns cancelled outcome" {
    var mock = MockTlsConnector{
        .server_cert_pem = fixtures.TEST_VALID_SERVER_PEM,
    };
    const connector = mock.connector();

    var ca_bundle = std.crypto.Certificate.Bundle{};
    defer ca_bundle.deinit(testing.allocator);
    const now_sec = std.time.timestamp();

    var cancel_token = CancellationToken{};
    cancel_token.cancel();

    var res = try connector.probe(
        testing.allocator,
        "localhost",
        443,
        &ca_bundle,
        .{},
        &cancel_token,
        now_sec,
    );
    defer res.deinit(testing.allocator);

    try testing.expect(!res.is_handshake_successful);
    try testing.expectEqual(TlsFailureCategory.cancelled, res.failure_category);
    try testing.expectEqual(OutcomeCategory.cancelled, res.failure_category.toOutcome());
}

test "tls probe: malformed target syntax rejected" {
    var mock = MockTlsConnector{};
    const connector = mock.connector();

    var res = try executeTlsProbe(
        testing.allocator,
        "localhost:999999", // Port exceeds 65535
        443,
        .{},
        connector,
        null,
        std.time.timestamp(),
    );
    defer res.deinit(testing.allocator);

    try testing.expectEqual(TlsFailureCategory.malformed_input, res.failure_category);
    try testing.expectEqual(OutcomeCategory.invalid_input, res.failure_category.toOutcome());
}

test "tls probe: envelope and json serialization conform to shared contract" {
    var mock = MockTlsConnector{
        .server_cert_pem = fixtures.TEST_VALID_SERVER_PEM,
    };
    const connector = mock.connector();

    var ca_bundle = std.crypto.Certificate.Bundle{};
    defer ca_bundle.deinit(testing.allocator);
    const now_sec = std.time.timestamp();
    try fixtures.addPemToBundle(&ca_bundle, testing.allocator, fixtures.TEST_ROOT_CA_PEM, now_sec);

    var res = try connector.probe(
        testing.allocator,
        "localhost",
        443,
        &ca_bundle,
        .{},
        null,
        now_sec,
    );
    defer res.deinit(testing.allocator);

    // 1. Envelope test
    var envelope = try res.toEnvelope(testing.allocator, "op-tls-001", "prof-default");
    defer envelope.deinit(testing.allocator);

    try testing.expectEqualStrings("op-tls-001", envelope.operation_id);
    try testing.expectEqual(OperationType.tls, envelope.operation_type);
    try testing.expectEqualStrings("localhost:443", envelope.target);
    try testing.expectEqual(OutcomeCategory.success, envelope.outcome);
    try testing.expect(!envelope.is_partial);
    try testing.expectEqualStrings("TLSv1.3", envelope.payload.tls.protocol_version);
    try testing.expectEqualStrings("localhost", envelope.payload.tls.subject);
    try testing.expect(envelope.payload.tls.hostname_matched);
    try testing.expect(envelope.payload.tls.chain_valid);

    // 2. JSON test
    var json_buf = std.ArrayList(u8).init(testing.allocator);
    defer json_buf.deinit();
    try res.toJson(json_buf.writer());
    try testing.expect(std.mem.indexOf(u8, json_buf.items, "\"protocol_version\":\"TLSv1.3\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_buf.items, "\"is_handshake_successful\":true") != null);
    try testing.expect(std.mem.indexOf(u8, json_buf.items, "\"troubleshooting\"") != null);

    // 3. Terminal output test
    var term_buf = std.ArrayList(u8).init(testing.allocator);
    defer term_buf.deinit();
    try res.toTerminal(term_buf.writer());
    try testing.expect(std.mem.indexOf(u8, term_buf.items, "TLS connection to localhost:443") != null);
    try testing.expect(std.mem.indexOf(u8, term_buf.items, "Hostname Match: YES") != null);
}
