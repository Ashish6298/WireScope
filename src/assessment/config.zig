const std = @import("std");
const testing = std.testing;

pub const ConfigValidationError = error{
    TimeoutTooLow,
    TimeoutTooHigh,
    ExcessiveConcurrency,
    ZeroConcurrency,
    ExcessiveRetries,
    ExcessiveOperationLimit,
    InvalidDataDirectory,
};

pub const TimeoutConfig = struct {
    default_timeout_ms: u32 = 5000,
    connect_timeout_ms: u32 = 3000,
    total_assessment_deadline_s: u32 = 300,
};

pub const ConcurrencyConfig = struct {
    max_parallel_probes: u16 = 10,
    rate_limit_per_second: u16 = 20,
};

pub const LimitConfig = struct {
    max_retries: u8 = 1,
    max_response_size_bytes: usize = 64 * 1024, // 64 KB safety buffer
    max_hosts: usize = 256,
    max_ports_per_host: usize = 100,
    max_total_operations: usize = 1000,
};

pub const StorageConfig = struct {
    data_dir: []const u8 = "data",
    auto_prune_days: u32 = 30,
};

pub const OutputConfig = struct {
    default_format: []const u8 = "terminal",
    redact_sensitive: bool = true,
};

/// Master WireScope Global Configuration (Version 1)
pub const WireScopeConfig = struct {
    version: u32 = 1,
    timeouts: TimeoutConfig = .{},
    concurrency: ConcurrencyConfig = .{},
    limits: LimitConfig = .{},
    storage: StorageConfig = .{},
    output: OutputConfig = .{},

    /// Hard safety constraints preventing dangerous operational expansion
    pub const HARD_MAX_CONCURRENCY: u16 = 50;
    pub const HARD_MIN_TIMEOUT_MS: u32 = 100;
    pub const HARD_MAX_TIMEOUT_MS: u32 = 60000;
    pub const HARD_MAX_RETRIES: u8 = 3;
    pub const HARD_MAX_TOTAL_OPERATIONS: usize = 5000;

    /// Validates configuration values against safe bounds
    pub fn validate(self: *const WireScopeConfig) ConfigValidationError!void {
        if (self.timeouts.default_timeout_ms < HARD_MIN_TIMEOUT_MS) return error.TimeoutTooLow;
        if (self.timeouts.default_timeout_ms > HARD_MAX_TIMEOUT_MS) return error.TimeoutTooHigh;
        if (self.timeouts.connect_timeout_ms < HARD_MIN_TIMEOUT_MS) return error.TimeoutTooLow;
        if (self.timeouts.connect_timeout_ms > HARD_MAX_TIMEOUT_MS) return error.TimeoutTooHigh;

        if (self.concurrency.max_parallel_probes == 0) return error.ZeroConcurrency;
        if (self.concurrency.max_parallel_probes > HARD_MAX_CONCURRENCY) return error.ExcessiveConcurrency;

        if (self.limits.max_retries > HARD_MAX_RETRIES) return error.ExcessiveRetries;
        if (self.limits.max_total_operations > HARD_MAX_TOTAL_OPERATIONS) return error.ExcessiveOperationLimit;

        if (self.storage.data_dir.len == 0) return error.InvalidDataDirectory;
    }

    /// Parses configuration from JSON string
    pub fn parseFromJson(allocator: std.mem.Allocator, json_slice: []const u8) !WireScopeConfig {
        const parsed = try std.json.parseFromSlice(WireScopeConfig, allocator, json_slice, .{
            .ignore_unknown_fields = false,
        });
        defer parsed.deinit();

        const cfg = parsed.value;
        try cfg.validate();
        return cfg;
    }
};

test "default configuration is valid" {
    const config = WireScopeConfig{};
    try config.validate();
    try testing.expectEqual(@as(u32, 1), config.version);
    try testing.expectEqual(@as(u16, 10), config.concurrency.max_parallel_probes);
}

test "validation rejects invalid timeouts and excessive concurrency" {
    var bad_timeout = WireScopeConfig{};
    bad_timeout.timeouts.default_timeout_ms = 10;
    try testing.expectError(error.TimeoutTooLow, bad_timeout.validate());

    var high_timeout = WireScopeConfig{};
    high_timeout.timeouts.default_timeout_ms = 100000;
    try testing.expectError(error.TimeoutTooHigh, high_timeout.validate());

    var bad_conc = WireScopeConfig{};
    bad_conc.concurrency.max_parallel_probes = 100;
    try testing.expectError(error.ExcessiveConcurrency, bad_conc.validate());

    var zero_conc = WireScopeConfig{};
    zero_conc.concurrency.max_parallel_probes = 0;
    try testing.expectError(error.ZeroConcurrency, zero_conc.validate());

    var bad_retries = WireScopeConfig{};
    bad_retries.limits.max_retries = 10;
    try testing.expectError(error.ExcessiveRetries, bad_retries.validate());
}

test "parse valid json configuration" {
    const json_str =
        \\{
        \\  "version": 1,
        \\  "timeouts": {
        \\    "default_timeout_ms": 4000,
        \\    "connect_timeout_ms": 2000,
        \\    "total_assessment_deadline_s": 120
        \\  },
        \\  "concurrency": {
        \\    "max_parallel_probes": 5,
        \\    "rate_limit_per_second": 10
        \\  },
        \\  "limits": {
        \\    "max_retries": 1,
        \\    "max_response_size_bytes": 32768,
        \\    "max_hosts": 16,
        \\    "max_ports_per_host": 50,
        \\    "max_total_operations": 500
        \\  },
        \\  "storage": {
        \\    "data_dir": "data",
        \\    "auto_prune_days": 14
        \\  },
        \\  "output": {
        \\    "default_format": "json",
        \\    "redact_sensitive": true
        \\  }
        \\}
    ;

    const parsed = try WireScopeConfig.parseFromJson(testing.allocator, json_str);
    try testing.expectEqual(@as(u32, 4000), parsed.timeouts.default_timeout_ms);
    try testing.expectEqual(@as(u16, 5), parsed.concurrency.max_parallel_probes);
    try testing.expectEqual(@as(usize, 500), parsed.limits.max_total_operations);
}
