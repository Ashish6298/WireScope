const std = @import("std");
const testing = std.testing;

pub const paths = @import("paths.zig");
pub const atomic = @import("atomic.zig");
pub const schema = @import("schema.zig");
pub const store = @import("store.zig");
pub const history = @import("history.zig");

// Paths
pub const StoragePaths = paths.StoragePaths;
pub const resolveDefaultDataDir = paths.resolveDefaultDataDir;

// Atomic Writes
pub const atomicWriteFile = atomic.atomicWriteFile;
pub const AtomicWriteError = atomic.AtomicWriteError;

// Schema & Envelope
pub const StorageError = schema.StorageError;
pub const RecordType = schema.RecordType;
pub const RecordEnvelope = schema.RecordEnvelope;
pub const CURRENT_SCHEMA_VERSION = schema.CURRENT_SCHEMA_VERSION;
pub const parseAndValidateRecord = schema.parseAndValidateRecord;

// Store & Management
pub const LocalStorage = store.LocalStorage;
pub const StoredRecordSummary = store.StoredRecordSummary;

// History & Retention
pub const HistoryEntry = history.HistoryEntry;
pub const RetentionPolicy = history.RetentionPolicy;
pub const HistoryComparison = history.HistoryComparison;
pub const HistoryManager = history.HistoryManager;

// Backward Compatibility
pub const StorageConfig = struct {
    base_dir: []const u8 = "data",
    schema_version: u32 = CURRENT_SCHEMA_VERSION,
};

test "storage definitions compile" {
    _ = paths;
    _ = atomic;
    _ = schema;
    _ = store;
    _ = history;

    const config = StorageConfig{};
    try testing.expectEqual(CURRENT_SCHEMA_VERSION, config.schema_version);
}
