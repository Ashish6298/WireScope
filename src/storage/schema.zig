const std = @import("std");

pub const CURRENT_SCHEMA_VERSION: u32 = 2;

pub const StorageError = error{
    RecordNotFound,
    CorruptRecord,
    TruncatedRecord,
    InvalidSchema,
    UnsupportedFutureVersion,
    ChecksumMismatch,
    MigrationFailed,
    WriteFailed,
    IoError,
    PathTraversalEscape,
    OutOfMemory,
};

pub const RecordType = enum {
    profile,
    assessment,
    observations,
    findings,
    baseline,
    manifest,

    pub fn toSlice(self: RecordType) []const u8 {
        return @tagName(self);
    }

    pub fn fromSlice(str: []const u8) ?RecordType {
        if (std.mem.eql(u8, str, "profile")) return .profile;
        if (std.mem.eql(u8, str, "assessment")) return .assessment;
        if (std.mem.eql(u8, str, "observations")) return .observations;
        if (std.mem.eql(u8, str, "findings")) return .findings;
        if (std.mem.eql(u8, str, "baseline")) return .baseline;
        if (std.mem.eql(u8, str, "manifest")) return .manifest;
        return null;
    }
};

/// Unified versioned storage record envelope
pub const RecordEnvelope = struct {
    schema_version: u32 = CURRENT_SCHEMA_VERSION,
    record_type: RecordType,
    record_id: []const u8,
    created_at_ms: i64,
    checksum: [64]u8,
    payload: []const u8,

    pub fn computeChecksum(payload: []const u8) [64]u8 {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});
        return std.fmt.bytesToHex(digest, .lower);
    }

    pub fn serialize(self: *const RecordEnvelope, allocator: std.mem.Allocator) ![]const u8 {
        return try std.fmt.allocPrint(allocator,
            \\{{"schema_version":{d},"record_type":"{s}","record_id":"{s}","created_at_ms":{d},"checksum":"{s}","payload":{s}}}
        , .{
            self.schema_version,
            self.record_type.toSlice(),
            self.record_id,
            self.created_at_ms,
            &self.checksum,
            self.payload,
        });
    }

    pub fn deinit(self: *RecordEnvelope, allocator: std.mem.Allocator) void {
        allocator.free(self.record_id);
        allocator.free(self.payload);
    }
};

/// Validates raw file bytes and parses them into a validated RecordEnvelope.
/// Automatically detects schema version and executes migration paths when needed.
pub fn parseAndValidateRecord(allocator: std.mem.Allocator, bytes: []const u8) StorageError!RecordEnvelope {
    const trimmed = std.mem.trim(u8, bytes, " \t\r\n");

    // 1. Truncation check: empty or incomplete JSON
    if (trimmed.len < 10 or trimmed[0] != '{' or trimmed[trimmed.len - 1] != '}') {
        return StorageError.TruncatedRecord;
    }

    // 2. Parse JSON
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, trimmed, .{}) catch {
        return StorageError.CorruptRecord;
    };
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) return StorageError.CorruptRecord;

    // 3. Extract schema_version
    const ver_val = root.object.get("schema_version") orelse return StorageError.InvalidSchema;
    if (ver_val != .integer or ver_val.integer < 1) return StorageError.InvalidSchema;
    const schema_ver: u32 = @intCast(ver_val.integer);

    if (schema_ver > CURRENT_SCHEMA_VERSION) {
        return StorageError.UnsupportedFutureVersion;
    }

    // 4. Extract record_type
    const type_val = root.object.get("record_type") orelse return StorageError.InvalidSchema;
    if (type_val != .string) return StorageError.InvalidSchema;
    const rtype = RecordType.fromSlice(type_val.string) orelse return StorageError.InvalidSchema;

    // 5. Extract record_id
    const id_val = root.object.get("record_id") orelse return StorageError.InvalidSchema;
    if (id_val != .string or id_val.string.len == 0) return StorageError.InvalidSchema;

    // 6. Extract created_at_ms
    const time_val = root.object.get("created_at_ms") orelse return StorageError.InvalidSchema;
    if (time_val != .integer) return StorageError.InvalidSchema;
    const created_at_ms: i64 = time_val.integer;

    // 7. Extract payload
    const payload_val = root.object.get("payload") orelse return StorageError.InvalidSchema;
    var payload_buf = std.ArrayList(u8).init(allocator);
    defer payload_buf.deinit();
    try std.json.stringify(payload_val, .{}, payload_buf.writer());
    const payload_str = try allocator.dupe(u8, payload_buf.items);
    errdefer allocator.free(payload_str);

    // 8. Handle Schema Migration (v1 -> v2)
    if (schema_ver == 1) {
        // Schema v1 did not have checksums; migration computes SHA-256 and promotes to v2
        const computed_cksum = RecordEnvelope.computeChecksum(payload_str);
        return RecordEnvelope{
            .schema_version = CURRENT_SCHEMA_VERSION,
            .record_type = rtype,
            .record_id = try allocator.dupe(u8, id_val.string),
            .created_at_ms = created_at_ms,
            .checksum = computed_cksum,
            .payload = payload_str,
        };
    }

    // Schema v2 requires valid checksum
    const cksum_val = root.object.get("checksum") orelse return StorageError.InvalidSchema;
    if (cksum_val != .string or cksum_val.string.len != 64) return StorageError.InvalidSchema;

    var cksum: [64]u8 = undefined;
    @memcpy(&cksum, cksum_val.string[0..64]);

    const actual_cksum = RecordEnvelope.computeChecksum(payload_str);
    if (!std.mem.eql(u8, &cksum, &actual_cksum)) {
        return StorageError.ChecksumMismatch;
    }

    return RecordEnvelope{
        .schema_version = schema_ver,
        .record_type = rtype,
        .record_id = try allocator.dupe(u8, id_val.string),
        .created_at_ms = created_at_ms,
        .checksum = cksum,
        .payload = payload_str,
    };
}
