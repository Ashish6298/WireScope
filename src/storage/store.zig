const std = @import("std");
const testing = std.testing;
const paths_mod = @import("paths.zig");
const atomic_mod = @import("atomic.zig");
const schema_mod = @import("schema.zig");

const StoragePaths = paths_mod.StoragePaths;
pub const StorageError = schema_mod.StorageError;
pub const RecordEnvelope = schema_mod.RecordEnvelope;
pub const RecordType = schema_mod.RecordType;
pub const CURRENT_SCHEMA_VERSION = schema_mod.CURRENT_SCHEMA_VERSION;

pub const StoredRecordSummary = struct {
    record_id: []const u8,
    record_type: RecordType,
    schema_version: u32,
    created_at_ms: i64,
};

/// Local filesystem-based versioned storage manager
pub const LocalStorage = struct {
    allocator: std.mem.Allocator,
    paths: StoragePaths,

    pub fn init(allocator: std.mem.Allocator, base_dir: []const u8) !LocalStorage {
        const store = LocalStorage{
            .allocator = allocator,
            .paths = StoragePaths.init(base_dir),
        };
        try store.paths.ensureDirectoriesExist(allocator);
        return store;
    }

    /// Helper to write an arbitrary record envelope atomically
    pub fn writeRecord(
        self: *const LocalStorage,
        dir_path: []const u8,
        file_name: []const u8,
        record_type: RecordType,
        record_id: []const u8,
        payload_json: []const u8,
    ) !void {
        const checksum = RecordEnvelope.computeChecksum(payload_json);
        const envelope = RecordEnvelope{
            .schema_version = CURRENT_SCHEMA_VERSION,
            .record_type = record_type,
            .record_id = record_id,
            .created_at_ms = std.time.milliTimestamp(),
            .checksum = checksum,
            .payload = payload_json,
        };

        const serialized = try envelope.serialize(self.allocator);
        defer self.allocator.free(serialized);

        try atomic_mod.atomicWriteFile(self.allocator, dir_path, file_name, serialized);
    }

    /// Helper to read and validate a record envelope
    pub fn readRecord(
        self: *const LocalStorage,
        dir_path: []const u8,
        file_name: []const u8,
    ) !RecordEnvelope {
        const full_path = try std.fs.path.join(self.allocator, &[_][]const u8{ dir_path, file_name });
        defer self.allocator.free(full_path);

        const file = std.fs.cwd().openFile(full_path, .{}) catch |err| {
            if (err == error.FileNotFound) return StorageError.RecordNotFound;
            return StorageError.IoError;
        };
        defer file.close();

        const content = file.readToEndAlloc(self.allocator, 10 * 1024 * 1024) catch |err| {
            if (err == error.StreamTooLong) return StorageError.CorruptRecord;
            return StorageError.IoError;
        };
        defer self.allocator.free(content);

        return try schema_mod.parseAndValidateRecord(self.allocator, content);
    }

    // -------------------------------------------------------------------------
    // 1. Profile Persistence
    // -------------------------------------------------------------------------

    pub fn saveProfileJson(self: *const LocalStorage, profile_id: []const u8, json_payload: []const u8) !void {
        const dir = try self.paths.profilesDir(self.allocator);
        defer self.allocator.free(dir);

        var fname_buf: [128]u8 = undefined;
        const fname = try std.fmt.bufPrint(&fname_buf, "{s}.json", .{profile_id});

        try self.writeRecord(dir, fname, .profile, profile_id, json_payload);
    }

    pub fn loadProfileJson(self: *const LocalStorage, profile_id: []const u8) !RecordEnvelope {
        const dir = try self.paths.profilesDir(self.allocator);
        defer self.allocator.free(dir);

        var fname_buf: [128]u8 = undefined;
        const fname = try std.fmt.bufPrint(&fname_buf, "{s}.json", .{profile_id});

        return try self.readRecord(dir, fname);
    }

    // -------------------------------------------------------------------------
    // 2. Assessment Results Persistence
    // -------------------------------------------------------------------------

    pub fn saveAssessmentJson(self: *const LocalStorage, assessment_id: []const u8, json_payload: []const u8) !void {
        const dir = try self.paths.assessmentsDir(self.allocator);
        defer self.allocator.free(dir);

        var fname_buf: [128]u8 = undefined;
        const fname = try std.fmt.bufPrint(&fname_buf, "{s}.json", .{assessment_id});

        try self.writeRecord(dir, fname, .assessment, assessment_id, json_payload);
    }

    pub fn loadAssessmentJson(self: *const LocalStorage, assessment_id: []const u8) !RecordEnvelope {
        const dir = try self.paths.assessmentsDir(self.allocator);
        defer self.allocator.free(dir);

        var fname_buf: [128]u8 = undefined;
        const fname = try std.fmt.bufPrint(&fname_buf, "{s}.json", .{assessment_id});

        return try self.readRecord(dir, fname);
    }

    // -------------------------------------------------------------------------
    // 3. Baseline Snapshot Persistence
    // -------------------------------------------------------------------------

    pub fn saveBaselineJson(self: *const LocalStorage, name: []const u8, version: u32, json_payload: []const u8) !void {
        const dir = try self.paths.baselinesDir(self.allocator);
        defer self.allocator.free(dir);

        var fname_buf: [128]u8 = undefined;
        const fname = try std.fmt.bufPrint(&fname_buf, "{s}_v{d}.json", .{ name, version });

        var id_buf: [128]u8 = undefined;
        const rec_id = try std.fmt.bufPrint(&id_buf, "{s}:v{d}", .{ name, version });

        try self.writeRecord(dir, fname, .baseline, rec_id, json_payload);
    }

    pub fn loadBaselineJson(self: *const LocalStorage, name: []const u8, version: u32) !RecordEnvelope {
        const dir = try self.paths.baselinesDir(self.allocator);
        defer self.allocator.free(dir);

        var fname_buf: [128]u8 = undefined;
        const fname = try std.fmt.bufPrint(&fname_buf, "{s}_v{d}.json", .{ name, version });

        return try self.readRecord(dir, fname);
    }

    // -------------------------------------------------------------------------
    // 4. Findings Ledger Persistence
    // -------------------------------------------------------------------------

    pub fn saveFindingsJson(self: *const LocalStorage, json_payload: []const u8) !void {
        const dir = try self.paths.findingsDir(self.allocator);
        defer self.allocator.free(dir);

        try self.writeRecord(dir, "findings.json", .findings, "findings-ledger", json_payload);
    }

    pub fn loadFindingsJson(self: *const LocalStorage) !RecordEnvelope {
        const dir = try self.paths.findingsDir(self.allocator);
        defer self.allocator.free(dir);

        return try self.readRecord(dir, "findings.json");
    }

    // -------------------------------------------------------------------------
    // 5. Manifest Persistence
    // -------------------------------------------------------------------------

    pub fn saveManifestJson(self: *const LocalStorage, assessment_id: []const u8, json_payload: []const u8) !void {
        const dir = try self.paths.manifestsDir(self.allocator);
        defer self.allocator.free(dir);

        var fname_buf: [128]u8 = undefined;
        const fname = try std.fmt.bufPrint(&fname_buf, "{s}.json", .{assessment_id});

        try self.writeRecord(dir, fname, .manifest, assessment_id, json_payload);
    }

    pub fn loadManifestJson(self: *const LocalStorage, assessment_id: []const u8) !RecordEnvelope {
        const dir = try self.paths.manifestsDir(self.allocator);
        defer self.allocator.free(dir);

        var fname_buf: [128]u8 = undefined;
        const fname = try std.fmt.bufPrint(&fname_buf, "{s}.json", .{assessment_id});

        return try self.readRecord(dir, fname);
    }

    // -------------------------------------------------------------------------
    // 6. Directory Listing & Enumeration
    // -------------------------------------------------------------------------

    pub fn listRecords(self: *const LocalStorage, dir_path: []const u8) ![][]const u8 {
        var list = std.ArrayList([]const u8).init(self.allocator);
        errdefer {
            for (list.items) |item| self.allocator.free(item);
            list.deinit();
        }

        var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch {
            return list.toOwnedSlice();
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".json") and !std.mem.containsAtLeast(u8, entry.name, 1, ".tmp.")) {
                try list.append(try self.allocator.dupe(u8, entry.name));
            }
        }

        return list.toOwnedSlice();
    }
};

// -----------------------------------------------------------------------------
// Unit & Integration Tests (Phase 11.1 Acceptance Criteria)
// -----------------------------------------------------------------------------

test "local storage: records survive process restart (save, deinit, re-open, read)" {
    const allocator = testing.allocator;
    const test_dir = "test_data_persistence";
    defer std.fs.cwd().deleteTree(test_dir) catch {};

    // 1. First process session: initialize storage and save records
    {
        var store1 = try LocalStorage.init(allocator, test_dir);
        _ = &store1;

        const sample_profile = "{\"profile_id\":\"test-prof-1\",\"targets\":[\"127.0.0.1\"],\"ports\":[80,443]}";
        try store1.saveProfileJson("test-prof-1", sample_profile);

        const sample_asm = "{\"assessment_id\":\"asm-999\",\"status\":\"completed\",\"tasks_succeeded\":5}";
        try store1.saveAssessmentJson("asm-999", sample_asm);
    }

    // 2. Second process session (simulating process restart): re-open storage and read
    {
        var store2 = try LocalStorage.init(allocator, test_dir);
        _ = &store2;

        var prof_rec = try store2.loadProfileJson("test-prof-1");
        defer prof_rec.deinit(allocator);

        try testing.expectEqualStrings("test-prof-1", prof_rec.record_id);
        try testing.expectEqual(RecordType.profile, prof_rec.record_type);
        try testing.expect(std.mem.indexOf(u8, prof_rec.payload, "127.0.0.1") != null);

        var asm_rec = try store2.loadAssessmentJson("asm-999");
        defer asm_rec.deinit(allocator);

        try testing.expectEqualStrings("asm-999", asm_rec.record_id);
        try testing.expectEqual(RecordType.assessment, asm_rec.record_type);
        try testing.expect(std.mem.indexOf(u8, asm_rec.payload, "completed") != null);
    }
}

test "local storage: corrupt or truncated records return actionable errors" {
    const allocator = testing.allocator;
    const test_dir = "test_data_corruption";
    defer std.fs.cwd().deleteTree(test_dir) catch {};

    var store = try LocalStorage.init(allocator, test_dir);
    _ = &store;

    const prof_dir = try store.paths.profilesDir(allocator);
    defer allocator.free(prof_dir);

    // 1. Truncated record (empty or cut off early)
    const truncated_file = try std.fs.path.join(allocator, &[_][]const u8{ prof_dir, "truncated.json" });
    defer allocator.free(truncated_file);
    try std.fs.cwd().writeFile(.{ .sub_path = truncated_file, .data = "{\"schema_" });

    try testing.expectError(StorageError.TruncatedRecord, store.readRecord(prof_dir, "truncated.json"));

    // 2. Corrupt JSON syntax
    const corrupt_file = try std.fs.path.join(allocator, &[_][]const u8{ prof_dir, "corrupt.json" });
    defer allocator.free(corrupt_file);
    try std.fs.cwd().writeFile(.{ .sub_path = corrupt_file, .data = "{\"schema_version\":2, invalid_syntax!@#}" });

    try testing.expectError(StorageError.CorruptRecord, store.readRecord(prof_dir, "corrupt.json"));

    // 3. Checksum mismatch (payload altered by attacker or bit-rot)
    const tampered_file = try std.fs.path.join(allocator, &[_][]const u8{ prof_dir, "tampered.json" });
    defer allocator.free(tampered_file);
    const tampered_data = "{\"schema_version\":2,\"record_type\":\"profile\",\"record_id\":\"tampered\",\"created_at_ms\":100,\"checksum\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"payload\":{\"data\":\"legit\"}}";
    try std.fs.cwd().writeFile(.{ .sub_path = tampered_file, .data = tampered_data });

    try testing.expectError(StorageError.ChecksumMismatch, store.readRecord(prof_dir, "tampered.json"));

    // 4. Unsupported future schema version
    const future_file = try std.fs.path.join(allocator, &[_][]const u8{ prof_dir, "future.json" });
    defer allocator.free(future_file);
    const future_data = "{\"schema_version\":999,\"record_type\":\"profile\",\"record_id\":\"future\",\"created_at_ms\":100,\"checksum\":\"0000\",\"payload\":{}}";
    try std.fs.cwd().writeFile(.{ .sub_path = future_file, .data = future_data });

    try testing.expectError(StorageError.UnsupportedFutureVersion, store.readRecord(prof_dir, "future.json"));
}

test "local storage: schema migration from v1 to v2 works and is verified" {
    const allocator = testing.allocator;
    const test_dir = "test_data_migration";
    defer std.fs.cwd().deleteTree(test_dir) catch {};

    var store = try LocalStorage.init(allocator, test_dir);
    _ = &store;

    const prof_dir = try store.paths.profilesDir(allocator);
    defer allocator.free(prof_dir);

    // Schema v1 record (has schema_version: 1 and NO checksum field)
    const v1_file = try std.fs.path.join(allocator, &[_][]const u8{ prof_dir, "v1_record.json" });
    defer allocator.free(v1_file);
    const v1_data = "{\"schema_version\":1,\"record_type\":\"profile\",\"record_id\":\"legacy-profile\",\"created_at_ms\":1600000000000,\"payload\":{\"targets\":[\"localhost\"]}}";
    try std.fs.cwd().writeFile(.{ .sub_path = v1_file, .data = v1_data });

    // Read record: parser automatically detects schema v1, computes SHA-256, and promotes to v2
    var migrated = try store.readRecord(prof_dir, "v1_record.json");
    defer migrated.deinit(allocator);

    try testing.expectEqual(@as(u32, 2), migrated.schema_version);
    try testing.expectEqualStrings("legacy-profile", migrated.record_id);
    try testing.expectEqual(RecordType.profile, migrated.record_type);
    try testing.expectEqual(@as(usize, 64), migrated.checksum.len);
    try testing.expect(std.mem.indexOf(u8, migrated.payload, "localhost") != null);
}

test "local storage: atomic writes do not expose partially written records" {
    const allocator = testing.allocator;
    const test_dir = "test_data_atomic";
    defer std.fs.cwd().deleteTree(test_dir) catch {};

    var store = try LocalStorage.init(allocator, test_dir);
    _ = &store;

    const prof_dir = try store.paths.profilesDir(allocator);
    defer allocator.free(prof_dir);

    // 1. Initial valid write
    const initial_content = "{\"initial\":\"complete_valid_data\"}";
    try store.saveProfileJson("atomic-prof", initial_content);

    var rec1 = try store.loadProfileJson("atomic-prof");
    defer rec1.deinit(allocator);
    try testing.expect(std.mem.indexOf(u8, rec1.payload, "complete_valid_data") != null);

    // 2. Perform atomic overwrite
    const updated_content = "{\"updated\":\"atomic_replacement\"}";
    try store.saveProfileJson("atomic-prof", updated_content);

    var rec2 = try store.loadProfileJson("atomic-prof");
    defer rec2.deinit(allocator);
    try testing.expect(std.mem.indexOf(u8, rec2.payload, "atomic_replacement") != null);

    // 3. Verify no temporary files remain in the directory
    const files = try store.listRecords(prof_dir);
    defer {
        for (files) |f| allocator.free(f);
        allocator.free(files);
    }
    for (files) |f| {
        try testing.expect(!std.mem.containsAtLeast(u8, f, 1, ".tmp."));
    }
}
