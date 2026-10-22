const std = @import("std");
const testing = std.testing;
const paths_mod = @import("paths.zig");
const atomic_mod = @import("atomic.zig");
const schema_mod = @import("schema.zig");
const store_mod = @import("store.zig");

pub const StoragePaths = paths_mod.StoragePaths;
pub const StorageError = schema_mod.StorageError;
pub const RecordEnvelope = schema_mod.RecordEnvelope;
pub const LocalStorage = store_mod.LocalStorage;

/// Summary metadata for a stored assessment history record
pub const HistoryEntry = struct {
    assessment_id: []const u8,
    profile_id: []const u8,
    status: []const u8,
    created_at_ms: i64,
    duration_ms: u64,
    tasks_succeeded: usize,
    tasks_failed: usize,
    findings_count: usize,
    is_interrupted: bool,
    file_name: []const u8,

    pub fn deinit(self: *HistoryEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.assessment_id);
        allocator.free(self.profile_id);
        allocator.free(self.status);
        allocator.free(self.file_name);
    }
};

/// Configurable retention policy for bounded local history management
pub const RetentionPolicy = struct {
    max_records: usize = 50,
    max_age_days: ?u32 = null,
};

/// Deterministic comparison between two historical assessment records
pub const HistoryComparison = struct {
    allocator: std.mem.Allocator,
    id_a: []const u8,
    id_b: []const u8,
    status_a: []const u8,
    status_b: []const u8,
    profile_a: []const u8,
    profile_b: []const u8,
    tasks_succeeded_a: usize,
    tasks_succeeded_b: usize,
    tasks_failed_a: usize,
    tasks_failed_b: usize,
    findings_count_a: usize,
    findings_count_b: usize,
    duration_diff_ms: i64,

    pub fn deinit(self: *HistoryComparison) void {
        self.allocator.free(self.id_a);
        self.allocator.free(self.id_b);
        self.allocator.free(self.status_a);
        self.allocator.free(self.status_b);
        self.allocator.free(self.profile_a);
        self.allocator.free(self.profile_b);
    }

    pub fn toTerminal(self: *const HistoryComparison, writer: anytype) !void {
        try writer.print(
            \\================================================================================
            \\WIRESCOPE HISTORICAL ASSESSMENT COMPARISON
            \\================================================================================
            \\Record A (Base):      {s} ({s})
            \\Record B (Target):    {s} ({s})
            \\
            \\Metric                     Record A             Record B             Delta
            \\--------------------------------------------------------------------------------
            \\Status                     {s:<20} {s:<20} {s}
            \\Tasks Succeeded            {d:<20} {d:<20} {d}
            \\Tasks Failed               {d:<20} {d:<20} {d}
            \\Findings Count             {d:<20} {d:<20} {d}
            \\================================================================================
            \\
        , .{
            self.id_a,
            self.profile_a,
            self.id_b,
            self.profile_b,
            self.status_a,
            self.status_b,
            if (std.mem.eql(u8, self.status_a, self.status_b)) "Unchanged" else "Changed",
            self.tasks_succeeded_a,
            self.tasks_succeeded_b,
            @as(i64, @intCast(self.tasks_succeeded_b)) - @as(i64, @intCast(self.tasks_succeeded_a)),
            self.tasks_failed_a,
            self.tasks_failed_b,
            @as(i64, @intCast(self.tasks_failed_b)) - @as(i64, @intCast(self.tasks_failed_a)),
            self.findings_count_a,
            self.findings_count_b,
            @as(i64, @intCast(self.findings_count_b)) - @as(i64, @intCast(self.findings_count_a)),
        });
    }

    pub fn toJson(self: *const HistoryComparison, writer: anytype) !void {
        try writer.print(
            \\{{"report_type":"history_comparison","schema_version":1,"record_a":{{"id":"{s}","profile":"{s}","status":"{s}","succeeded":{d},"failed":{d},"findings":{d}}},"record_b":{{"id":"{s}","profile":"{s}","status":"{s}","succeeded":{d},"failed":{d},"findings":{d}}}}}
            \\
        , .{
            self.id_a,
            self.profile_a,
            self.status_a,
            self.tasks_succeeded_a,
            self.tasks_failed_a,
            self.findings_count_a,
            self.id_b,
            self.profile_b,
            self.status_b,
            self.tasks_succeeded_b,
            self.tasks_failed_b,
            self.findings_count_b,
        });
    }

    pub fn toMarkdown(self: *const HistoryComparison, writer: anytype) !void {
        try writer.print(
            \\# WireScope Historical Assessment Comparison
            \\
            \\| Metric | Record A (`{s}`) | Record B (`{s}`) | Diff |
            \\| :--- | :--- | :--- | :--- |
            \\| **Profile** | `{s}` | `{s}` | {s} |
            \\| **Status** | `{s}` | `{s}` | {s} |
            \\| **Tasks Succeeded** | {d} | {d} | {d} |
            \\| **Tasks Failed** | {d} | {d} | {d} |
            \\| **Findings Count** | {d} | {d} | {d} |
            \\
        , .{
            self.id_a,
            self.id_b,
            self.profile_a,
            self.profile_b,
            if (std.mem.eql(u8, self.profile_a, self.profile_b)) "Identical" else "Different",
            self.status_a,
            self.status_b,
            if (std.mem.eql(u8, self.status_a, self.status_b)) "Unchanged" else "Changed",
            self.tasks_succeeded_a,
            self.tasks_succeeded_b,
            @as(i64, @intCast(self.tasks_succeeded_b)) - @as(i64, @intCast(self.tasks_succeeded_a)),
            self.tasks_failed_a,
            self.tasks_failed_b,
            @as(i64, @intCast(self.tasks_failed_b)) - @as(i64, @intCast(self.tasks_failed_a)),
            self.findings_count_a,
            self.findings_count_b,
            @as(i64, @intCast(self.findings_count_b)) - @as(i64, @intCast(self.findings_count_a)),
        });
    }
};

/// High-level assessment history queries, retention enforcement, and recovery
pub const HistoryManager = struct {
    allocator: std.mem.Allocator,
    storage: LocalStorage,

    pub fn init(allocator: std.mem.Allocator, base_dir: []const u8) !HistoryManager {
        const store = try LocalStorage.init(allocator, base_dir);
        return HistoryManager{
            .allocator = allocator,
            .storage = store,
        };
    }

    /// List historical assessments sorted chronologically (newest first)
    pub fn listHistory(self: *const HistoryManager) ![]HistoryEntry {
        const asm_dir = try self.storage.paths.assessmentsDir(self.allocator);
        defer self.allocator.free(asm_dir);

        const files = try self.storage.listRecords(asm_dir);
        defer {
            for (files) |f| self.allocator.free(f);
            self.allocator.free(files);
        }

        var entries = std.ArrayList(HistoryEntry).init(self.allocator);
        errdefer {
            for (entries.items) |*e| e.deinit(self.allocator);
            entries.deinit();
        }

        for (files) |file_name| {
            var envelope = self.storage.readRecord(asm_dir, file_name) catch continue;
            defer envelope.deinit(self.allocator);

            // Parse metadata from payload
            var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, envelope.payload, .{}) catch continue;
            defer parsed.deinit();

            const root = parsed.value;
            if (root != .object) continue;

            const prof_str = if (root.object.get("profile_id")) |p| if (p == .string) p.string else "unknown" else "unknown";
            const status_str = if (root.object.get("status")) |s| if (s == .string) s.string else "unknown" else "unknown";
            const dur_val: u64 = if (root.object.get("duration_ms")) |d| if (d == .integer and d.integer >= 0) @intCast(d.integer) else 0 else 0;
            const succ_val: usize = if (root.object.get("tasks_succeeded")) |s| if (s == .integer and s.integer >= 0) @intCast(s.integer) else 0 else 0;
            const fail_val: usize = if (root.object.get("tasks_failed")) |f| if (f == .integer and f.integer >= 0) @intCast(f.integer) else 0 else 0;
            const find_val: usize = if (root.object.get("findings_count")) |f| if (f == .integer and f.integer >= 0) @intCast(f.integer) else 0 else 0;
            const is_interrupted = std.mem.eql(u8, status_str, "interrupted") or std.mem.eql(u8, status_str, "cancelled");

            try entries.append(.{
                .assessment_id = try self.allocator.dupe(u8, envelope.record_id),
                .profile_id = try self.allocator.dupe(u8, prof_str),
                .status = try self.allocator.dupe(u8, status_str),
                .created_at_ms = envelope.created_at_ms,
                .duration_ms = dur_val,
                .tasks_succeeded = succ_val,
                .tasks_failed = fail_val,
                .findings_count = find_val,
                .is_interrupted = is_interrupted,
                .file_name = try self.allocator.dupe(u8, file_name),
            });
        }

        // Sort newest first
        std.mem.sort(HistoryEntry, entries.items, {}, struct {
            fn lessThan(_: void, a: HistoryEntry, b: HistoryEntry) bool {
                return a.created_at_ms > b.created_at_ms;
            }
        }.lessThan);

        return entries.toOwnedSlice();
    }

    /// Inspect a single assessment record in full detail
    pub fn inspectHistory(self: *const HistoryManager, assessment_id: []const u8) !RecordEnvelope {
        var fname_buf: [128]u8 = undefined;
        const fname = std.fmt.bufPrint(&fname_buf, "{s}.json", .{assessment_id}) catch return StorageError.PathTraversalEscape;

        // Sandbox check: ensure path cannot escape
        const contained_path = try self.storage.paths.validateContainedPath(self.allocator, "assessments", fname);
        defer self.allocator.free(contained_path);

        const asm_dir = try self.storage.paths.assessmentsDir(self.allocator);
        defer self.allocator.free(asm_dir);

        return try self.storage.readRecord(asm_dir, fname);
    }

    /// Compare two historical assessments deterministically
    pub fn compareHistory(self: *const HistoryManager, id_a: []const u8, id_b: []const u8) !HistoryComparison {
        var rec_a = try self.inspectHistory(id_a);
        defer rec_a.deinit(self.allocator);

        var rec_b = try self.inspectHistory(id_b);
        defer rec_b.deinit(self.allocator);

        var parsed_a = try std.json.parseFromSlice(std.json.Value, self.allocator, rec_a.payload, .{});
        defer parsed_a.deinit();

        var parsed_b = try std.json.parseFromSlice(std.json.Value, self.allocator, rec_b.payload, .{});
        defer parsed_b.deinit();

        const obj_a = parsed_a.value.object;
        const obj_b = parsed_b.value.object;

        const stat_a = if (obj_a.get("status")) |s| if (s == .string) s.string else "unknown" else "unknown";
        const stat_b = if (obj_b.get("status")) |s| if (s == .string) s.string else "unknown" else "unknown";

        const prof_a = if (obj_a.get("profile_id")) |p| if (p == .string) p.string else "unknown" else "unknown";
        const prof_b = if (obj_b.get("profile_id")) |p| if (p == .string) p.string else "unknown" else "unknown";

        const succ_a: usize = if (obj_a.get("tasks_succeeded")) |s| if (s == .integer and s.integer >= 0) @intCast(s.integer) else 0 else 0;
        const succ_b: usize = if (obj_b.get("tasks_succeeded")) |s| if (s == .integer and s.integer >= 0) @intCast(s.integer) else 0 else 0;

        const fail_a: usize = if (obj_a.get("tasks_failed")) |f| if (f == .integer and f.integer >= 0) @intCast(f.integer) else 0 else 0;
        const fail_b: usize = if (obj_b.get("tasks_failed")) |f| if (f == .integer and f.integer >= 0) @intCast(f.integer) else 0 else 0;

        const find_a: usize = if (obj_a.get("findings_count")) |f| if (f == .integer and f.integer >= 0) @intCast(f.integer) else 0 else 0;
        const find_b: usize = if (obj_b.get("findings_count")) |f| if (f == .integer and f.integer >= 0) @intCast(f.integer) else 0 else 0;

        return HistoryComparison{
            .allocator = self.allocator,
            .id_a = try self.allocator.dupe(u8, id_a),
            .id_b = try self.allocator.dupe(u8, id_b),
            .status_a = try self.allocator.dupe(u8, stat_a),
            .status_b = try self.allocator.dupe(u8, stat_b),
            .profile_a = try self.allocator.dupe(u8, prof_a),
            .profile_b = try self.allocator.dupe(u8, prof_b),
            .tasks_succeeded_a = succ_a,
            .tasks_succeeded_b = succ_b,
            .tasks_failed_a = fail_a,
            .tasks_failed_b = fail_b,
            .findings_count_a = find_a,
            .findings_count_b = find_b,
            .duration_diff_ms = rec_b.created_at_ms - rec_a.created_at_ms,
        };
    }

    /// Delete an assessment history record strictly within WireScope data sandbox
    pub fn deleteHistory(self: *const HistoryManager, assessment_id: []const u8) !void {
        var fname_buf: [128]u8 = undefined;
        const fname = std.fmt.bufPrint(&fname_buf, "{s}.json", .{assessment_id}) catch return StorageError.PathTraversalEscape;

        // Strict sandbox containment verification: rejects "../", "..\\", absolute paths, and colons
        const contained_path = try self.storage.paths.validateContainedPath(self.allocator, "assessments", fname);
        defer self.allocator.free(contained_path);

        // Delete the verified assessment file
        std.fs.cwd().deleteFile(contained_path) catch |err| {
            if (err == error.FileNotFound) return StorageError.RecordNotFound;
            return StorageError.IoError;
        };

        // Also clean up any linked manifest strictly within WireScope directory
        const manifest_path = self.storage.paths.validateContainedPath(self.allocator, "manifests", fname) catch null;
        if (manifest_path) |mp| {
            defer self.allocator.free(mp);
            std.fs.cwd().deleteFile(mp) catch {};
        }
    }

    /// Apply bounded retention policy: prunes oldest assessment records beyond limit
    pub fn applyRetention(self: *const HistoryManager, policy: RetentionPolicy) !usize {
        const entries = try self.listHistory();
        defer {
            for (entries) |*e| e.deinit(self.allocator);
            self.allocator.free(entries);
        }

        if (entries.len <= policy.max_records) {
            return 0;
        }

        // entries is sorted newest first, so oldest entries are at the end
        var pruned_count: usize = 0;
        var idx: usize = entries.len;
        while (idx > policy.max_records) : (idx -= 1) {
            const entry = entries[idx - 1];
            self.deleteHistory(entry.assessment_id) catch continue;
            pruned_count += 1;
        }

        return pruned_count;
    }

    /// Preserves interrupted or cancelled assessments as incomplete records
    pub fn saveInterruptedAssessment(
        self: *const HistoryManager,
        assessment_id: []const u8,
        profile_id: []const u8,
        tasks_succeeded: usize,
        tasks_failed: usize,
        interruption_reason: []const u8,
    ) !void {
        const payload = try std.fmt.allocPrint(self.allocator,
            \\{{"assessment_id":"{s}","profile_id":"{s}","status":"interrupted","tasks_succeeded":{d},"tasks_failed":{d},"findings_count":0,"interruption_reason":"{s}"}}
        , .{
            assessment_id,
            profile_id,
            tasks_succeeded,
            tasks_failed,
            interruption_reason,
        });
        defer self.allocator.free(payload);

        try self.storage.saveAssessmentJson(assessment_id, payload);
    }

    /// Recovers from interrupted writes by cleaning up orphaned .tmp files
    pub fn recoverInterruptedWrites(self: *const HistoryManager) !usize {
        var cleaned_count: usize = 0;

        const subdirs = [_][]const u8{ "profiles", "assessments", "observations", "findings", "baselines", "manifests" };
        for (subdirs) |sub| {
            const dir_path = try std.fs.path.join(self.allocator, &[_][]const u8{ self.storage.paths.base_dir, sub });
            defer self.allocator.free(dir_path);

            var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch continue;
            defer dir.close();

            var iter = dir.iterate();
            while (try iter.next()) |entry| {
                if (entry.kind == .file and std.mem.containsAtLeast(u8, entry.name, 1, ".tmp.")) {
                    dir.deleteFile(entry.name) catch continue;
                    cleaned_count += 1;
                }
            }
        }

        return cleaned_count;
    }
};

// -----------------------------------------------------------------------------
// Unit & Integration Tests (Phase 11.2 Acceptance Criteria)
// -----------------------------------------------------------------------------

test "history manager: list, inspect, compare, and export work offline" {
    const allocator = testing.allocator;
    const test_dir = "test_history_offline";
    defer std.fs.cwd().deleteTree(test_dir) catch {};

    var mgr = try HistoryManager.init(allocator, test_dir);
    _ = &mgr;

    // Create 2 test assessments
    const sample1 = "{\"assessment_id\":\"asm-101\",\"profile_id\":\"loopback-diagnostics\",\"status\":\"completed\",\"tasks_succeeded\":4,\"tasks_failed\":0,\"findings_count\":0}";
    try mgr.storage.saveAssessmentJson("asm-101", sample1);

    const sample2 = "{\"assessment_id\":\"asm-102\",\"profile_id\":\"local-security-audit\",\"status\":\"completed\",\"tasks_succeeded\":8,\"tasks_failed\":1,\"findings_count\":2}";
    try mgr.storage.saveAssessmentJson("asm-102", sample2);

    // 1. List history offline
    const list = try mgr.listHistory();
    defer {
        for (list) |*e| e.deinit(allocator);
        allocator.free(list);
    }
    try testing.expectEqual(@as(usize, 2), list.len);

    // 2. Inspect history offline
    var inspected = try mgr.inspectHistory("asm-101");
    defer inspected.deinit(allocator);
    try testing.expectEqualStrings("asm-101", inspected.record_id);
    try testing.expect(std.mem.indexOf(u8, inspected.payload, "loopback-diagnostics") != null);

    // 3. Compare history offline
    var cmp = try mgr.compareHistory("asm-101", "asm-102");
    defer cmp.deinit();

    try testing.expectEqualStrings("asm-101", cmp.id_a);
    try testing.expectEqualStrings("asm-102", cmp.id_b);
    try testing.expectEqual(@as(usize, 4), cmp.tasks_succeeded_a);
    try testing.expectEqual(@as(usize, 8), cmp.tasks_succeeded_b);
    try testing.expectEqual(@as(usize, 0), cmp.findings_count_a);
    try testing.expectEqual(@as(usize, 2), cmp.findings_count_b);
}

test "history manager: configurable bounded retention prunes oldest records" {
    const allocator = testing.allocator;
    const test_dir = "test_history_retention";
    defer std.fs.cwd().deleteTree(test_dir) catch {};

    var mgr = try HistoryManager.init(allocator, test_dir);
    _ = &mgr;

    // Create 5 assessment records
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        var id_buf: [32]u8 = undefined;
        const asm_id = try std.fmt.bufPrint(&id_buf, "asm-ret-{d}", .{i});
        const payload = "{\"assessment_id\":\"asm\",\"profile_id\":\"test\",\"status\":\"completed\"}";
        try mgr.storage.saveAssessmentJson(asm_id, payload);
    }

    const initial_list = try mgr.listHistory();
    defer {
        for (initial_list) |*e| e.deinit(allocator);
        allocator.free(initial_list);
    }
    try testing.expectEqual(@as(usize, 5), initial_list.len);

    // Apply retention policy: keep max 3 records
    const pruned = try mgr.applyRetention(.{ .max_records = 3 });
    try testing.expectEqual(@as(usize, 2), pruned);

    const retained_list = try mgr.listHistory();
    defer {
        for (retained_list) |*e| e.deinit(allocator);
        allocator.free(retained_list);
    }
    try testing.expectEqual(@as(usize, 3), retained_list.len);
}

test "history manager: sandbox containment prevents deletion escape" {
    const allocator = testing.allocator;
    const test_dir = "test_history_sandbox";
    defer std.fs.cwd().deleteTree(test_dir) catch {};

    var mgr = try HistoryManager.init(allocator, test_dir);
    _ = &mgr;

    // Path traversal attacks must fail with PathTraversalEscape
    try testing.expectError(StorageError.PathTraversalEscape, mgr.deleteHistory("../outside.json"));
    try testing.expectError(StorageError.PathTraversalEscape, mgr.deleteHistory("..\\outside.json"));
    try testing.expectError(StorageError.PathTraversalEscape, mgr.deleteHistory("/etc/passwd"));
    try testing.expectError(StorageError.PathTraversalEscape, mgr.deleteHistory("C:\\Windows\\System32\\test.dll"));
}

test "history manager: interrupted assessments and interrupted writes are preserved and recovered" {
    const allocator = testing.allocator;
    const test_dir = "test_history_recovery";
    defer std.fs.cwd().deleteTree(test_dir) catch {};

    var mgr = try HistoryManager.init(allocator, test_dir);
    _ = &mgr;

    // 1. Interrupted assessment is preserved as incomplete record
    try mgr.saveInterruptedAssessment("asm-int-1", "local-security-audit", 3, 1, "Process terminated by operator signal SIGINT");

    var rec = try mgr.inspectHistory("asm-int-1");
    defer rec.deinit(allocator);

    try testing.expect(std.mem.indexOf(u8, rec.payload, "interrupted") != null);
    try testing.expect(std.mem.indexOf(u8, rec.payload, "SIGINT") != null);

    // 2. Interrupted write leaves an orphaned .tmp file
    const asm_dir = try mgr.storage.paths.assessmentsDir(allocator);
    defer allocator.free(asm_dir);

    const orphaned_tmp = try std.fs.path.join(allocator, &[_][]const u8{ asm_dir, "orphan.json.tmp.12345" });
    defer allocator.free(orphaned_tmp);
    try std.fs.cwd().writeFile(.{ .sub_path = orphaned_tmp, .data = "half-written-payload" });

    // 3. Recovery cleans up orphaned .tmp file
    const recovered = try mgr.recoverInterruptedWrites();
    try testing.expectEqual(@as(usize, 1), recovered);

    // Valid record remains intact
    var rec2 = try mgr.inspectHistory("asm-int-1");
    defer rec2.deinit(allocator);
    try testing.expect(std.mem.indexOf(u8, rec2.payload, "interrupted") != null);
}
