const std = @import("std");
const testing = std.testing;
const core = @import("../core/root.zig");
const runner_mod = @import("runner.zig");
pub const AssessmentResult = runner_mod.AssessmentResult;
pub const AssessmentObservations = runner_mod.AssessmentObservations;

pub const DEFAULT_MAX_RETENTION_VERSIONS: u32 = 5;

pub const DiffClassification = enum {
    new_item,
    removed_item,
    changed_item,
    unchanged_item,
    inconclusive,

    pub fn toSlice(self: DiffClassification) []const u8 {
        return switch (self) {
            .new_item => "new",
            .removed_item => "removed",
            .changed_item => "changed",
            .unchanged_item => "unchanged",
            .inconclusive => "inconclusive",
        };
    }
};

pub const BaselineItemType = enum {
    listener,
    dns,
    tcp_service,
    tls_config,
    http_config,

    pub fn toSlice(self: BaselineItemType) []const u8 {
        return @tagName(self);
    }
};

pub const NormalizedBaselineItem = struct {
    key: []const u8,
    item_type: BaselineItemType,
    summary: []const u8,
    details: []const u8,

    pub fn deinit(self: *NormalizedBaselineItem, allocator: std.mem.Allocator) void {
        allocator.free(self.key);
        allocator.free(self.summary);
        allocator.free(self.details);
    }

    pub fn clone(self: *const NormalizedBaselineItem, allocator: std.mem.Allocator) !NormalizedBaselineItem {
        return .{
            .key = try allocator.dupe(u8, self.key),
            .item_type = self.item_type,
            .summary = try allocator.dupe(u8, self.summary),
            .details = try allocator.dupe(u8, self.details),
        };
    }
};

pub const BaselineSnapshot = struct {
    name: []const u8,
    version: u32,
    created_at_ms: i64,
    assessment_id: []const u8,
    profile_id: []const u8,
    items: []NormalizedBaselineItem,
    snapshot_hash: [64]u8,

    pub fn deinit(self: *BaselineSnapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.assessment_id);
        allocator.free(self.profile_id);
        for (self.items) |*item| {
            item.deinit(allocator);
        }
        allocator.free(self.items);
    }

    pub fn clone(self: *const BaselineSnapshot, allocator: std.mem.Allocator) !BaselineSnapshot {
        const cloned_items = try allocator.alloc(NormalizedBaselineItem, self.items.len);
        errdefer allocator.free(cloned_items);

        var count: usize = 0;
        errdefer {
            for (cloned_items[0..count]) |*it| it.deinit(allocator);
        }

        for (self.items) |*item| {
            cloned_items[count] = try item.clone(allocator);
            count += 1;
        }

        return BaselineSnapshot{
            .name = try allocator.dupe(u8, self.name),
            .version = self.version,
            .created_at_ms = self.created_at_ms,
            .assessment_id = try allocator.dupe(u8, self.assessment_id),
            .profile_id = try allocator.dupe(u8, self.profile_id),
            .items = cloned_items,
            .snapshot_hash = self.snapshot_hash,
        };
    }

    pub fn computeHash(name: []const u8, version: u32, assessment_id: []const u8, items: []const NormalizedBaselineItem) [64]u8 {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update("wirescope-baseline-v1:");
        hasher.update(name);

        var buf: [32]u8 = undefined;
        const v_str = std.fmt.bufPrint(&buf, ":v{d}:", .{version}) catch "";
        hasher.update(v_str);
        hasher.update(assessment_id);

        for (items) |item| {
            hasher.update(":");
            hasher.update(item.key);
            hasher.update("=");
            hasher.update(item.details);
        }

        var digest: [32]u8 = undefined;
        hasher.final(&digest);
        return std.fmt.bytesToHex(digest, .lower);
    }
};

pub const DiffEntry = struct {
    key: []const u8,
    item_type: BaselineItemType,
    classification: DiffClassification,
    baseline_value: ?[]const u8 = null,
    observed_value: ?[]const u8 = null,
    explanation: []const u8,

    pub fn deinit(self: *DiffEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.key);
        if (self.baseline_value) |b| allocator.free(b);
        if (self.observed_value) |o| allocator.free(o);
        allocator.free(self.explanation);
    }
};

pub const BaselineDiffReport = struct {
    baseline_name: []const u8,
    baseline_version: u32,
    compared_at_ms: i64,
    total_baseline_items: usize,
    total_observed_items: usize,
    new_count: usize,
    removed_count: usize,
    changed_count: usize,
    unchanged_count: usize,
    inconclusive_count: usize,
    entries: []DiffEntry,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *BaselineDiffReport) void {
        self.allocator.free(self.baseline_name);
        for (self.entries) |*entry| {
            entry.deinit(self.allocator);
        }
        self.allocator.free(self.entries);
    }

    pub fn toTerminal(self: *const BaselineDiffReport, writer: anytype) !void {
        try writer.print(
            \\================================================================================
            \\WIRESCOPE BASELINE DETERMINISTIC DIFF REPORT
            \\================================================================================
            \\Baseline:            {s} (v{d})
            \\Compared At:         {d}ms
            \\Baseline Items:      {d}
            \\Observed Items:      {d}
            \\Diff Summary:        {d} Unchanged, {d} Changed, {d} New, {d} Removed, {d} Inconclusive
            \\
            \\  Status        Item Key / Description
            \\  --------------------------------------------------------------------------------
            \\
        , .{
            self.baseline_name,
            self.baseline_version,
            self.compared_at_ms,
            self.total_baseline_items,
            self.total_observed_items,
            self.unchanged_count,
            self.changed_count,
            self.new_count,
            self.removed_count,
            self.inconclusive_count,
        });

        for (self.entries) |entry| {
            try writer.print("  [{s:<12}] {s}\n", .{ entry.classification.toSlice(), entry.key });
            if (entry.classification == .changed_item) {
                try writer.print("                 Baseline: {s}\n", .{entry.baseline_value orelse "-"});
                try writer.print("                 Observed: {s}\n", .{entry.observed_value orelse "-"});
            } else if (entry.classification == .inconclusive) {
                try writer.print("                 Reason:   {s}\n", .{entry.explanation});
            }
        }

        try writer.print(
            \\================================================================================
            \\WireScope Baseline Invariant:
            \\  Incomplete evidence does not imply removal. Diffs are strictly deterministic.
            \\  Baseline snapshots are never overwritten automatically.
            \\================================================================================
            \\
        , .{});
    }

    pub fn toJson(self: *const BaselineDiffReport, writer: anytype) !void {
        try writer.print(
            \\{{"report_type":"baseline_diff","schema_version":1,"baseline_name":"{s}","baseline_version":{d},"compared_at_ms":{d},"metrics":{{"total_baseline":{d},"total_observed":{d},"unchanged":{d},"changed":{d},"new":{d},"removed":{d},"inconclusive":{d}}},"entries":[
        , .{
            self.baseline_name,
            self.baseline_version,
            self.compared_at_ms,
            self.total_baseline_items,
            self.total_observed_items,
            self.unchanged_count,
            self.changed_count,
            self.new_count,
            self.removed_count,
            self.inconclusive_count,
        });

        for (self.entries, 0..) |entry, i| {
            if (i > 0) try writer.print(",", .{});
            try writer.print(
                \\{{"key":"{s}","type":"{s}","status":"{s}","explanation":"{s}"
            , .{
                entry.key,
                entry.item_type.toSlice(),
                entry.classification.toSlice(),
                entry.explanation,
            });
            if (entry.baseline_value) |b| {
                try writer.print(",\"baseline_value\":\"{s}\"", .{b});
            }
            if (entry.observed_value) |o| {
                try writer.print(",\"observed_value\":\"{s}\"", .{o});
            }
            try writer.print("}}", .{});
        }

        try writer.print("]}}\n", .{});
    }

    pub fn toMarkdown(self: *const BaselineDiffReport, writer: anytype) !void {
        try writer.print(
            \\# WireScope Baseline Deterministic Diff Report
            \\
            \\**Baseline:** `{s}` (version `{d}`)  
            \\**Summary:** {d} Unchanged | {d} Changed | {d} New | {d} Removed | {d} Inconclusive  
            \\
            \\> [!NOTE]
            \\> Diffs are deterministic and sortable. Incomplete evidence does not imply removal; affected items are classified as inconclusive.
            \\
            \\| Status | Item Type | Key | Baseline Value | Observed Value |
            \\| :--- | :--- | :--- | :--- | :--- |
            \\
        , .{
            self.baseline_name,
            self.baseline_version,
            self.unchanged_count,
            self.changed_count,
            self.new_count,
            self.removed_count,
            self.inconclusive_count,
        });

        for (self.entries) |entry| {
            try writer.print("| `{s}` | `{s}` | `{s}` | `{s}` | `{s}` |\n", .{
                entry.classification.toSlice(),
                entry.item_type.toSlice(),
                entry.key,
                entry.baseline_value orelse "-",
                entry.observed_value orelse "-",
            });
        }
    }
};

// -----------------------------------------------------------------------------
// Normalization Engine
// -----------------------------------------------------------------------------

pub fn normalizeObservations(allocator: std.mem.Allocator, observations: *const AssessmentObservations) ![]NormalizedBaselineItem {
    var items = std.ArrayList(NormalizedBaselineItem).init(allocator);
    errdefer {
        for (items.items) |*it| it.deinit(allocator);
        items.deinit();
    }

    // 1. Normalize Listeners (Volatile PID and volatile timestamp excluded)
    for (observations.listeners.items) |l| {
        const key = try std.fmt.allocPrint(allocator, "listener:{s}:{s}:{d}", .{
            l.transport,
            l.address,
            l.port,
        });
        errdefer allocator.free(key);

        const summary = try std.fmt.allocPrint(allocator, "Listening socket {s}:{d} ({s})", .{
            l.address,
            l.port,
            l.binding_type,
        });
        errdefer allocator.free(summary);

        const details = try std.fmt.allocPrint(allocator, "binding={s};process={s}", .{
            l.binding_type,
            l.process_name orelse "unresolved",
        });
        errdefer allocator.free(details);

        try items.append(.{
            .key = key,
            .item_type = .listener,
            .summary = summary,
            .details = details,
        });
    }

    // 2. Normalize DNS (Volatile latency excluded; answers deterministically sorted)
    for (observations.dns.items) |d| {
        const key = try std.fmt.allocPrint(allocator, "dns:{s}", .{d.target});
        errdefer allocator.free(key);

        const summary = try std.fmt.allocPrint(allocator, "DNS resolution for {s}", .{d.target});
        errdefer allocator.free(summary);

        // Sort answers lexicographically
        const sorted_answers = try allocator.alloc([]const u8, d.answers.len);
        defer allocator.free(sorted_answers);
        @memcpy(sorted_answers, d.answers);

        std.mem.sort([]const u8, sorted_answers, {}, struct {
            fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.lessThan);

        var details_buf = std.ArrayList(u8).init(allocator);
        errdefer details_buf.deinit();
        for (sorted_answers, 0..) |ans, i| {
            if (i > 0) try details_buf.append(',');
            try details_buf.appendSlice(ans);
        }
        const details = try details_buf.toOwnedSlice();

        try items.append(.{
            .key = key,
            .item_type = .dns,
            .summary = summary,
            .details = details,
        });
    }

    // 3. Normalize TCP services (Volatile RTT latency excluded)
    for (observations.tcp.items) |t| {
        const key = try std.fmt.allocPrint(allocator, "tcp:{s}:{d}", .{ t.target, t.port });
        errdefer allocator.free(key);

        const summary = try std.fmt.allocPrint(allocator, "TCP connectivity to {s}:{d}", .{ t.target, t.port });
        errdefer allocator.free(summary);

        const details = try std.fmt.allocPrint(allocator, "open={s}", .{if (t.is_open) "true" else "false"});
        errdefer allocator.free(details);

        try items.append(.{
            .key = key,
            .item_type = .tcp_service,
            .summary = summary,
            .details = details,
        });
    }

    // 4. Normalize TLS configuration (Volatile remaining days window bucketed to stable status)
    for (observations.tls.items) |tls| {
        const key = try std.fmt.allocPrint(allocator, "tls:{s}:{d}", .{ tls.target, tls.port });
        errdefer allocator.free(key);

        const summary = try std.fmt.allocPrint(allocator, "TLS posture for {s}:{d}", .{ tls.target, tls.port });
        errdefer allocator.free(summary);

        const details = try std.fmt.allocPrint(allocator, "proto={s};valid_chain={s};hostname_matches={s}", .{
            tls.protocol_version,
            if (tls.is_valid_chain) "true" else "false",
            if (tls.hostname_matches) "true" else "false",
        });
        errdefer allocator.free(details);

        try items.append(.{
            .key = key,
            .item_type = .tls_config,
            .summary = summary,
            .details = details,
        });
    }

    // 5. Normalize HTTP security configuration
    for (observations.http.items) |h| {
        const key = try std.fmt.allocPrint(allocator, "http:{s}", .{h.target_url});
        errdefer allocator.free(key);

        const summary = try std.fmt.allocPrint(allocator, "HTTP security configuration for {s}", .{h.target_url});
        errdefer allocator.free(summary);

        const details = try std.fmt.allocPrint(allocator, "status={d};hsts={s};csp={s};nosniff={s}", .{
            h.status_code,
            h.hsts_header orelse "none",
            if (h.csp_header != null) "configured" else "none",
            h.x_content_type_options orelse "none",
        });
        errdefer allocator.free(details);

        try items.append(.{
            .key = key,
            .item_type = .http_config,
            .summary = summary,
            .details = details,
        });
    }

    // Sort items lexicographically by key for strict determinism
    std.mem.sort(NormalizedBaselineItem, items.items, {}, struct {
        fn lessThan(_: void, a: NormalizedBaselineItem, b: NormalizedBaselineItem) bool {
            return std.mem.lessThan(u8, a.key, b.key);
        }
    }.lessThan);

    return items.toOwnedSlice();
}

// -----------------------------------------------------------------------------
// Baseline Version Storage & History
// -----------------------------------------------------------------------------

pub const BaselineChain = struct {
    name: []const u8,
    versions: std.ArrayListUnmanaged(BaselineSnapshot),

    pub fn deinit(self: *BaselineChain, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        for (self.versions.items) |*v| {
            v.deinit(allocator);
        }
        self.versions.deinit(allocator);
    }
};

pub const BaselineError = error{
    BaselineAlreadyExists,
    BaselineNotFound,
    BaselineVersionNotFound,
    EmptyBaselineName,
};

pub const BaselineManager = struct {
    allocator: std.mem.Allocator,
    chains: std.StringHashMapUnmanaged(BaselineChain),
    max_retention_versions: u32,

    pub fn init(allocator: std.mem.Allocator) BaselineManager {
        return .{
            .allocator = allocator,
            .chains = std.StringHashMapUnmanaged(BaselineChain){},
            .max_retention_versions = DEFAULT_MAX_RETENTION_VERSIONS,
        };
    }

    pub fn deinit(self: *BaselineManager) void {
        var iter = self.chains.valueIterator();
        while (iter.next()) |chain| {
            chain.deinit(self.allocator);
        }
        self.chains.deinit(self.allocator);
    }

    /// Explicit creation of a new named baseline (v1)
    pub fn create(self: *BaselineManager, name: []const u8, assessment: *const AssessmentResult) !*const BaselineSnapshot {
        if (name.len == 0) return error.EmptyBaselineName;
        if (self.chains.contains(name)) return error.BaselineAlreadyExists;

        const normalized_items = try normalizeObservations(self.allocator, &assessment.observations);
        errdefer {
            for (normalized_items) |*it| it.deinit(self.allocator);
            self.allocator.free(normalized_items);
        }

        const snapshot_hash = BaselineSnapshot.computeHash(name, 1, assessment.manifest.assessment_id, normalized_items);

        var chain = BaselineChain{
            .name = try self.allocator.dupe(u8, name),
            .versions = std.ArrayListUnmanaged(BaselineSnapshot){},
        };
        errdefer chain.deinit(self.allocator);

        const snapshot = BaselineSnapshot{
            .name = try self.allocator.dupe(u8, name),
            .version = 1,
            .created_at_ms = std.time.milliTimestamp(),
            .assessment_id = try self.allocator.dupe(u8, assessment.manifest.assessment_id),
            .profile_id = try self.allocator.dupe(u8, assessment.profile_id),
            .items = normalized_items,
            .snapshot_hash = snapshot_hash,
        };

        try chain.versions.append(self.allocator, snapshot);
        try self.chains.put(self.allocator, chain.name, chain);

        return &self.chains.getPtr(name).?.versions.items[0];
    }

    /// Explicit update of an existing named baseline (creating version N+1 and enforcing retention)
    pub fn update(self: *BaselineManager, name: []const u8, assessment: *const AssessmentResult) !*const BaselineSnapshot {
        if (name.len == 0) return error.EmptyBaselineName;
        const chain_ptr = self.chains.getPtr(name) orelse return error.BaselineNotFound;

        const latest_version = chain_ptr.versions.items[chain_ptr.versions.items.len - 1].version;
        const new_version = latest_version + 1;

        const normalized_items = try normalizeObservations(self.allocator, &assessment.observations);
        errdefer {
            for (normalized_items) |*it| it.deinit(self.allocator);
            self.allocator.free(normalized_items);
        }

        const snapshot_hash = BaselineSnapshot.computeHash(name, new_version, assessment.manifest.assessment_id, normalized_items);

        const new_snapshot = BaselineSnapshot{
            .name = try self.allocator.dupe(u8, name),
            .version = new_version,
            .created_at_ms = std.time.milliTimestamp(),
            .assessment_id = try self.allocator.dupe(u8, assessment.manifest.assessment_id),
            .profile_id = try self.allocator.dupe(u8, assessment.profile_id),
            .items = normalized_items,
            .snapshot_hash = snapshot_hash,
        };

        try chain_ptr.versions.append(self.allocator, new_snapshot);

        // Apply retention policy: remove oldest versions exceeding max_retention_versions
        while (chain_ptr.versions.items.len > self.max_retention_versions) {
            var oldest = chain_ptr.versions.orderedRemove(0);
            oldest.deinit(self.allocator);
        }

        return &chain_ptr.versions.items[chain_ptr.versions.items.len - 1];
    }

    /// Retrieve an explicit baseline version, or latest if version is null
    pub fn inspect(self: *const BaselineManager, name: []const u8, target_version: ?u32) !*const BaselineSnapshot {
        const chain = self.chains.get(name) orelse return error.BaselineNotFound;
        if (target_version) |v| {
            for (chain.versions.items) |*snap| {
                if (snap.version == v) return snap;
            }
            return error.BaselineVersionNotFound;
        }
        return &chain.versions.items[chain.versions.items.len - 1];
    }

    /// Explicit deletion of a baseline or single version
    pub fn delete(self: *BaselineManager, name: []const u8, target_version: ?u32) !void {
        const chain_ptr = self.chains.getPtr(name) orelse return error.BaselineNotFound;

        if (target_version) |v| {
            var found_idx: ?usize = null;
            for (chain_ptr.versions.items, 0..) |snap, idx| {
                if (snap.version == v) {
                    found_idx = idx;
                    break;
                }
            }
            if (found_idx) |idx| {
                var removed = chain_ptr.versions.orderedRemove(idx);
                removed.deinit(self.allocator);
                if (chain_ptr.versions.items.len == 0) {
                    _ = self.chains.remove(name);
                    chain_ptr.deinit(self.allocator);
                }
                return;
            }
            return error.BaselineVersionNotFound;
        } else {
            // Delete entire baseline chain
            if (self.chains.fetchRemove(name)) |kv| {
                var c = kv.value;
                c.deinit(self.allocator);
            }
        }
    }

    pub fn list(self: *const BaselineManager, writer: anytype) !void {
        try writer.print(
            \\================================================================================
            \\WIRESCOPE STORED BASELINE SNAPSHOTS
            \\================================================================================
            \\Retention Limit:     {d} versions per baseline
            \\Total Baselines:     {d}
            \\
            \\  Baseline Name             Ver   Total Vers  Items  SHA-256 Digest (Latest)
            \\  --------------------------------------------------------------------------------
            \\
        , .{ self.max_retention_versions, self.chains.count() });

        var iter = self.chains.iterator();
        while (iter.next()) |entry| {
            const chain = entry.value_ptr.*;
            const latest = &chain.versions.items[chain.versions.items.len - 1];
            try writer.print("  {s:<25} v{d:<4} {d:<11} {d:<6} {s}...\n", .{
                chain.name,
                latest.version,
                chain.versions.items.len,
                latest.items.len,
                latest.snapshot_hash[0..16],
            });
        }

        try writer.print(
            \\================================================================================
            \\
        , .{});
    }

    /// Compare current assessment observations against a named baseline version
    pub fn compare(
        self: *const BaselineManager,
        allocator: std.mem.Allocator,
        name: []const u8,
        target_version: ?u32,
        new_assessment: *const AssessmentResult,
    ) !BaselineDiffReport {
        const baseline = try self.inspect(name, target_version);
        const observed_items = try normalizeObservations(allocator, &new_assessment.observations);
        defer {
            for (observed_items) |*it| it.deinit(allocator);
            allocator.free(observed_items);
        }

        var entries = std.ArrayList(DiffEntry).init(allocator);
        errdefer {
            for (entries.items) |*e| e.deinit(allocator);
            entries.deinit();
        }

        var new_count: usize = 0;
        var removed_count: usize = 0;
        var changed_count: usize = 0;
        var unchanged_count: usize = 0;
        var inconclusive_count: usize = 0;

        const is_assessment_incomplete = (new_assessment.status == .partial or new_assessment.status == .failed or new_assessment.status == .cancelled);

        // 1. Iterate over baseline items: check whether present, changed, removed, or inconclusive
        for (baseline.items) |b_item| {
            var found_observed: ?NormalizedBaselineItem = null;
            for (observed_items) |o_item| {
                if (std.mem.eql(u8, b_item.key, o_item.key)) {
                    found_observed = o_item;
                    break;
                }
            }

            if (found_observed) |o_item| {
                if (std.mem.eql(u8, b_item.details, o_item.details)) {
                    unchanged_count += 1;
                    try entries.append(.{
                        .key = try allocator.dupe(u8, b_item.key),
                        .item_type = b_item.item_type,
                        .classification = .unchanged_item,
                        .baseline_value = try allocator.dupe(u8, b_item.details),
                        .observed_value = try allocator.dupe(u8, o_item.details),
                        .explanation = try allocator.dupe(u8, "Item configuration is identical to baseline snapshot."),
                    });
                } else {
                    changed_count += 1;
                    try entries.append(.{
                        .key = try allocator.dupe(u8, b_item.key),
                        .item_type = b_item.item_type,
                        .classification = .changed_item,
                        .baseline_value = try allocator.dupe(u8, b_item.details),
                        .observed_value = try allocator.dupe(u8, o_item.details),
                        .explanation = try allocator.dupe(u8, "Observed configuration deviates from baseline snapshot."),
                    });
                }
            } else {
                // Not found in observed items.
                // Incomplete evidence invariant: If the assessment was incomplete or had errors,
                // a missing item MUST be classified as inconclusive, NOT removed!
                if (is_assessment_incomplete) {
                    inconclusive_count += 1;
                    try entries.append(.{
                        .key = try allocator.dupe(u8, b_item.key),
                        .item_type = b_item.item_type,
                        .classification = .inconclusive,
                        .baseline_value = try allocator.dupe(u8, b_item.details),
                        .observed_value = null,
                        .explanation = try allocator.dupe(u8, "Assessment was incomplete or encountered errors; cannot assert removal without complete observation."),
                    });
                } else {
                    removed_count += 1;
                    try entries.append(.{
                        .key = try allocator.dupe(u8, b_item.key),
                        .item_type = b_item.item_type,
                        .classification = .removed_item,
                        .baseline_value = try allocator.dupe(u8, b_item.details),
                        .observed_value = null,
                        .explanation = try allocator.dupe(u8, "Item was confirmed absent in complete observation."),
                    });
                }
            }
        }

        // 2. Iterate over observed items: find items absent from baseline (new items)
        for (observed_items) |o_item| {
            var found_in_baseline = false;
            for (baseline.items) |b_item| {
                if (std.mem.eql(u8, o_item.key, b_item.key)) {
                    found_in_baseline = true;
                    break;
                }
            }

            if (!found_in_baseline) {
                new_count += 1;
                try entries.append(.{
                    .key = try allocator.dupe(u8, o_item.key),
                    .item_type = o_item.item_type,
                    .classification = .new_item,
                    .baseline_value = null,
                    .observed_value = try allocator.dupe(u8, o_item.details),
                    .explanation = try allocator.dupe(u8, "New observation absent from approved baseline snapshot."),
                });
            }
        }

        // 3. Strict Determinism Invariant: Sort all diff entries lexicographically by key
        std.mem.sort(DiffEntry, entries.items, {}, struct {
            fn lessThan(_: void, a: DiffEntry, b: DiffEntry) bool {
                return std.mem.lessThan(u8, a.key, b.key);
            }
        }.lessThan);

        return BaselineDiffReport{
            .baseline_name = try allocator.dupe(u8, name),
            .baseline_version = baseline.version,
            .compared_at_ms = std.time.milliTimestamp(),
            .total_baseline_items = baseline.items.len,
            .total_observed_items = observed_items.len,
            .new_count = new_count,
            .removed_count = removed_count,
            .changed_count = changed_count,
            .unchanged_count = unchanged_count,
            .inconclusive_count = inconclusive_count,
            .entries = try entries.toOwnedSlice(),
            .allocator = allocator,
        };
    }
};

// -----------------------------------------------------------------------------
// Unit & Integration Tests (Phase 10.2 Acceptance Criteria)
// -----------------------------------------------------------------------------

test "baseline: full CRUD lifecycle (create, list, inspect, update, delete) and version retention" {
    var mgr = BaselineManager.init(testing.allocator);
    defer mgr.deinit();

    var runner = runner_mod.AssessmentRunner.init(testing.allocator);
    const profile = runner_mod.BuiltinProfiles.loopback_diagnostic;
    var assessment1 = try runner.run(profile, .{ .mode = .fixture });
    defer assessment1.deinit();

    // 1. Create Baseline
    const snap1 = try mgr.create("test-base", &assessment1);
    try testing.expectEqual(@as(u32, 1), snap1.version);
    try testing.expectEqualStrings("test-base", snap1.name);
    try testing.expect(snap1.items.len > 0);

    // 2. Prevent Duplicate Creation (requires explicit update command)
    try testing.expectError(error.BaselineAlreadyExists, mgr.create("test-base", &assessment1));

    // 3. Inspect Baseline
    const inspected = try mgr.inspect("test-base", null);
    try testing.expectEqual(@as(u32, 1), inspected.version);

    // 4. Update Baseline (creates v2, preserves v1 in history)
    var assessment2 = try runner.run(profile, .{ .mode = .fixture });
    defer assessment2.deinit();

    const snap2 = try mgr.update("test-base", &assessment2);
    try testing.expectEqual(@as(u32, 2), snap2.version);

    // Verify v1 is still available in history!
    const old_v1 = try mgr.inspect("test-base", 1);
    try testing.expectEqual(@as(u32, 1), old_v1.version);

    // 5. Test Retention Policy Limit (add versions up to 7, verify bounded to 5)
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        _ = try mgr.update("test-base", &assessment2);
    }
    const chain = mgr.chains.get("test-base").?;
    try testing.expectEqual(@as(usize, 5), chain.versions.items.len);

    // 6. Delete explicit version
    const latest_v = chain.versions.items[chain.versions.items.len - 1].version;
    try mgr.delete("test-base", latest_v);
    const updated_chain = mgr.chains.get("test-base").?;
    try testing.expectEqual(@as(usize, 4), updated_chain.versions.items.len);

    // 7. Delete entire baseline
    try mgr.delete("test-base", null);
    try testing.expectError(error.BaselineNotFound, mgr.inspect("test-base", null));
}

test "baseline: deterministic diff correctly detects changed listeners, DNS, and TLS" {
    var mgr = BaselineManager.init(testing.allocator);
    defer mgr.deinit();

    var runner = runner_mod.AssessmentRunner.init(testing.allocator);
    const profile = runner_mod.BuiltinProfiles.local_security_audit;

    // Run baseline assessment
    var base_assessment = try runner.run(profile, .{ .mode = .fixture });
    defer base_assessment.deinit();
    _ = try mgr.create("prod-sec", &base_assessment);

    // Run modified assessment with changed listener (wildcard exposure) and modified TLS protocol
    var mod_assessment = try runner.run(profile, .{ .mode = .fixture });
    defer mod_assessment.deinit();

    // Modify listener from loopback to wildcard
    if (mod_assessment.observations.listeners.items.len > 0) {
        testing.allocator.free(mod_assessment.observations.listeners.items[0].binding_type);
        mod_assessment.observations.listeners.items[0].binding_type = try testing.allocator.dupe(u8, "wildcard");
    }

    // Modify TLS protocol from TLSv1.3 to TLSv1.2
    if (mod_assessment.observations.tls.items.len > 0) {
        testing.allocator.free(mod_assessment.observations.tls.items[0].protocol_version);
        mod_assessment.observations.tls.items[0].protocol_version = try testing.allocator.dupe(u8, "TLSv1.2");
    }

    var diff = try mgr.compare(testing.allocator, "prod-sec", null, &mod_assessment);
    defer diff.deinit();

    try testing.expect(diff.changed_count >= 2);
    try testing.expect(diff.unchanged_count > 0);

    // Verify determinism: Running comparison again yields identical counts
    var diff2 = try mgr.compare(testing.allocator, "prod-sec", null, &mod_assessment);
    defer diff2.deinit();

    try testing.expectEqual(diff.changed_count, diff2.changed_count);
    try testing.expectEqual(diff.unchanged_count, diff2.unchanged_count);
    try testing.expectEqual(diff.new_count, diff2.new_count);
    try testing.expectEqual(diff.removed_count, diff2.removed_count);
}

test "baseline: incomplete evidence does NOT imply removal (inconclusive classification)" {
    var mgr = BaselineManager.init(testing.allocator);
    defer mgr.deinit();

    var runner = runner_mod.AssessmentRunner.init(testing.allocator);
    const profile = runner_mod.BuiltinProfiles.local_security_audit;

    // Run complete baseline assessment
    var base_assessment = try runner.run(profile, .{ .mode = .fixture });
    defer base_assessment.deinit();
    _ = try mgr.create("sec-baseline", &base_assessment);

    // Run incomplete assessment (simulated partial failure where TCP failed)
    var partial_assessment = try runner.run(profile, .{ .mode = .fixture, .fail_tcp = true });
    defer partial_assessment.deinit();
    try testing.expectEqual(runner_mod.AssessmentStatus.partial, partial_assessment.status);

    var diff = try mgr.compare(testing.allocator, "sec-baseline", null, &partial_assessment);
    defer diff.deinit();

    // Acceptance criterion: Incomplete evidence does not imply removal!
    // Unobserved/failed items are classified as inconclusive, NOT removed!
    try testing.expect(diff.inconclusive_count > 0 or diff.changed_count > 0);
    try testing.expectEqual(@as(usize, 0), diff.removed_count);
}
