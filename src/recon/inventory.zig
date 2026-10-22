const std = @import("std");
const testing = std.testing;

const plan_mod = @import("plan.zig");
const discovery_mod = @import("discovery.zig");
const service_mod = @import("service.zig");

pub const LEGAL_DISCLAIMER = plan_mod.LEGAL_DISCLAIMER;
pub const HostReachabilityState = discovery_mod.HostReachabilityState;
pub const HostDiscoveryResult = discovery_mod.HostDiscoveryResult;
pub const DiscoveredHost = discovery_mod.DiscoveredHost;

pub const PortState = service_mod.PortState;
pub const ConfidenceLevel = service_mod.ConfidenceLevel;
pub const IdentificationMethod = service_mod.IdentificationMethod;
pub const ServiceIdentity = service_mod.ServiceIdentity;
pub const PortCheckResult = service_mod.PortCheckResult;
pub const ServiceScanResult = service_mod.ServiceScanResult;

/// Observed service on an inventory asset, preserving raw evidence
pub const AssetService = struct {
    port: u16,
    protocol: []const u8, // e.g. "tcp"
    service_name: ?[]const u8 = null,
    version: ?[]const u8 = null,
    banner: ?[]const u8 = null,
    confidence: ConfidenceLevel = .none,
    method: IdentificationMethod = .none,
    first_seen_sec: i64,
    last_seen_sec: i64,
    original_evidence: []const u8, // Raw empirical evidence preserved!

    pub fn deinit(self: *AssetService, allocator: std.mem.Allocator) void {
        allocator.free(self.protocol);
        if (self.service_name) |s| allocator.free(s);
        if (self.version) |v| allocator.free(v);
        if (self.banner) |b| allocator.free(b);
        allocator.free(self.original_evidence);
    }

    pub fn clone(self: *const AssetService, allocator: std.mem.Allocator) !AssetService {
        const proto_dup = try allocator.dupe(u8, self.protocol);
        errdefer allocator.free(proto_dup);

        const s_dup = if (self.service_name) |s| try allocator.dupe(u8, s) else null;
        errdefer if (s_dup) |s| allocator.free(s);

        const v_dup = if (self.version) |v| try allocator.dupe(u8, v) else null;
        errdefer if (v_dup) |v| allocator.free(v);

        const b_dup = if (self.banner) |b| try allocator.dupe(u8, b) else null;
        errdefer if (b_dup) |b| allocator.free(b);

        const ev_dup = try allocator.dupe(u8, self.original_evidence);

        return AssetService{
            .port = self.port,
            .protocol = proto_dup,
            .service_name = s_dup,
            .version = v_dup,
            .banner = b_dup,
            .confidence = self.confidence,
            .method = self.method,
            .first_seen_sec = self.first_seen_sec,
            .last_seen_sec = self.last_seen_sec,
            .original_evidence = ev_dup,
        };
    }
};

/// Normalized host in the asset inventory
pub const AssetHost = struct {
    id: []const u8,
    ip_address: []const u8,
    hostname: ?[]const u8 = null,
    reachability_state: HostReachabilityState,
    first_seen_sec: i64,
    last_seen_sec: i64,
    services: []AssetService,
    original_evidence: []const u8, // Preserves raw evidence from discovery!

    pub fn deinit(self: *AssetHost, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.ip_address);
        if (self.hostname) |h| allocator.free(h);
        for (self.services) |*s| {
            s.deinit(allocator);
        }
        if (self.services.len > 0) {
            allocator.free(self.services);
        }
        allocator.free(self.original_evidence);
    }

    pub fn clone(self: *const AssetHost, allocator: std.mem.Allocator) !AssetHost {
        const id_dup = try allocator.dupe(u8, self.id);
        errdefer allocator.free(id_dup);

        const ip_dup = try allocator.dupe(u8, self.ip_address);
        errdefer allocator.free(ip_dup);

        const h_dup = if (self.hostname) |h| try allocator.dupe(u8, h) else null;
        errdefer if (h_dup) |h| allocator.free(h);

        var s_list = std.ArrayList(AssetService).init(allocator);
        errdefer {
            for (s_list.items) |*s| s.deinit(allocator);
            s_list.deinit();
        }

        for (self.services) |*s| {
            const sc = try s.clone(allocator);
            try s_list.append(sc);
        }

        const ev_dup = try allocator.dupe(u8, self.original_evidence);

        return AssetHost{
            .id = id_dup,
            .ip_address = ip_dup,
            .hostname = h_dup,
            .reachability_state = self.reachability_state,
            .first_seen_sec = self.first_seen_sec,
            .last_seen_sec = self.last_seen_sec,
            .services = try s_list.toOwnedSlice(),
            .original_evidence = ev_dup,
        };
    }
};

/// Category of difference observed between assessment inventories
pub const DiffCategory = enum {
    new_asset,
    new_service,
    removed_service,
    changed_service,
    unchanged_service,
    inconclusive_state,

    pub fn asString(self: DiffCategory) []const u8 {
        return switch (self) {
            .new_asset => "new_asset",
            .new_service => "new_service",
            .removed_service => "removed_service",
            .changed_service => "changed_service",
            .unchanged_service => "unchanged_service",
            .inconclusive_state => "inconclusive_state",
        };
    }
};

/// Individual difference record comparing two observation runs
pub const DiffEntry = struct {
    category: DiffCategory,
    target: []const u8,
    port: ?u16 = null,
    old_value: ?[]const u8 = null,
    new_value: ?[]const u8 = null,
    reason: []const u8,

    pub fn deinit(self: *DiffEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.target);
        if (self.old_value) |v| allocator.free(v);
        if (self.new_value) |v| allocator.free(v);
        allocator.free(self.reason);
    }
};

/// Aggregated diff between baseline and current assessment inventories
pub const InventoryDiff = struct {
    entries: []DiffEntry,
    new_assets_count: usize,
    new_services_count: usize,
    removed_services_count: usize,
    changed_services_count: usize,
    unchanged_count: usize,
    inconclusive_count: usize,
    legal_disclaimer: []const u8 = LEGAL_DISCLAIMER,

    pub fn deinit(self: *InventoryDiff, allocator: std.mem.Allocator) void {
        for (self.entries) |*e| {
            e.deinit(allocator);
        }
        if (self.entries.len > 0) {
            allocator.free(self.entries);
        }
    }

    /// Formats human-readable CLI terminal diff
    pub fn toTerminal(self: *const InventoryDiff, writer: anytype) !void {
        try writer.print(
            \\WireScope Asset Inventory Assessment Diff
            \\==========================================
            \\New Assets:           {d}
            \\New Services:         {d}
            \\Removed Services:     {d}
            \\Changed Services:     {d}
            \\Unchanged:            {d}
            \\Inconclusive/Pending: {d}
            \\
            \\Diff Observations ({d}):
            \\
        , .{
            self.new_assets_count,
            self.new_services_count,
            self.removed_services_count,
            self.changed_services_count,
            self.unchanged_count,
            self.inconclusive_count,
            self.entries.len,
        });

        for (self.entries, 0..) |e, idx| {
            const tag: []const u8 = switch (e.category) {
                .new_asset => "[+ ASSET]",
                .new_service => "[+ SERVICE]",
                .removed_service => "[- REMOVED]",
                .changed_service => "[~ CHANGED]",
                .unchanged_service => "[= UNCHANGED]",
                .inconclusive_state => "[? INCONCLUSIVE]",
            };

            try writer.print("  {d:>3}. {s:<16} {s}", .{ idx + 1, tag, e.target });
            if (e.port) |p| {
                try writer.print(":{d}", .{p});
            }
            try writer.print("\n", .{});

            if (e.old_value != null or e.new_value != null) {
                try writer.print("       From: {s} -> To: {s}\n", .{
                    if (e.old_value) |ov| ov else "none",
                    if (e.new_value) |nv| nv else "none",
                });
            }
            try writer.print("       Reason: {s}\n", .{e.reason});
        }

        try writer.print(
            \\
            \\[LEGAL DISCLAIMER]
            \\{s}
            \\
        , .{self.legal_disclaimer});
    }

    /// Formats machine-readable JSON diff
    pub fn toJson(self: *const InventoryDiff, writer: anytype) !void {
        try writer.print(
            \\{{"type":"inventory_diff","summary":{{"new_assets":{d},"new_services":{d},"removed_services":{d},"changed_services":{d},"unchanged":{d},"inconclusive":{d}}},"legal_disclaimer":"{s}","entries":[
        , .{
            self.new_assets_count,
            self.new_services_count,
            self.removed_services_count,
            self.changed_services_count,
            self.unchanged_count,
            self.inconclusive_count,
            self.legal_disclaimer,
        });

        for (self.entries, 0..) |e, idx| {
            if (idx > 0) try writer.print(",", .{});
            try writer.print(
                \\{{"category":"{s}","target":"{s}","port":
            , .{
                e.category.asString(),
                e.target,
            });

            if (e.port) |p| {
                try writer.print("{d}", .{p});
            } else {
                try writer.writeAll("null");
            }

            try writer.print(",\"old_value\":", .{});
            if (e.old_value) |ov| try writer.print("\"{s}\"", .{ov}) else try writer.writeAll("null");

            try writer.print(",\"new_value\":", .{});
            if (e.new_value) |nv| try writer.print("\"{s}\"", .{nv}) else try writer.writeAll("null");

            try writer.print(",\"reason\":\"{s}\"}}", .{e.reason});
        }

        try writer.print("]}}\n", .{});
    }
};

/// Normalized Asset and Exposure Inventory
pub const AssetInventory = struct {
    schema_version: u32 = 1,
    created_at_sec: i64,
    updated_at_sec: i64,
    hosts: []AssetHost,
    total_hosts: usize,
    total_services: usize,
    legal_disclaimer: []const u8 = LEGAL_DISCLAIMER,

    pub fn init(allocator: std.mem.Allocator, now_sec: i64) AssetInventory {
        _ = allocator;
        return AssetInventory{
            .schema_version = 1,
            .created_at_sec = now_sec,
            .updated_at_sec = now_sec,
            .hosts = &.{},
            .total_hosts = 0,
            .total_services = 0,
            .legal_disclaimer = LEGAL_DISCLAIMER,
        };
    }

    pub fn deinit(self: *AssetInventory, allocator: std.mem.Allocator) void {
        for (self.hosts) |*h| {
            h.deinit(allocator);
        }
        if (self.hosts.len > 0) {
            allocator.free(self.hosts);
        }
    }

    /// Ingests discovery results into normalized inventory
    pub fn ingestHostDiscovery(
        self: *AssetInventory,
        allocator: std.mem.Allocator,
        result: *const HostDiscoveryResult,
        now_sec: i64,
    ) !void {
        var host_list = std.ArrayList(AssetHost).init(allocator);
        errdefer {
            for (host_list.items) |*h| h.deinit(allocator);
            host_list.deinit();
        }

        // Copy existing hosts
        for (self.hosts) |*h| {
            const hc = try h.clone(allocator);
            try host_list.append(hc);
        }

        // Process newly observed hosts
        for (result.hosts) |h| {
            var existing_idx: ?usize = null;
            for (host_list.items, 0..) |eh, idx| {
                if (std.mem.eql(u8, eh.ip_address, h.target)) {
                    existing_idx = idx;
                    break;
                }
            }

            if (existing_idx) |idx| {
                // Update existing host
                host_list.items[idx].last_seen_sec = now_sec;
                host_list.items[idx].reachability_state = h.state;
                allocator.free(host_list.items[idx].original_evidence);
                host_list.items[idx].original_evidence = try allocator.dupe(u8, h.evidence.notes);
            } else {
                // Add new host
                const id_str = try std.fmt.allocPrint(allocator, "asset_{s}", .{h.target});
                const ip_dup = try allocator.dupe(u8, h.target);
                const ev_dup = try allocator.dupe(u8, h.evidence.notes);

                try host_list.append(.{
                    .id = id_str,
                    .ip_address = ip_dup,
                    .hostname = null,
                    .reachability_state = h.state,
                    .first_seen_sec = now_sec,
                    .last_seen_sec = now_sec,
                    .services = &.{},
                    .original_evidence = ev_dup,
                });
            }
        }

        // Sort hosts by IP address ascending
        sortHosts(host_list.items);

        // Free previous slice and replace
        if (self.hosts.len > 0) {
            for (self.hosts) |*h| h.deinit(allocator);
            allocator.free(self.hosts);
        }

        self.hosts = try host_list.toOwnedSlice();
        self.total_hosts = self.hosts.len;
        self.updated_at_sec = now_sec;
    }

    /// Ingests port checks and identified services into inventory
    pub fn ingestServiceScan(
        self: *AssetInventory,
        allocator: std.mem.Allocator,
        result: *const ServiceScanResult,
        now_sec: i64,
    ) !void {
        var host_list = std.ArrayList(AssetHost).init(allocator);
        errdefer {
            for (host_list.items) |*h| h.deinit(allocator);
            host_list.deinit();
        }

        // Copy existing hosts
        for (self.hosts) |*h| {
            const hc = try h.clone(allocator);
            try host_list.append(hc);
        }

        var total_svcs: usize = 0;

        for (result.checks) |check| {
            var host_idx: usize = 0;
            var found_host = false;
            for (host_list.items, 0..) |eh, idx| {
                if (std.mem.eql(u8, eh.ip_address, check.target)) {
                    host_idx = idx;
                    found_host = true;
                    break;
                }
            }

            if (!found_host) {
                // Create host entry
                const id_str = try std.fmt.allocPrint(allocator, "asset_{s}", .{check.target});
                const ip_dup = try allocator.dupe(u8, check.target);
                const ev_dup = try allocator.dupe(u8, "Observed during port scan");

                const new_h = AssetHost{
                    .id = id_str,
                    .ip_address = ip_dup,
                    .hostname = null,
                    .reachability_state = if (check.state == .open) .reachable else .inconclusive,
                    .first_seen_sec = now_sec,
                    .last_seen_sec = now_sec,
                    .services = &.{},
                    .original_evidence = ev_dup,
                };
                host_idx = host_list.items.len;
                try host_list.append(new_h);
            }

            var host_ref = &host_list.items[host_idx];
            host_ref.last_seen_sec = now_sec;
            if (check.state == .open) {
                host_ref.reachability_state = .reachable;
            }

            // Only add open services to host.services
            if (check.state == .open) {
                var s_list = std.ArrayList(AssetService).init(allocator);
                defer s_list.deinit();

                var found_svc = false;
                for (host_ref.services) |*s| {
                    if (s.port == check.port) {
                        found_svc = true;
                        // Update existing service
                        s.last_seen_sec = now_sec;
                        if (check.service.service_name) |sn| {
                            if (s.service_name) |old_sn| allocator.free(old_sn);
                            s.service_name = try allocator.dupe(u8, sn);
                        }
                        if (check.service.version) |v| {
                            if (s.version) |old_v| allocator.free(old_v);
                            s.version = try allocator.dupe(u8, v);
                        }
                        if (check.service.banner) |b| {
                            if (s.banner) |old_b| allocator.free(old_b);
                            s.banner = try allocator.dupe(u8, b);
                        }
                        s.confidence = check.service.confidence;
                        s.method = check.service.method;
                        allocator.free(s.original_evidence);
                        s.original_evidence = try allocator.dupe(u8, check.service.limitations);
                    }
                    const sc = try s.clone(allocator);
                    try s_list.append(sc);
                }

                if (!found_svc) {
                    // New service
                    const proto_dup = try allocator.dupe(u8, "tcp");
                    const s_dup = if (check.service.service_name) |s| try allocator.dupe(u8, s) else null;
                    const v_dup = if (check.service.version) |v| try allocator.dupe(u8, v) else null;
                    const b_dup = if (check.service.banner) |b| try allocator.dupe(u8, b) else null;
                    const ev_dup = try allocator.dupe(u8, check.service.limitations);

                    try s_list.append(.{
                        .port = check.port,
                        .protocol = proto_dup,
                        .service_name = s_dup,
                        .version = v_dup,
                        .banner = b_dup,
                        .confidence = check.service.confidence,
                        .method = check.service.method,
                        .first_seen_sec = now_sec,
                        .last_seen_sec = now_sec,
                        .original_evidence = ev_dup,
                    });
                }

                // Sort services by port ascending
                std.mem.sort(AssetService, s_list.items, {}, struct {
                    fn lessThan(_: void, a: AssetService, b: AssetService) bool {
                        return a.port < b.port;
                    }
                }.lessThan);

                // Free old services and update
                for (host_ref.services) |*s| s.deinit(allocator);
                if (host_ref.services.len > 0) allocator.free(host_ref.services);
                host_ref.services = try s_list.toOwnedSlice();
            }
        }

        // Compute total services
        for (host_list.items) |h| {
            total_svcs += h.services.len;
        }

        // Sort hosts by IP address ascending
        sortHosts(host_list.items);

        // Replace
        if (self.hosts.len > 0) {
            for (self.hosts) |*h| h.deinit(allocator);
            allocator.free(self.hosts);
        }

        self.hosts = try host_list.toOwnedSlice();
        self.total_hosts = self.hosts.len;
        self.total_services = total_svcs;
        self.updated_at_sec = now_sec;
    }

    /// Deterministically compares two inventory snapshots (Baseline vs Current)
    /// Enforces the invariant: Incomplete observations do not create false removals!
    pub fn compare(
        self: *const AssetInventory,
        allocator: std.mem.Allocator,
        current: *const AssetInventory,
    ) !InventoryDiff {
        var diff_list = std.ArrayList(DiffEntry).init(allocator);
        errdefer {
            for (diff_list.items) |*e| e.deinit(allocator);
            diff_list.deinit();
        }

        var new_assets: usize = 0;
        var new_services: usize = 0;
        var removed_services: usize = 0;
        var changed_services: usize = 0;
        var unchanged_count: usize = 0;
        var inconclusive_count: usize = 0;

        // 1. Check for New Assets & Services in Current that were not in Self (Baseline)
        for (current.hosts) |ch| {
            var in_baseline = false;
            for (self.hosts) |bh| {
                if (std.mem.eql(u8, bh.ip_address, ch.ip_address)) {
                    in_baseline = true;
                    break;
                }
            }

            if (!in_baseline) {
                // Completely new host asset
                const t_dup = try allocator.dupe(u8, ch.ip_address);
                const r_dup = try allocator.dupe(u8, "New asset discovered in current assessment run");
                try diff_list.append(.{
                    .category = .new_asset,
                    .target = t_dup,
                    .port = null,
                    .old_value = null,
                    .new_value = null,
                    .reason = r_dup,
                });
                new_assets += 1;

                // All services on new asset are new services
                for (ch.services) |cs| {
                    const st_dup = try allocator.dupe(u8, ch.ip_address);
                    const sn_dup = if (cs.service_name) |s| try allocator.dupe(u8, s) else null;
                    const sr_dup = try allocator.dupe(u8, "New service observed on newly discovered asset");
                    try diff_list.append(.{
                        .category = .new_service,
                        .target = st_dup,
                        .port = cs.port,
                        .old_value = null,
                        .new_value = sn_dup,
                        .reason = sr_dup,
                    });
                    new_services += 1;
                }
            }
        }

        // 2. Compare Assets & Services present in Baseline
        for (self.hosts) |bh| {
            var curr_host_opt: ?*const AssetHost = null;
            for (current.hosts) |*ch| {
                if (std.mem.eql(u8, ch.ip_address, bh.ip_address)) {
                    curr_host_opt = ch;
                    break;
                }
            }

            const ch = curr_host_opt orelse {
                // Invariant: If a baseline host was unobserved in current run, it is INCONCLUSIVE, not removed!
                const t_dup = try allocator.dupe(u8, bh.ip_address);
                const r_dup = try allocator.dupe(u8, "Host not observed in current assessment run; treated as inconclusive to prevent false removal");
                try diff_list.append(.{
                    .category = .inconclusive_state,
                    .target = t_dup,
                    .port = null,
                    .old_value = null,
                    .new_value = null,
                    .reason = r_dup,
                });
                inconclusive_count += 1;
                continue;
            };

            // Host was observed in current run. Compare services!
            for (bh.services) |bs| {
                var curr_svc_opt: ?*const AssetService = null;
                for (ch.services) |*cs| {
                    if (cs.port == bs.port) {
                        curr_svc_opt = cs;
                        break;
                    }
                }

                if (curr_svc_opt) |cs| {
                    // Service observed in both runs!
                    const old_v = bs.version orelse bs.service_name orelse "unidentified";
                    const new_v = cs.version orelse cs.service_name orelse "unidentified";

                    if (!std.mem.eql(u8, old_v, new_v)) {
                        // Service version or identification changed!
                        const t_dup = try allocator.dupe(u8, bh.ip_address);
                        const ov_dup = try allocator.dupe(u8, old_v);
                        const nv_dup = try allocator.dupe(u8, new_v);
                        const r_dup = try allocator.dupe(u8, "Service version or identity modified between assessment runs");

                        try diff_list.append(.{
                            .category = .changed_service,
                            .target = t_dup,
                            .port = bs.port,
                            .old_value = ov_dup,
                            .new_value = nv_dup,
                            .reason = r_dup,
                        });
                        changed_services += 1;
                    } else {
                        // Unchanged service!
                        const t_dup = try allocator.dupe(u8, bh.ip_address);
                        const r_dup = try allocator.dupe(u8, "Service identity and port state unchanged between runs");

                        try diff_list.append(.{
                            .category = .unchanged_service,
                            .target = t_dup,
                            .port = bs.port,
                            .old_value = null,
                            .new_value = null,
                            .reason = r_dup,
                        });
                        unchanged_count += 1;
                    }
                } else {
                    // Service was NOT observed open in current run!
                    // Invariant: Incomplete observations do not create false removals!
                    // Only mark removed if current host was explicitly reachable and verified closed!
                    if (ch.reachability_state == .reachable) {
                        // Verified removal via active connection refusal
                        const t_dup = try allocator.dupe(u8, bh.ip_address);
                        const sn_dup = if (bs.service_name) |s| try allocator.dupe(u8, s) else null;
                        const r_dup = try allocator.dupe(u8, "Service verified closed on active host (TCP RST received)");

                        try diff_list.append(.{
                            .category = .removed_service,
                            .target = t_dup,
                            .port = bs.port,
                            .old_value = sn_dup,
                            .new_value = null,
                            .reason = r_dup,
                        });
                        removed_services += 1;
                    } else {
                        // Inconclusive! Host was timeout or unreached, so service cannot be assumed removed
                        const t_dup = try allocator.dupe(u8, bh.ip_address);
                        const sn_dup = if (bs.service_name) |s| try allocator.dupe(u8, s) else null;
                        const r_dup = try allocator.dupe(u8, "Host was inconclusive or timed out; unobserved service cannot be claimed removed");

                        try diff_list.append(.{
                            .category = .inconclusive_state,
                            .target = t_dup,
                            .port = bs.port,
                            .old_value = sn_dup,
                            .new_value = null,
                            .reason = r_dup,
                        });
                        inconclusive_count += 1;
                    }
                }
            }

            // Check for new services on this existing host
            for (ch.services) |cs| {
                var in_baseline_svc = false;
                for (bh.services) |bs| {
                    if (bs.port == cs.port) {
                        in_baseline_svc = true;
                        break;
                    }
                }

                if (!in_baseline_svc) {
                    const t_dup = try allocator.dupe(u8, ch.ip_address);
                    const sn_dup = if (cs.service_name) |s| try allocator.dupe(u8, s) else null;
                    const r_dup = try allocator.dupe(u8, "New open port and service observed on existing host");

                    try diff_list.append(.{
                        .category = .new_service,
                        .target = t_dup,
                        .port = cs.port,
                        .old_value = null,
                        .new_value = sn_dup,
                        .reason = r_dup,
                    });
                    new_services += 1;
                }
            }
        }

        // Deterministically sort diff entries: target ascending, then port ascending, then category
        std.mem.sort(DiffEntry, diff_list.items, {}, struct {
            fn lessThan(_: void, a: DiffEntry, b: DiffEntry) bool {
                if (!std.mem.eql(u8, a.target, b.target)) {
                    return std.mem.lessThan(u8, a.target, b.target);
                }
                const p_a = a.port orelse 0;
                const p_b = b.port orelse 0;
                if (p_a != p_b) return p_a < p_b;
                return @intFromEnum(a.category) < @intFromEnum(b.category);
            }
        }.lessThan);

        return InventoryDiff{
            .entries = try diff_list.toOwnedSlice(),
            .new_assets_count = new_assets,
            .new_services_count = new_services,
            .removed_services_count = removed_services,
            .changed_services_count = changed_services,
            .unchanged_count = unchanged_count,
            .inconclusive_count = inconclusive_count,
            .legal_disclaimer = LEGAL_DISCLAIMER,
        };
    }

    /// Formats human-readable CLI terminal inventory
    pub fn toTerminal(self: *const AssetInventory, writer: anytype) !void {
        try writer.print(
            \\WireScope Asset and Exposure Inventory
            \\======================================
            \\Total Assets:      {d}
            \\Total Services:    {d}
            \\Created Timestamp: {d}
            \\Updated Timestamp: {d}
            \\
            \\Assets and Exposures:
            \\
        , .{
            self.total_hosts,
            self.total_services,
            self.created_at_sec,
            self.updated_at_sec,
        });

        for (self.hosts, 0..) |h, idx| {
            try writer.print("  [{d:>2}] Asset: {s} (state: {s}, services: {d})\n", .{
                idx + 1,
                h.ip_address,
                h.reachability_state.asString(),
                h.services.len,
            });
            try writer.print("       Original Evidence: {s}\n", .{h.original_evidence});

            for (h.services) |s| {
                const s_name = if (s.service_name) |sn| sn else "unrecognized";
                const v_str = if (s.version) |v| v else "unreported";
                try writer.print("       * {s}:{d:<5} -> {s} (version: {s}, confidence: {s}, method: {s})\n", .{
                    s.protocol,
                    s.port,
                    s_name,
                    v_str,
                    s.confidence.asString(),
                    s.method.asString(),
                });
                try writer.print("         Evidence: {s}\n", .{s.original_evidence});
            }
        }

        try writer.print(
            \\
            \\[LEGAL DISCLAIMER]
            \\{s}
            \\
        , .{self.legal_disclaimer});
    }

    /// Formats structured machine-readable JSON inventory
    pub fn toJson(self: *const AssetInventory, writer: anytype) !void {
        try writer.print(
            \\{{"type":"asset_inventory","schema_version":{d},"created_at":{d},"updated_at":{d},"summary":{{"total_hosts":{d},"total_services":{d}}},"legal_disclaimer":"{s}","hosts":[
        , .{
            self.schema_version,
            self.created_at_sec,
            self.updated_at_sec,
            self.total_hosts,
            self.total_services,
            self.legal_disclaimer,
        });

        for (self.hosts, 0..) |h, h_idx| {
            if (h_idx > 0) try writer.print(",", .{});
            try writer.print(
                \\{{"id":"{s}","ip_address":"{s}","state":"{s}","first_seen":{d},"last_seen":{d},"original_evidence":"{s}","services":[
            , .{
                h.id,
                h.ip_address,
                h.reachability_state.asString(),
                h.first_seen_sec,
                h.last_seen_sec,
                h.original_evidence,
            });

            for (h.services, 0..) |s, s_idx| {
                if (s_idx > 0) try writer.print(",", .{});
                try writer.print(
                    \\{{"port":{d},"protocol":"{s}","service":
                , .{ s.port, s.protocol });

                if (s.service_name) |sn| {
                    try writer.print("\"{s}\"", .{sn});
                } else {
                    try writer.writeAll("null");
                }

                try writer.print(",\"version\":", .{});
                if (s.version) |v| try writer.print("\"{s}\"", .{v}) else try writer.writeAll("null");

                try writer.print(",\"banner\":", .{});
                if (s.banner) |b| try writer.print("\"{s}\"", .{b}) else try writer.writeAll("null");

                try writer.print(
                    \\,"confidence":"{s}","method":"{s}","original_evidence":"{s}"}}
                , .{
                    s.confidence.asString(),
                    s.method.asString(),
                    s.original_evidence,
                });
            }

            try writer.print("]}}", .{});
        }

        try writer.print("]}}\n", .{});
    }

    /// Rebuilds AssetInventory from structured observations
    pub fn rebuildFromObservations(
        allocator: std.mem.Allocator,
        host_results: []const HostDiscoveryResult,
        service_results: []const ServiceScanResult,
        now_sec: i64,
    ) !AssetInventory {
        var inv = AssetInventory.init(allocator, now_sec);
        errdefer inv.deinit(allocator);

        for (host_results) |*hr| {
            try inv.ingestHostDiscovery(allocator, hr, now_sec);
        }

        for (service_results) |*sr| {
            try inv.ingestServiceScan(allocator, sr, now_sec);
        }

        return inv;
    }
};

fn sortHosts(hosts: []AssetHost) void {
    std.mem.sort(AssetHost, hosts, {}, struct {
        fn lessThan(_: void, a: AssetHost, b: AssetHost) bool {
            return std.mem.lessThan(u8, a.ip_address, b.ip_address);
        }
    }.lessThan);
}

// -------------------------------------------------------------------------
// UNIT TESTS FOR ASSET INVENTORY & DETERMINISTIC DIFFS
// -------------------------------------------------------------------------

test "inventory: rebuild inventory from host discovery and service scan observations" {
    var inv = AssetInventory.init(testing.allocator, 1000);
    defer inv.deinit(testing.allocator);

    // 1. Ingest Host Discovery
    const h1_tgt = try testing.allocator.dupe(u8, "192.168.1.10");
    const h1_resp = try testing.allocator.dupe(u8, "tcp_syn_ack");
    const h1_note = try testing.allocator.dupe(u8, "Host active on TCP port 80");
    var hosts = [_]DiscoveredHost{.{
        .target = h1_tgt,
        .state = .reachable,
        .method = .tcp_probe,
        .evidence = .{
            .response_port = 80,
            .response_type = h1_resp,
            .rtt_ms = 4.2,
            .notes = h1_note,
        },
    }};

    const host_disc = HostDiscoveryResult{
        .hosts = &hosts,
        .total_scanned = 1,
        .reachable_count = 1,
        .inconclusive_count = 0,
        .failed_count = 0,
        .cancelled_count = 0,
        .elapsed_ms = 10,
        .legal_disclaimer = LEGAL_DISCLAIMER,
    };
    try inv.ingestHostDiscovery(testing.allocator, &host_disc, 1000);
    testing.allocator.free(h1_tgt);
    testing.allocator.free(h1_resp);
    testing.allocator.free(h1_note);

    try testing.expectEqual(@as(usize, 1), inv.total_hosts);
    try testing.expectEqualStrings("192.168.1.10", inv.hosts[0].ip_address);
    try testing.expectEqual(HostReachabilityState.reachable, inv.hosts[0].reachability_state);

    // 2. Ingest Service Scan
    const s_tgt = try testing.allocator.dupe(u8, "192.168.1.10");
    const s_lim = try testing.allocator.dupe(u8, "HTTP confirmed via Server header");
    var checks = [_]PortCheckResult{.{
        .target = s_tgt,
        .port = 80,
        .state = .open,
        .rtt_ms = 4.2,
        .service = .{
            .service_name = "http",
            .confidence = .confirmed,
            .version = "nginx/1.24.0",
            .banner = "nginx/1.24.0",
            .method = .http_head,
            .limitations = s_lim,
        },
    }};

    const svc_scan = ServiceScanResult{
        .checks = &checks,
        .summary = .{
            .total_ports_checked = 1,
            .open_count = 1,
            .closed_count = 0,
            .filtered_count = 0,
            .identified_service_count = 1,
            .elapsed_ms = 10,
        },
        .legal_disclaimer = LEGAL_DISCLAIMER,
    };
    try inv.ingestServiceScan(testing.allocator, &svc_scan, 1000);
    testing.allocator.free(s_tgt);
    testing.allocator.free(s_lim);

    try testing.expectEqual(@as(usize, 1), inv.total_services);
    try testing.expectEqual(@as(u16, 80), inv.hosts[0].services[0].port);
    try testing.expectEqualStrings("http", inv.hosts[0].services[0].service_name.?);
    try testing.expectEqualStrings("nginx/1.24.0", inv.hosts[0].services[0].version.?);

    // Original evidence preserved!
    try testing.expect(std.mem.indexOf(u8, inv.hosts[0].services[0].original_evidence, "HTTP confirmed") != null);
}

test "inventory: diff detects new assets, changed versions, and removed services" {
    // Baseline (Run A)
    var base = AssetInventory.init(testing.allocator, 1000);
    defer base.deinit(testing.allocator);

    const base_checks = [_]PortCheckResult{
        .{
            .target = try testing.allocator.dupe(u8, "10.0.0.1"),
            .port = 80,
            .state = .open,
            .service = .{
                .service_name = "http",
                .version = "Apache/2.4.50",
                .confidence = .confirmed,
                .method = .http_head,
                .limitations = try testing.allocator.dupe(u8, "Lim1"),
            },
        },
        .{
            .target = try testing.allocator.dupe(u8, "10.0.0.1"),
            .port = 22,
            .state = .open,
            .service = .{
                .service_name = "ssh",
                .version = "OpenSSH_8.9",
                .confidence = .confirmed,
                .method = .banner_grab,
                .limitations = try testing.allocator.dupe(u8, "Lim2"),
            },
        },
    };
    defer {
        for (base_checks) |c| {
            testing.allocator.free(c.target);
            testing.allocator.free(c.service.limitations);
        }
    }

    const base_scan = ServiceScanResult{
        .checks = @constCast(&base_checks),
        .summary = .{ .total_ports_checked = 2, .open_count = 2, .closed_count = 0, .filtered_count = 0, .identified_service_count = 2, .elapsed_ms = 5 },
    };
    try base.ingestServiceScan(testing.allocator, &base_scan, 1000);

    // Current (Run B)
    // 10.0.0.1:80 updated to Apache/2.4.54 (changed)
    // 10.0.0.1:22 closed (removed)
    // 10.0.0.2:443 new asset and service
    var curr = AssetInventory.init(testing.allocator, 2000);
    defer curr.deinit(testing.allocator);

    const curr_checks = [_]PortCheckResult{
        .{
            .target = try testing.allocator.dupe(u8, "10.0.0.1"),
            .port = 80,
            .state = .open,
            .service = .{
                .service_name = "http",
                .version = "Apache/2.4.54",
                .confidence = .confirmed,
                .method = .http_head,
                .limitations = try testing.allocator.dupe(u8, "Lim1 updated"),
            },
        },
        .{
            .target = try testing.allocator.dupe(u8, "10.0.0.2"),
            .port = 443,
            .state = .open,
            .service = .{
                .service_name = "https",
                .confidence = .confirmed,
                .method = .tls_handshake,
                .limitations = try testing.allocator.dupe(u8, "TLS 1.3"),
            },
        },
    };
    defer {
        for (curr_checks) |c| {
            testing.allocator.free(c.target);
            testing.allocator.free(c.service.limitations);
        }
    }

    const curr_scan = ServiceScanResult{
        .checks = @constCast(&curr_checks),
        .summary = .{ .total_ports_checked = 2, .open_count = 2, .closed_count = 0, .filtered_count = 0, .identified_service_count = 2, .elapsed_ms = 5 },
    };
    try curr.ingestServiceScan(testing.allocator, &curr_scan, 2000);

    var diff = try base.compare(testing.allocator, &curr);
    defer diff.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), diff.new_assets_count); // 10.0.0.2
    try testing.expectEqual(@as(usize, 1), diff.new_services_count); // 10.0.0.2:443
    try testing.expectEqual(@as(usize, 1), diff.changed_services_count); // 10.0.0.1:80 version changed
    try testing.expectEqual(@as(usize, 1), diff.removed_services_count); // 10.0.0.1:22 removed on active host
}

test "inventory: incomplete observations do NOT create false removals" {
    // Baseline (Run A) has host with port 80 open
    var base = AssetInventory.init(testing.allocator, 1000);
    defer base.deinit(testing.allocator);

    const base_checks = [_]PortCheckResult{.{
        .target = try testing.allocator.dupe(u8, "192.168.1.50"),
        .port = 80,
        .state = .open,
        .service = .{
            .service_name = "http",
            .version = "nginx",
            .confidence = .confirmed,
            .method = .http_head,
            .limitations = try testing.allocator.dupe(u8, "lim"),
        },
    }};
    defer {
        testing.allocator.free(base_checks[0].target);
        testing.allocator.free(base_checks[0].service.limitations);
    }

    const base_scan = ServiceScanResult{
        .checks = @constCast(&base_checks),
        .summary = .{ .total_ports_checked = 1, .open_count = 1, .closed_count = 0, .filtered_count = 0, .identified_service_count = 1, .elapsed_ms = 5 },
    };
    try base.ingestServiceScan(testing.allocator, &base_scan, 1000);

    // Run B is INCOMPLETE or TIMED OUT: host was not reached / no response received
    var curr = AssetInventory.init(testing.allocator, 2000);
    defer curr.deinit(testing.allocator);

    const disc_host = [_]DiscoveredHost{.{
        .target = try testing.allocator.dupe(u8, "192.168.1.50"),
        .state = .inconclusive, // Timeout!
        .method = .tcp_probe,
        .evidence = .{
            .response_port = null,
            .response_type = try testing.allocator.dupe(u8, "timeout"),
            .rtt_ms = null,
            .notes = try testing.allocator.dupe(u8, "No response"),
        },
    }};
    defer {
        testing.allocator.free(disc_host[0].target);
        testing.allocator.free(disc_host[0].evidence.response_type);
        testing.allocator.free(disc_host[0].evidence.notes);
    }

    const curr_disc = HostDiscoveryResult{
        .hosts = @constCast(&disc_host),
        .total_scanned = 1,
        .reachable_count = 0,
        .inconclusive_count = 1,
        .failed_count = 0,
        .cancelled_count = 0,
        .elapsed_ms = 2000,
        .legal_disclaimer = LEGAL_DISCLAIMER,
    };
    try curr.ingestHostDiscovery(testing.allocator, &curr_disc, 2000);

    var diff = try base.compare(testing.allocator, &curr);
    defer diff.deinit(testing.allocator);

    // CRITICAL INVARIANT: Incomplete observation must NEVER be reported as removed!
    try testing.expectEqual(@as(usize, 0), diff.removed_services_count);
    try testing.expectEqual(@as(usize, 1), diff.inconclusive_count);
    try testing.expectEqual(DiffCategory.inconclusive_state, diff.entries[0].category);
    try testing.expect(std.mem.indexOf(u8, diff.entries[0].reason, "cannot be claimed removed") != null);
}
