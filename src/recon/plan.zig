const std = @import("std");
const testing = std.testing;
const scope_mod = @import("scope.zig");
pub const ScopeCaps = scope_mod.ScopeCaps;
pub const ScopeError = scope_mod.ScopeError;
pub const NormalizedScope = scope_mod.NormalizedScope;
pub const normalizeScope = scope_mod.normalizeScope;
pub const explainScopeError = scope_mod.explainScopeError;
pub const isLoopbackTarget = scope_mod.isLoopbackTarget;

pub const LEGAL_DISCLAIMER: []const u8 =
    "WireScope cannot verify legal permission or ownership; operators bear sole legal responsibility for ensuring explicit written authorization before assessing remote targets.";

pub const CheckType = enum {
    dns_lookup,
    tcp_connect,
    tls_handshake,

    pub fn asString(self: CheckType) []const u8 {
        return switch (self) {
            .dns_lookup => "dns_lookup",
            .tcp_connect => "tcp_connect",
            .tls_handshake => "tls_handshake",
        };
    }
};

pub const PlannedTask = struct {
    sequence_id: usize,
    target: []const u8,
    port: ?u16 = null,
    check_type: CheckType,
    description: []const u8,
};

pub const AssessmentPlanConfig = struct {
    targets: []const []const u8,
    exclusions: []const []const u8 = &.{},
    ports: []const u16 = &.{},
    confirm_authorized: bool = false,
    caps: ScopeCaps = .{},
    include_dns: bool = true,
    include_tcp: bool = true,
};

pub const DnsScopeError = error{
    ResolvedTargetExcluded,
    ScopeExpansionPrevented,
};

pub const AssessmentPlan = struct {
    scope: NormalizedScope,
    tasks: []PlannedTask,
    total_operations: usize,
    is_loopback_only: bool,
    authorization_acknowledged: bool,
    legal_disclaimer: []const u8 = LEGAL_DISCLAIMER,
    caps: ScopeCaps,

    pub fn create(allocator: std.mem.Allocator, config: AssessmentPlanConfig) !AssessmentPlan {
        // 1. Normalize and validate scope according to policy and caps
        var norm_scope = try normalizeScope(
            allocator,
            config.targets,
            config.exclusions,
            config.ports,
            config.confirm_authorized,
            config.caps,
        );
        errdefer norm_scope.deinit(allocator);

        // 2. Generate deterministic planned task sequence
        var task_list = std.ArrayList(PlannedTask).init(allocator);
        errdefer {
            for (task_list.items) |t| {
                allocator.free(t.target);
                allocator.free(t.description);
            }
            task_list.deinit();
        }

        var seq: usize = 1;

        // If DNS is enabled, schedule DNS check for non-IP targets
        if (config.include_dns) {
            for (norm_scope.targets) |tgt| {
                // Check if target is not a pure IPv4
                if (scope_mod.parseIpv4Octets(tgt)) |_| {
                    // IP address does not require DNS lookup task
                } else |_| {
                    const desc = try std.fmt.allocPrint(allocator, "DNS resolution for '{s}'", .{tgt});
                    const tgt_dup = try allocator.dupe(u8, tgt);
                    try task_list.append(.{
                        .sequence_id = seq,
                        .target = tgt_dup,
                        .port = null,
                        .check_type = .dns_lookup,
                        .description = desc,
                    });
                    seq += 1;
                }
            }
        }

        // Schedule TCP / Service probe tasks
        if (config.include_tcp) {
            if (norm_scope.ports.len > 0) {
                for (norm_scope.targets) |tgt| {
                    for (norm_scope.ports) |p| {
                        const check_t: CheckType = if (p == 443) .tls_handshake else .tcp_connect;
                        const desc = try std.fmt.allocPrint(
                            allocator,
                            "{s} connect to {s}:{d}",
                            .{ if (p == 443) "TLS" else "TCP", tgt, p },
                        );
                        const tgt_dup = try allocator.dupe(u8, tgt);
                        try task_list.append(.{
                            .sequence_id = seq,
                            .target = tgt_dup,
                            .port = p,
                            .check_type = check_t,
                            .description = desc,
                        });
                        seq += 1;
                    }
                }
            } else {
                // If no ports specified, default to host discovery ping/check
                for (norm_scope.targets) |tgt| {
                    const desc = try std.fmt.allocPrint(allocator, "TCP connectivity check for '{s}' (default port 80)", .{tgt});
                    const tgt_dup = try allocator.dupe(u8, tgt);
                    try task_list.append(.{
                        .sequence_id = seq,
                        .target = tgt_dup,
                        .port = 80,
                        .check_type = .tcp_connect,
                        .description = desc,
                    });
                    seq += 1;
                }
            }
        }

        const total_ops = task_list.items.len;
        if (total_ops > config.caps.max_operations) {
            return error.ExcessiveOperationCount;
        }

        const tasks_slice = try task_list.toOwnedSlice();

        return AssessmentPlan{
            .scope = norm_scope,
            .tasks = tasks_slice,
            .total_operations = total_ops,
            .is_loopback_only = norm_scope.is_loopback_only,
            .authorization_acknowledged = norm_scope.authorization_acknowledged,
            .legal_disclaimer = LEGAL_DISCLAIMER,
            .caps = config.caps,
        };
    }

    pub fn deinit(self: *AssessmentPlan, allocator: std.mem.Allocator) void {
        self.scope.deinit(allocator);
        for (self.tasks) |t| {
            allocator.free(t.target);
            allocator.free(t.description);
        }
        if (self.tasks.len > 0) {
            allocator.free(self.tasks);
        }
    }

    /// Verifies that DNS-resolved IP addresses comply strictly with approved scope
    /// and do not bypass exclusions or expand loopback-confined scopes.
    pub fn verifyDnsScopeCompliance(self: *const AssessmentPlan, resolved_ips: []const []const u8) DnsScopeError!void {
        for (resolved_ips) |ip| {
            // 1. Exclusions check: any resolved IP matching an exclusion list entry is immediately blocked
            for (self.scope.exclusions) |ex| {
                if (std.ascii.eqlIgnoreCase(ex, ip)) {
                    return error.ResolvedTargetExcluded;
                }
            }

            // 2. Loopback-only scope check: if plan is restricted to loopback, resolved IPs must also be loopback
            if (self.is_loopback_only) {
                if (!isLoopbackTarget(ip)) {
                    return error.ScopeExpansionPrevented;
                }
            }
        }
    }

    /// Formats human-readable CLI terminal preview
    pub fn toTerminal(self: *const AssessmentPlan, writer: anytype) !void {
        try writer.print(
            \\WireScope Assessment Plan Preview
            \\==================================
            \\Scope Status:       {s}
            \\Loopback Confined:  {s}
            \\Authorization:      {s}
            \\Targets:            {d} host(s)
            \\Ports:              {d} port(s)
            \\Planned Operations: {d} total
            \\Safety Caps:        Max Hosts={d}, Max Ports={d}, Max Operations={d}
            \\
            \\
        , .{
            if (self.authorization_acknowledged) "Authorized" else "Pending Authorization",
            if (self.is_loopback_only) "Yes (local only)" else "No (remote targets present)",
            if (self.authorization_acknowledged) "Explicitly Acknowledged" else "Unacknowledged",
            self.scope.targets.len,
            self.scope.ports.len,
            self.total_operations,
            self.caps.max_hosts,
            self.caps.max_ports,
            self.caps.max_operations,
        });

        try writer.print("Approved Target Scope ({d}):\n", .{self.scope.targets.len});
        for (self.scope.targets, 0..) |t, idx| {
            if (idx < 20) {
                try writer.print("  - {s}\n", .{t});
            } else if (idx == 20) {
                try writer.print("  ... ({d} additional targets omitted from display)\n", .{self.scope.targets.len - 20});
                break;
            }
        }

        if (self.scope.exclusions.len > 0) {
            try writer.print("\nExclusions Applied ({d}):\n", .{self.scope.exclusions.len});
            for (self.scope.exclusions) |ex| {
                try writer.print("  - {s}\n", .{ex});
            }
        }

        if (self.scope.ports.len > 0) {
            try writer.print("\nPorts In Scope ({d}):\n  ", .{self.scope.ports.len});
            for (self.scope.ports, 0..) |p, idx| {
                if (idx > 0) try writer.print(", ", .{});
                try writer.print("{d}", .{p});
            }
            try writer.print("\n", .{});
        }

        try writer.print("\nPlanned Execution Tasks ({d} operations):\n", .{self.tasks.len});
        for (self.tasks, 0..) |task, idx| {
            if (idx < 25) {
                if (task.port) |p| {
                    try writer.print("  [{d:>3}] {s:<14} -> {s}:{d}\n", .{ task.sequence_id, task.check_type.asString(), task.target, p });
                } else {
                    try writer.print("  [{d:>3}] {s:<14} -> {s}\n", .{ task.sequence_id, task.check_type.asString(), task.target });
                }
            } else if (idx == 25) {
                try writer.print("  ... ({d} additional tasks omitted from display)\n", .{self.tasks.len - 25});
                break;
            }
        }

        try writer.print(
            \\
            \\[LEGAL DISCLAIMER]
            \\{s}
            \\
        , .{self.legal_disclaimer});
    }

    /// Formats machine-readable JSON preview
    pub fn toJson(self: *const AssessmentPlan, writer: anytype) !void {
        try writer.print(
            \\{{"type":"assessment_plan_preview","status":"{s}","is_loopback_only":{s},"authorization_acknowledged":{s},"legal_disclaimer":"{s}","caps":{{"max_hosts":{d},"max_ports":{d},"max_operations":{d}}},"summary":{{"target_count":{d},"port_count":{d},"total_operations":{d}}},"targets":[
        , .{
            if (self.authorization_acknowledged) "authorized" else "pending_authorization",
            if (self.is_loopback_only) "true" else "false",
            if (self.authorization_acknowledged) "true" else "false",
            self.legal_disclaimer,
            self.caps.max_hosts,
            self.caps.max_ports,
            self.caps.max_operations,
            self.scope.targets.len,
            self.scope.ports.len,
            self.total_operations,
        });

        for (self.scope.targets, 0..) |t, idx| {
            if (idx > 0) try writer.print(",", .{});
            try writer.print("\"{s}\"", .{t});
        }

        try writer.print("],\"exclusions\":[", .{});
        for (self.scope.exclusions, 0..) |ex, idx| {
            if (idx > 0) try writer.print(",", .{});
            try writer.print("\"{s}\"", .{ex});
        }

        try writer.print("],\"ports\":[", .{});
        for (self.scope.ports, 0..) |p, idx| {
            if (idx > 0) try writer.print(",", .{});
            try writer.print("{d}", .{p});
        }

        try writer.print("],\"tasks\":[", .{});
        for (self.tasks, 0..) |task, idx| {
            if (idx > 0) try writer.print(",", .{});
            try writer.print(
                \\{{"sequence_id":{d},"target":"{s}","port":
            , .{
                task.sequence_id,
                task.target,
            });
            if (task.port) |p| {
                try writer.print("{d}", .{p});
            } else {
                try writer.print("null", .{});
            }
            try writer.print(
                \\,"check_type":"{s}","description":"{s}"}}
            , .{
                task.check_type.asString(),
                task.description,
            });
        }
        try writer.print("]}}\n", .{});
    }
};

// -------------------------------------------------------------------------
// UNIT TESTS FOR ASSESSMENT PLAN PREVIEW & EQUIVALENCE
// -------------------------------------------------------------------------

test "plan: preview generates 1:1 matching planned tasks" {
    const targets = [_][]const u8{ "127.0.0.1", "localhost" };
    const ports = [_]u16{ 80, 443 };

    var plan = try AssessmentPlan.create(testing.allocator, .{
        .targets = &targets,
        .ports = &ports,
        .confirm_authorized = true,
        .include_dns = true,
        .include_tcp = true,
    });
    defer plan.deinit(testing.allocator);

    // localhost needs DNS (1 task)
    // 127.0.0.1 (IP) does not need DNS
    // 2 targets * 2 ports = 4 TCP/TLS tasks
    // Total operations = 1 + 4 = 5
    try testing.expectEqual(@as(usize, 5), plan.total_operations);
    try testing.expectEqual(plan.total_operations, plan.tasks.len);

    // Verify task details
    try testing.expectEqual(CheckType.dns_lookup, plan.tasks[0].check_type);
    try testing.expectEqualStrings("localhost", plan.tasks[0].target);

    // Terminal preview format
    var term_buf = std.ArrayList(u8).init(testing.allocator);
    defer term_buf.deinit();
    try plan.toTerminal(term_buf.writer());
    try testing.expect(std.mem.indexOf(u8, term_buf.items, "WireScope Assessment Plan Preview") != null);
    try testing.expect(std.mem.indexOf(u8, term_buf.items, LEGAL_DISCLAIMER) != null);

    // JSON preview format
    var json_buf = std.ArrayList(u8).init(testing.allocator);
    defer json_buf.deinit();
    try plan.toJson(json_buf.writer());
    try testing.expect(std.mem.indexOf(u8, json_buf.items, "\"type\":\"assessment_plan_preview\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_buf.items, "\"total_operations\":5") != null);
}

test "plan: dns resolution scope expansion prevention" {
    const targets = [_][]const u8{"localhost"};
    const exclusions = [_][]const u8{"192.168.1.100"};

    var plan = try AssessmentPlan.create(testing.allocator, .{
        .targets = &targets,
        .exclusions = &exclusions,
        .confirm_authorized = true,
    });
    defer plan.deinit(testing.allocator);

    // Permitted loopback resolution
    const good_ips = [_][]const u8{"127.0.0.1"};
    try plan.verifyDnsScopeCompliance(&good_ips);

    // Blocked: exclusion hit
    const excluded_ips = [_][]const u8{"192.168.1.100"};
    try testing.expectError(error.ResolvedTargetExcluded, plan.verifyDnsScopeCompliance(&excluded_ips));

    // Blocked: loopback-confined target resolving to remote public IP
    const escaped_ips = [_][]const u8{"8.8.8.8"};
    try testing.expectError(error.ScopeExpansionPrevented, plan.verifyDnsScopeCompliance(&escaped_ips));
}

test "plan: cap enforcement rejects oversized operations" {
    const targets = [_][]const u8{"127.0.0.1"};
    const ports = [_]u16{ 80, 81, 82 };

    // Max operations = 2, but we have 3 ports
    const result = AssessmentPlan.create(testing.allocator, .{
        .targets = &targets,
        .ports = &ports,
        .caps = .{ .max_operations = 2 },
    });
    try testing.expectError(error.ExcessiveOperationCount, result);
}
