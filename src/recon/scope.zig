const std = @import("std");
const testing = std.testing;

pub const ScopeError = error{
    EmptyTargets,
    EmptyTargetString,
    MalformedHostname,
    MalformedIpAddress,
    MalformedCidr,
    ExcessiveCidrRange,
    ExcessiveHostCount,
    ExcessivePortCount,
    ExcessiveOperationCount,
    MissingAuthorizationAcknowledgement,
    InvalidPortRange,
    InvalidPortSyntax,
    AllTargetsExcluded,
    OutOfMemory,
};

/// Operational safety caps bounding reconnaissance scope
pub const ScopeCaps = struct {
    max_hosts: usize = 256,
    max_ports: usize = 100,
    max_operations: usize = 5000,
    allow_broad_cidrs: bool = false, // Strictly false: cannot be bypassed implicitly!
};

/// Checks if target string represents loopback addresses
pub fn isLoopbackTarget(target: []const u8) bool {
    const trimmed = std.mem.trim(u8, target, " \t\r\n");
    if (std.ascii.eqlIgnoreCase(trimmed, "127.0.0.1") or
        std.ascii.eqlIgnoreCase(trimmed, "localhost") or
        std.ascii.eqlIgnoreCase(trimmed, "::1") or
        std.ascii.eqlIgnoreCase(trimmed, "[::1]"))
    {
        return true;
    }
    if (std.mem.startsWith(u8, trimmed, "127.")) return true;
    return false;
}

/// Normalizes and validates hostnames according to RFC 1123 / RFC 1035
pub fn normalizeHostname(allocator: std.mem.Allocator, raw: []const u8) ScopeError![]u8 {
    var trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return error.EmptyTargetString;

    // Strip trailing dot if present (FQDN root)
    if (std.mem.endsWith(u8, trimmed, ".")) {
        trimmed = trimmed[0 .. trimmed.len - 1];
    }
    if (trimmed.len == 0 or trimmed.len > 253) return error.MalformedHostname;

    var result = try allocator.alloc(u8, trimmed.len);
    errdefer allocator.free(result);

    var label_len: usize = 0;
    var i: usize = 0;
    while (i < trimmed.len) : (i += 1) {
        const c = trimmed[i];
        if (c == '.') {
            if (label_len == 0 or label_len > 63) return error.MalformedHostname;
            // Label cannot end with hyphen
            if (trimmed[i - 1] == '-') return error.MalformedHostname;
            result[i] = '.';
            label_len = 0;
        } else if ((c >= 'a' and c <= 'z') or (c >= '0' and c <= '9')) {
            result[i] = c;
            label_len += 1;
        } else if (c >= 'A' and c <= 'Z') {
            result[i] = c + ('a' - 'A'); // Lowercase normalization
            label_len += 1;
        } else if (c == '-') {
            // Label cannot start with hyphen
            if (label_len == 0) return error.MalformedHostname;
            result[i] = '-';
            label_len += 1;
        } else {
            return error.MalformedHostname;
        }
    }

    if (label_len == 0 or label_len > 63) return error.MalformedHostname;
    if (trimmed[trimmed.len - 1] == '-') return error.MalformedHostname;

    return result;
}

/// Parses IPv4 dotted-decimal octets with strict range validation
pub fn parseIpv4Octets(ip_str: []const u8) ScopeError![4]u8 {
    var octets: [4]u8 = undefined;
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, ip_str, '.');
    while (it.next()) |part| {
        if (count >= 4) return error.MalformedIpAddress;
        if (part.len == 0 or part.len > 3) return error.MalformedIpAddress;
        const val = std.fmt.parseInt(u16, part, 10) catch return error.MalformedIpAddress;
        if (val > 255) return error.MalformedIpAddress;
        octets[count] = @intCast(val);
        count += 1;
    }
    if (count != 4) return error.MalformedIpAddress;
    return octets;
}

pub fn ipv4ToU32(octets: [4]u8) u32 {
    return (@as(u32, octets[0]) << 24) |
        (@as(u32, octets[1]) << 16) |
        (@as(u32, octets[2]) << 8) |
        @as(u32, octets[3]);
}

pub fn u32ToIpv4(allocator: std.mem.Allocator, val: u32) ![]u8 {
    const o1: u8 = @intCast((val >> 24) & 0xFF);
    const o2: u8 = @intCast((val >> 16) & 0xFF);
    const o3: u8 = @intCast((val >> 8) & 0xFF);
    const o4: u8 = @intCast(val & 0xFF);
    return std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{ o1, o2, o3, o4 });
}

/// Normalizes IPv4 address into canonical dotted-decimal string without leading zeroes
pub fn normalizeIpv4(allocator: std.mem.Allocator, raw: []const u8) ScopeError![]u8 {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    const octets = try parseIpv4Octets(trimmed);
    return u32ToIpv4(allocator, ipv4ToU32(octets)) catch return error.MalformedIpAddress;
}

/// Checks if string is a CIDR notation (e.g. 192.168.1.0/24)
pub fn isCidr(raw: []const u8) bool {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    return std.mem.indexOfScalar(u8, trimmed, '/') != null;
}

/// Expands a bounded IPv4 CIDR into a list of normalized IP strings
pub fn expandCidr(allocator: std.mem.Allocator, raw_cidr: []const u8, allow_broad: bool) ScopeError![][]u8 {
    const trimmed = std.mem.trim(u8, raw_cidr, " \t\r\n");
    const slash_idx = std.mem.indexOfScalar(u8, trimmed, '/') orelse return error.MalformedCidr;
    const ip_part = trimmed[0..slash_idx];
    const prefix_str = trimmed[slash_idx + 1 ..];

    if (prefix_str.len == 0 or prefix_str.len > 2) return error.MalformedCidr;
    const prefix = std.fmt.parseInt(u8, prefix_str, 10) catch return error.MalformedCidr;

    if (prefix > 32) return error.MalformedCidr;

    // Safety Gate: Reject /0 through /23 unless explicitly authorized
    if (prefix < 24 and !allow_broad) {
        return error.ExcessiveCidrRange;
    }

    const octets = try parseIpv4Octets(ip_part);
    const base_ip = ipv4ToU32(octets);

    const host_bits = 32 - prefix;
    const host_count: u32 = @as(u32, 1) << @intCast(host_bits);

    // Apply netmask to ensure base_ip is aligned
    const mask: u32 = if (prefix == 0) 0 else ~((@as(u32, 1) << @intCast(host_bits)) - 1);
    const network_ip = base_ip & mask;

    var list = std.ArrayList([]u8).init(allocator);
    errdefer {
        for (list.items) |ip| allocator.free(ip);
        list.deinit();
    }

    var i: u32 = 0;
    while (i < host_count) : (i += 1) {
        const ip_str = u32ToIpv4(allocator, network_ip + i) catch return error.MalformedCidr;
        list.append(ip_str) catch return error.MalformedCidr;
    }

    return list.toOwnedSlice() catch return error.MalformedCidr;
}

/// Parses port specifications (e.g., "80,443", "80-85", "8080") into sorted, deduplicated u16 list
pub fn parsePortSpec(allocator: std.mem.Allocator, raw_ports: []const u8, max_ports: usize) ScopeError![]u16 {
    const trimmed = std.mem.trim(u8, raw_ports, " \t\r\n");
    if (trimmed.len == 0) return &.{};

    var list = std.ArrayList(u16).init(allocator);
    defer list.deinit();

    var comma_it = std.mem.splitScalar(u8, trimmed, ',');
    while (comma_it.next()) |item| {
        const token = std.mem.trim(u8, item, " \t\r\n");
        if (token.len == 0) continue;

        if (std.mem.indexOfScalar(u8, token, '-')) |dash_idx| {
            // Port range: "80-85"
            const start_str = std.mem.trim(u8, token[0..dash_idx], " ");
            const end_str = std.mem.trim(u8, token[dash_idx + 1 ..], " ");

            const p_start = std.fmt.parseInt(u32, start_str, 10) catch return error.InvalidPortSyntax;
            const p_end = std.fmt.parseInt(u32, end_str, 10) catch return error.InvalidPortSyntax;

            if (p_start == 0 or p_start > 65535 or p_end == 0 or p_end > 65535 or p_start > p_end) {
                return error.InvalidPortRange;
            }

            var p = p_start;
            while (p <= p_end) : (p += 1) {
                try list.append(@intCast(p));
            }
        } else {
            // Single port: "80"
            const p_num = std.fmt.parseInt(u32, token, 10) catch return error.InvalidPortSyntax;
            if (p_num == 0 or p_num > 65535) return error.InvalidPortRange;
            try list.append(@intCast(p_num));
        }
    }

    if (list.items.len == 0) return &.{};

    // Sort ascending
    std.mem.sort(u16, list.items, {}, comptime std.sort.asc(u16));

    // Deduplicate in-place
    var unique_len: usize = 0;
    for (list.items, 0..) |p, idx| {
        if (idx == 0 or p != list.items[idx - 1]) {
            list.items[unique_len] = p;
            unique_len += 1;
        }
    }
    list.shrinkRetainingCapacity(unique_len);

    if (list.items.len > max_ports) {
        return error.ExcessivePortCount;
    }

    return allocator.dupe(u16, list.items) catch return error.InvalidPortSyntax;
}

/// Cleaned, validated, and normalized reconnaissance scope
pub const NormalizedScope = struct {
    targets: [][]const u8,
    ports: []u16,
    exclusions: [][]const u8,
    is_loopback_only: bool,
    authorization_acknowledged: bool,

    pub fn deinit(self: *NormalizedScope, allocator: std.mem.Allocator) void {
        for (self.targets) |t| allocator.free(t);
        if (self.targets.len > 0) allocator.free(self.targets);
        if (self.ports.len > 0) allocator.free(self.ports);
        for (self.exclusions) |e| allocator.free(e);
        if (self.exclusions.len > 0) allocator.free(self.exclusions);
    }

    /// Checks if a given host is permitted in scope (respecting exclusions)
    pub fn isHostPermitted(self: *const NormalizedScope, host: []const u8) bool {
        // 1. Exclusions check
        for (self.exclusions) |ex| {
            if (std.ascii.eqlIgnoreCase(ex, host)) return false;
        }

        // 2. Targets check
        for (self.targets) |t| {
            if (std.ascii.eqlIgnoreCase(t, host)) return true;
        }

        return false;
    }

    /// Checks if a given host and port combination is permitted in scope
    pub fn isTargetPermitted(self: *const NormalizedScope, host: []const u8, port: ?u16) bool {
        if (!self.isHostPermitted(host)) return false;

        if (port) |p| {
            if (self.ports.len == 0) return true;
            for (self.ports) |planned_p| {
                if (planned_p == p) return true;
            }
            return false;
        }

        return true;
    }
};

/// Normalizes target inputs, resolves CIDRs, filters exclusions, and applies security caps
pub fn normalizeScope(
    allocator: std.mem.Allocator,
    raw_targets: []const []const u8,
    raw_exclusions: []const []const u8,
    raw_ports: []const u16,
    confirm_authorized: bool,
    caps: ScopeCaps,
) ScopeError!NormalizedScope {
    if (raw_targets.len == 0) return error.EmptyTargets;

    // 1. Normalize exclusions first
    var norm_exclusions = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (norm_exclusions.items) |e| allocator.free(e);
        norm_exclusions.deinit();
    }

    for (raw_exclusions) |raw_ex| {
        const trimmed = std.mem.trim(u8, raw_ex, " \t\r\n");
        if (trimmed.len == 0) continue;

        if (isCidr(trimmed)) {
            const expanded = try expandCidr(allocator, trimmed, caps.allow_broad_cidrs);
            defer allocator.free(expanded);
            for (expanded) |ip| {
                try norm_exclusions.append(ip);
            }
        } else if (parseIpv4Octets(trimmed)) |_| {
            const ip = try normalizeIpv4(allocator, trimmed);
            try norm_exclusions.append(ip);
        } else |_| {
            const host = try normalizeHostname(allocator, trimmed);
            try norm_exclusions.append(host);
        }
    }

    // 2. Expand and normalize targets
    var norm_targets = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (norm_targets.items) |t| allocator.free(t);
        norm_targets.deinit();
    }

    var all_loopback = true;

    for (raw_targets) |raw_t| {
        const trimmed = std.mem.trim(u8, raw_t, " \t\r\n");
        if (trimmed.len == 0) return error.EmptyTargetString;

        if (isCidr(trimmed)) {
            const expanded = try expandCidr(allocator, trimmed, caps.allow_broad_cidrs);
            defer allocator.free(expanded);

            for (expanded) |ip| {
                if (!isLoopbackTarget(ip)) all_loopback = false;

                // Check against exclusions
                var is_excluded = false;
                for (norm_exclusions.items) |ex| {
                    if (std.ascii.eqlIgnoreCase(ex, ip)) {
                        is_excluded = true;
                        break;
                    }
                }

                if (!is_excluded) {
                    try norm_targets.append(ip);
                } else {
                    allocator.free(ip);
                }
            }
        } else if (parseIpv4Octets(trimmed)) |_| {
            const ip = try normalizeIpv4(allocator, trimmed);
            if (!isLoopbackTarget(ip)) all_loopback = false;

            var is_excluded = false;
            for (norm_exclusions.items) |ex| {
                if (std.ascii.eqlIgnoreCase(ex, ip)) {
                    is_excluded = true;
                    break;
                }
            }

            if (!is_excluded) {
                try norm_targets.append(ip);
            } else {
                allocator.free(ip);
            }
        } else |_| {
            const host = try normalizeHostname(allocator, trimmed);
            if (!isLoopbackTarget(host)) all_loopback = false;

            var is_excluded = false;
            for (norm_exclusions.items) |ex| {
                if (std.ascii.eqlIgnoreCase(ex, host)) {
                    is_excluded = true;
                    break;
                }
            }

            if (!is_excluded) {
                try norm_targets.append(host);
            } else {
                allocator.free(host);
            }
        }
    }

    if (norm_targets.items.len == 0) {
        return error.AllTargetsExcluded;
    }

    // 3. Deduplicate targets
    std.mem.sort([]const u8, norm_targets.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);

    var unique_count: usize = 0;
    for (norm_targets.items, 0..) |t, idx| {
        if (idx == 0 or !std.mem.eql(u8, t, norm_targets.items[idx - 1])) {
            norm_targets.items[unique_count] = t;
            unique_count += 1;
        } else {
            allocator.free(t);
        }
    }
    norm_targets.shrinkRetainingCapacity(unique_count);

    // 4. Validate Host Cap
    if (norm_targets.items.len > caps.max_hosts) {
        return error.ExcessiveHostCount;
    }

    // 5. Validate Ports
    var norm_ports = std.ArrayList(u16).init(allocator);
    errdefer norm_ports.deinit();
    for (raw_ports) |p| {
        if (p == 0) return error.InvalidPortRange;
        try norm_ports.append(p);
    }

    // Deduplicate ports
    if (norm_ports.items.len > 0) {
        std.mem.sort(u16, norm_ports.items, {}, comptime std.sort.asc(u16));
        var p_unique: usize = 0;
        for (norm_ports.items, 0..) |p, idx| {
            if (idx == 0 or p != norm_ports.items[idx - 1]) {
                norm_ports.items[p_unique] = p;
                p_unique += 1;
            }
        }
        norm_ports.shrinkRetainingCapacity(p_unique);
    }

    if (norm_ports.items.len > caps.max_ports) {
        return error.ExcessivePortCount;
    }

    // 6. Validate Total Operations Cap
    const port_multiplier = if (norm_ports.items.len == 0) 1 else norm_ports.items.len;
    const total_planned_ops = norm_targets.items.len * port_multiplier;
    if (total_planned_ops > caps.max_operations) {
        return error.ExcessiveOperationCount;
    }

    // 7. Enforce Authorization Acknowledgement for remote targets
    if (!all_loopback and !confirm_authorized) {
        return error.MissingAuthorizationAcknowledgement;
    }

    return NormalizedScope{
        .targets = try norm_targets.toOwnedSlice(),
        .ports = try norm_ports.toOwnedSlice(),
        .exclusions = try norm_exclusions.toOwnedSlice(),
        .is_loopback_only = all_loopback,
        .authorization_acknowledged = (all_loopback or confirm_authorized),
    };
}

/// Provides clear, actionable, safety-related error explanations
pub fn explainScopeError(err: ScopeError, context: ?[]const u8, buf: []u8) []const u8 {
    return switch (err) {
        error.EmptyTargets => "Target scope is empty. Provide at least one target host, IP, or CIDR range.",
        error.EmptyTargetString => "Target specification contains an empty or whitespace-only entry.",
        error.MalformedHostname => if (context) |c|
            std.fmt.bufPrint(buf, "Target '{s}' is not a valid hostname (RFC 1123 label 1-63 chars, alphanumeric/hyphens).", .{c}) catch "Malformed hostname"
        else
            "Target contains a malformed hostname.",
        error.MalformedIpAddress => if (context) |c|
            std.fmt.bufPrint(buf, "Target '{s}' is not a valid IPv4 address (dotted-decimal octets 0-255).", .{c}) catch "Malformed IP address"
        else
            "Target contains a malformed IP address.",
        error.MalformedCidr => if (context) |c|
            std.fmt.bufPrint(buf, "CIDR '{s}' is malformed. Expected format is 'IP/prefix' (e.g. 192.168.1.0/24).", .{c}) catch "Malformed CIDR"
        else
            "Target contains a malformed CIDR.",
        error.ExcessiveCidrRange => if (context) |c|
            std.fmt.bufPrint(buf, "CIDR '{s}' rejected: broad CIDRs (< /24) are prohibited to prevent unbounded scanning. Allowed prefix range is /24 to /32.", .{c}) catch "Excessive CIDR range"
        else
            "CIDR range is too broad (/24 to /32 allowed).",
        error.ExcessiveHostCount => if (context) |c|
            std.fmt.bufPrint(buf, "Target scope exceeds maximum host cap ({s} hosts). Reduce target scope or adjust --max-hosts.", .{c}) catch "Excessive host count"
        else
            "Target scope exceeds maximum host cap.",
        error.ExcessivePortCount => if (context) |c|
            std.fmt.bufPrint(buf, "Port list exceeds maximum port cap ({s} ports). Reduce port count or adjust --max-ports.", .{c}) catch "Excessive port count"
        else
            "Port list exceeds maximum port cap.",
        error.ExcessiveOperationCount => if (context) |c|
            std.fmt.bufPrint(buf, "Assessment plan exceeds total operations cap ({s} ops). Reduce targets, ports, or checks.", .{c}) catch "Excessive operation count"
        else
            "Assessment plan exceeds total operations cap.",
        error.MissingAuthorizationAcknowledgement => "Remote target scope requires explicit authorization acknowledgement (--confirm-authorized or profile authorization_acknowledged=true). NOTE: WireScope cannot verify legal permission or ownership; operators are solely responsible for ensuring explicit authorization.",
        error.InvalidPortRange => "Port number out of range. Valid range is 1 to 65535.",
        error.InvalidPortSyntax => "Invalid port syntax. Expected numeric port, comma-separated list, or range (e.g. '80,443' or '80-85').",
        error.AllTargetsExcluded => "All targets were eliminated by the exclusion list. No active targets remain in scope.",
        error.OutOfMemory => "Insufficient memory to complete scope normalization.",
    };
}

// -------------------------------------------------------------------------
// UNIT TESTS FOR SCOPE VALIDATION AND CAPS
// -------------------------------------------------------------------------

test "scope: loopback detection" {
    try testing.expect(isLoopbackTarget("127.0.0.1"));
    try testing.expect(isLoopbackTarget("127.0.0.2"));
    try testing.expect(isLoopbackTarget("localhost"));
    try testing.expect(isLoopbackTarget("::1"));
    try testing.expect(isLoopbackTarget("[::1]"));
    try testing.expect(!isLoopbackTarget("192.168.1.1"));
    try testing.expect(!isLoopbackTarget("example.com"));
}

test "scope: hostname normalization and rejection" {
    const valid = try normalizeHostname(testing.allocator, "  EXAMPLE.COM. ");
    defer testing.allocator.free(valid);
    try testing.expectEqualStrings("example.com", valid);

    try testing.expectError(error.MalformedHostname, normalizeHostname(testing.allocator, "-invalid.com"));
    try testing.expectError(error.MalformedHostname, normalizeHostname(testing.allocator, "invalid-.com"));
    try testing.expectError(error.MalformedHostname, normalizeHostname(testing.allocator, "inv@lid.com"));
}

test "scope: ipv4 normalization" {
    const ip = try normalizeIpv4(testing.allocator, "192.168.001.005");
    defer testing.allocator.free(ip);
    try testing.expectEqualStrings("192.168.1.5", ip);

    try testing.expectError(error.MalformedIpAddress, normalizeIpv4(testing.allocator, "256.1.1.1"));
    try testing.expectError(error.MalformedIpAddress, normalizeIpv4(testing.allocator, "1.2.3"));
}

test "scope: cidr expansion and broad cidr rejection" {
    // /30 expansion = 4 IPs
    const ips = try expandCidr(testing.allocator, "192.168.1.0/30", false);
    defer {
        for (ips) |ip| testing.allocator.free(ip);
        testing.allocator.free(ips);
    }
    try testing.expectEqual(@as(usize, 4), ips.len);
    try testing.expectEqualStrings("192.168.1.0", ips[0]);
    try testing.expectEqualStrings("192.168.1.3", ips[3]);

    // Broad CIDRs (< /24) rejected by safety gate
    try testing.expectError(error.ExcessiveCidrRange, expandCidr(testing.allocator, "10.0.0.0/16", false));
    try testing.expectError(error.ExcessiveCidrRange, expandCidr(testing.allocator, "0.0.0.0/0", false));
}

test "scope: port specification parsing, deduplication, and ranges" {
    const ports = try parsePortSpec(testing.allocator, "443, 80, 80-82, 443", 10);
    defer testing.allocator.free(ports);

    try testing.expectEqual(@as(usize, 4), ports.len);
    try testing.expectEqual(@as(u16, 80), ports[0]);
    try testing.expectEqual(@as(u16, 81), ports[1]);
    try testing.expectEqual(@as(u16, 82), ports[2]);
    try testing.expectEqual(@as(u16, 443), ports[3]);

    // Port cap rejection
    try testing.expectError(error.ExcessivePortCount, parsePortSpec(testing.allocator, "1-100", 50));
}

test "scope: full normalization with exclusions and caps" {
    const raw_targets = [_][]const u8{ "127.0.0.1", "127.0.0.2", "127.0.0.3" };
    const raw_exclusions = [_][]const u8{"127.0.0.2"};
    const raw_ports = [_]u16{ 80, 443 };

    var scope = try normalizeScope(
        testing.allocator,
        &raw_targets,
        &raw_exclusions,
        &raw_ports,
        true,
        .{},
    );
    defer scope.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 2), scope.targets.len);
    try testing.expectEqualStrings("127.0.0.1", scope.targets[0]);
    try testing.expectEqualStrings("127.0.0.3", scope.targets[1]);
    try testing.expect(scope.isHostPermitted("127.0.0.1"));
    try testing.expect(!scope.isHostPermitted("127.0.0.2")); // Excluded!
}

test "scope: remote target requires authorization acknowledgement" {
    const remote = [_][]const u8{"192.168.1.10"};
    const ports = [_]u16{80};

    // Missing authorization rejected
    try testing.expectError(
        error.MissingAuthorizationAcknowledgement,
        normalizeScope(testing.allocator, &remote, &.{}, &ports, false, .{}),
    );

    // Confirmed authorization accepted
    var scope = try normalizeScope(testing.allocator, &remote, &.{}, &ports, true, .{});
    defer scope.deinit(testing.allocator);
    try testing.expect(scope.authorization_acknowledged);
    try testing.expect(!scope.is_loopback_only);
}

test "scope: safety error messages" {
    var buf: [256]u8 = undefined;
    const msg = explainScopeError(error.ExcessiveCidrRange, "10.0.0.0/16", &buf);
    try testing.expect(std.mem.indexOf(u8, msg, "/24 to /32") != null);
}
