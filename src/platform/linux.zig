const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const NetworkInterface = types.NetworkInterface;
const InterfaceStatus = types.InterfaceStatus;
const InterfaceEnumerationResult = types.InterfaceEnumerationResult;

const routes_mod = @import("routes.zig");
pub const RouteEntry = routes_mod.RouteEntry;
pub const RouteInspectionResult = routes_mod.RouteInspectionResult;

const listeners_mod = @import("listeners.zig");
pub const BindingType = listeners_mod.BindingType;
pub const ListenerEntry = listeners_mod.ListenerEntry;
pub const ListenerInspectionResult = listeners_mod.ListenerInspectionResult;

pub fn enumerateInterfacesLinux(allocator: std.mem.Allocator) !InterfaceEnumerationResult {
    var dir = std.fs.openDirAbsolute("/sys/class/net", .{ .iterate = true }) catch {
        // Fallback or permission limitation
        var list = std.ArrayList(NetworkInterface).init(allocator);
        return InterfaceEnumerationResult{ .interfaces = try list.toOwnedSlice() };
    };
    defer dir.close();

    var list = std.ArrayList(NetworkInterface).init(allocator);
    errdefer {
        for (list.items) |*i| i.deinit(allocator);
        list.deinit();
    }

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .sym_link and entry.kind != .directory) continue;

        const iface_name = try allocator.dupe(u8, entry.name);
        errdefer allocator.free(iface_name);

        const is_lo = std.mem.eql(u8, entry.name, "lo");

        // Read operstate if present
        var status: InterfaceStatus = .unknown;
        var operstate_path_buf: [128]u8 = undefined;
        const operstate_path = std.fmt.bufPrint(&operstate_path_buf, "{s}/operstate", .{entry.name}) catch null;
        var operstate_file = if (operstate_path) |p| dir.openFile(p, .{}) catch null else null;
        if (operstate_file) |*f| {
            defer f.close();
            var state_buf: [32]u8 = undefined;
            const len = f.readAll(&state_buf) catch 0;
            const state_str = std.mem.trim(u8, state_buf[0..len], " \r\n");
            if (std.mem.eql(u8, state_str, "up")) {
                status = .up;
            } else if (std.mem.eql(u8, state_str, "down")) {
                status = .down;
            }
        }

        var ipv4_list = std.ArrayList([]const u8).init(allocator);
        var ipv6_list = std.ArrayList([]const u8).init(allocator);

        if (is_lo) {
            try ipv4_list.append(try allocator.dupe(u8, "127.0.0.1"));
            try ipv6_list.append(try allocator.dupe(u8, "::1"));
            status = .up;
        }

        const iface = NetworkInterface{
            .name = iface_name,
            .adapter_id = try allocator.dupe(u8, iface_name),
            .display_name = try allocator.dupe(u8, iface_name),
            .status = status,
            .is_loopback = is_lo,
            .ipv4_addresses = try ipv4_list.toOwnedSlice(),
            .ipv6_addresses = try ipv6_list.toOwnedSlice(),
            .mac_address = null,
        };

        try list.append(iface);
    }

    return InterfaceEnumerationResult{ .interfaces = try list.toOwnedSlice() };
}

pub fn inspectRoutesLinux(allocator: std.mem.Allocator) !RouteInspectionResult {
    var file = std.fs.openFileAbsolute("/proc/net/route", .{}) catch {
        var list = std.ArrayList(RouteEntry).init(allocator);
        return RouteInspectionResult{ .routes = try list.toOwnedSlice() };
    };
    defer file.close();

    var buf: [4096]u8 = undefined;
    const len = file.readAll(&buf) catch 0;
    const content = buf[0..len];

    var list = std.ArrayList(RouteEntry).init(allocator);
    errdefer {
        for (list.items) |*r| r.deinit(allocator);
        list.deinit();
    }

    var default_gw: ?[]const u8 = null;
    errdefer if (default_gw) |gw| allocator.free(gw);

    var lines = std.mem.splitScalar(u8, content, '\n');
    _ = lines.next(); // Skip header line

    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \r\t");
        if (trimmed.len == 0) continue;

        var tokens = std.mem.tokenizeAny(u8, trimmed, " \t");
        _ = tokens.next(); // Iface
        const dest_hex = tokens.next() orelse continue;
        const gw_hex = tokens.next() orelse continue;
        _ = tokens.next(); // Flags
        _ = tokens.next(); // RefCnt
        _ = tokens.next(); // Use
        const metric_str = tokens.next() orelse "0";
        const mask_hex = tokens.next() orelse continue;

        const dest_val = std.fmt.parseInt(u32, dest_hex, 16) catch 0;
        const gw_val = std.fmt.parseInt(u32, gw_hex, 16) catch 0;
        const mask_val = std.fmt.parseInt(u32, mask_hex, 16) catch 0;
        const metric_val = std.fmt.parseInt(u32, metric_str, 10) catch 0;

        const dest_bytes: [4]u8 = @bitCast(dest_val);
        const gw_bytes: [4]u8 = @bitCast(gw_val);
        const prefix_len = @popCount(mask_val);

        const dest_str = try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}/{d}", .{
            dest_bytes[0], dest_bytes[1], dest_bytes[2], dest_bytes[3], prefix_len,
        });
        errdefer allocator.free(dest_str);

        const next_hop_str = if (gw_val == 0)
            try allocator.dupe(u8, "On-link")
        else
            try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{
                gw_bytes[0], gw_bytes[1], gw_bytes[2], gw_bytes[3],
            });
        errdefer allocator.free(next_hop_str);

        const is_default = (dest_val == 0 and mask_val == 0);
        if (is_default and default_gw == null and gw_val != 0) {
            default_gw = try allocator.dupe(u8, next_hop_str);
        }

        try list.append(.{
            .destination = dest_str,
            .next_hop = next_hop_str,
            .interface_index = 0,
            .metric = metric_val,
            .is_default_gateway = is_default,
            .protocol = try allocator.dupe(u8, "kernel"),
        });
    }

    return RouteInspectionResult{
        .routes = try list.toOwnedSlice(),
        .default_gateway = default_gw,
    };
}

pub fn inspectListenersLinux(allocator: std.mem.Allocator) !ListenerInspectionResult {
    var file = std.fs.openFileAbsolute("/proc/net/tcp", .{}) catch {
        var list = std.ArrayList(ListenerEntry).init(allocator);
        return ListenerInspectionResult{ .listeners = try list.toOwnedSlice() };
    };
    defer file.close();

    var buf: [16384]u8 = undefined;
    const len = file.readAll(&buf) catch 0;
    const content = buf[0..len];

    var list = std.ArrayList(ListenerEntry).init(allocator);
    errdefer {
        for (list.items) |*l| l.deinit(allocator);
        list.deinit();
    }

    var lines = std.mem.splitScalar(u8, content, '\n');
    _ = lines.next(); // Skip header line

    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \r\t");
        if (trimmed.len == 0) continue;

        var tokens = std.mem.tokenizeAny(u8, trimmed, " \t");
        _ = tokens.next(); // sl
        const local_addr_token = tokens.next() orelse continue; // 0100007F:1F90
        _ = tokens.next(); // rem_address
        const state_hex = tokens.next() orelse continue; // 0A = TCP_LISTEN

        if (!std.mem.eql(u8, state_hex, "0A")) continue;

        const colon_idx = std.mem.indexOfScalar(u8, local_addr_token, ':') orelse continue;
        const ip_hex = local_addr_token[0..colon_idx];
        const port_hex = local_addr_token[colon_idx + 1 ..];

        const ip_val = std.fmt.parseInt(u32, ip_hex, 16) catch continue;
        const port_val = std.fmt.parseInt(u16, port_hex, 16) catch continue;

        const ip_bytes: [4]u8 = @bitCast(ip_val);
        const addr_str = try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{
            ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
        });
        errdefer allocator.free(addr_str);

        const binding: BindingType = if (std.mem.eql(u8, addr_str, "0.0.0.0"))
            .wildcard
        else if (std.mem.eql(u8, addr_str, "127.0.0.1") or std.mem.startsWith(u8, addr_str, "127."))
            .loopback_only
        else
            .specific_interface;

        const proto_str = try allocator.dupe(u8, "tcp");
        errdefer allocator.free(proto_str);

        try list.append(.{
            .transport = proto_str,
            .local_address = addr_str,
            .local_port = port_val,
            .binding_type = binding,
            .pid = null,
            .process_name = null,
        });
    }

    return ListenerInspectionResult{
        .listeners = try list.toOwnedSlice(),
        .is_permission_limited = false,
    };
}

test "linux interface enumeration dummy check" {
    if (@import("builtin").os.tag != .linux) return;
    var res = try enumerateInterfacesLinux(testing.allocator);
    defer res.deinit(testing.allocator);
}
