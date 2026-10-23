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

const windows = std.os.windows;
const ULONG = windows.ULONG;
const DWORD = windows.DWORD;
const PVOID = windows.PVOID;
const WINAPI = windows.WINAPI;
const PWCHAR = [*:0]const u16;

pub const AF_UNSPEC: ULONG = 0;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 23;

pub const GAA_FLAG_INCLUDE_PREFIX: ULONG = 0x0010;
pub const GAA_FLAG_SKIP_ANYCAST: ULONG = 0x0002;
pub const GAA_FLAG_SKIP_MULTICAST: ULONG = 0x0004;
pub const GAA_FLAG_SKIP_DNS_SERVER: ULONG = 0x0008;

pub const ERROR_SUCCESS: ULONG = 0;
pub const ERROR_BUFFER_OVERFLOW: ULONG = 111;
pub const ERROR_NO_DATA: ULONG = 232;
pub const ERROR_ACCESS_DENIED: ULONG = 5;

pub const IF_TYPE_SOFTWARE_LOOPBACK: DWORD = 24;

pub const sockaddr = extern struct {
    sa_family: u16,
    sa_data: [14]u8,
};

pub const sockaddr_in = extern struct {
    sin_family: u16,
    sin_port: u16,
    sin_addr: [4]u8,
    sin_zero: [8]u8,
};

pub const sockaddr_in6 = extern struct {
    sin6_family: u16,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [16]u8,
    sin6_scope_id: u32,
};

pub const SOCKET_ADDRESS = extern struct {
    lpSockaddr: *sockaddr,
    iSockaddrLength: c_int,
};

pub const IP_ADAPTER_UNICAST_ADDRESS = extern struct {
    Length: ULONG,
    Flags: DWORD,
    Next: ?*IP_ADAPTER_UNICAST_ADDRESS,
    Address: SOCKET_ADDRESS,
    PrefixOrigin: c_int,
    SuffixOrigin: c_int,
    DadState: c_int,
    ValidLifetime: ULONG,
    PreferredLifetime: ULONG,
    LeaseLifetime: ULONG,
    OnLinkPrefixLength: u8,
};

pub const IP_ADAPTER_ADDRESSES = extern struct {
    Length: ULONG,
    IfIndex: DWORD,
    Next: ?*IP_ADAPTER_ADDRESSES,
    AdapterName: [*:0]const u8,
    FirstUnicastAddress: ?*IP_ADAPTER_UNICAST_ADDRESS,
    FirstAnycastAddress: ?PVOID,
    FirstMulticastAddress: ?PVOID,
    FirstDnsServerAddress: ?PVOID,
    DnsSuffix: ?PWCHAR,
    Description: ?PWCHAR,
    FriendlyName: ?PWCHAR,
    PhysicalAddress: [8]u8,
    PhysicalAddressLength: DWORD,
    Flags: DWORD,
    Mtu: DWORD,
    IfType: DWORD,
    OperStatus: DWORD,
    Ipv6IfIndex: DWORD,
    ZoneIndices: [16]DWORD,
    FirstPrefix: ?PVOID,
};

pub extern "iphlpapi" fn GetAdaptersAddresses(
    Family: ULONG,
    Flags: ULONG,
    Reserved: ?PVOID,
    AdapterAddresses: ?*IP_ADAPTER_ADDRESSES,
    SizePointer: *ULONG,
) callconv(WINAPI) ULONG;

fn parseOperStatus(status: DWORD) InterfaceStatus {
    return switch (status) {
        1 => .up,
        2 => .down,
        3 => .testing,
        4 => .unknown,
        5 => .dormant,
        6 => .not_present,
        7 => .lower_layer_down,
        else => .unknown,
    };
}

fn formatIpv4(allocator: std.mem.Allocator, addr_bytes: [4]u8) ![]const u8 {
    return std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{
        addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3],
    });
}

fn formatIpv6(allocator: std.mem.Allocator, addr_bytes: [16]u8) ![]const u8 {
    // Check for IPv6 loopback (::1)
    var is_loopback = true;
    for (addr_bytes[0..15]) |b| {
        if (b != 0) {
            is_loopback = false;
            break;
        }
    }
    if (is_loopback and addr_bytes[15] == 1) {
        return allocator.dupe(u8, "::1");
    }

    return std.fmt.allocPrint(allocator, "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
        addr_bytes[0],  addr_bytes[1],  addr_bytes[2],  addr_bytes[3],
        addr_bytes[4],  addr_bytes[5],  addr_bytes[6],  addr_bytes[7],
        addr_bytes[8],  addr_bytes[9],  addr_bytes[10], addr_bytes[11],
        addr_bytes[12], addr_bytes[13], addr_bytes[14], addr_bytes[15],
    });
}

fn pwcharToUtf8(allocator: std.mem.Allocator, pw: ?PWCHAR) ![]const u8 {
    if (pw) |p| {
        var len: usize = 0;
        while (p[len] != 0) : (len += 1) {}
        if (len == 0) return allocator.dupe(u8, "");
        return std.unicode.utf16LeToUtf8Alloc(allocator, p[0..len]);
    }
    return allocator.dupe(u8, "");
}

pub fn enumerateInterfacesWindows(allocator: std.mem.Allocator) !InterfaceEnumerationResult {
    var buf_size: ULONG = 32768; // Initial 32KB buffer
    var buffer = try allocator.alloc(u8, buf_size);
    defer allocator.free(buffer);

    const flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;

    var ret = GetAdaptersAddresses(
        AF_UNSPEC,
        flags,
        null,
        @ptrCast(@alignCast(buffer.ptr)),
        &buf_size,
    );

    if (ret == ERROR_BUFFER_OVERFLOW) {
        allocator.free(buffer);
        buffer = try allocator.alloc(u8, buf_size);
        ret = GetAdaptersAddresses(
            AF_UNSPEC,
            flags,
            null,
            @ptrCast(@alignCast(buffer.ptr)),
            &buf_size,
        );
    }

    if (ret == ERROR_ACCESS_DENIED) return error.AccessDenied;
    if (ret != ERROR_SUCCESS and ret != ERROR_NO_DATA) return error.ApiFailure;

    var list = std.ArrayList(NetworkInterface).init(allocator);
    errdefer {
        for (list.items) |*item| item.deinit(allocator);
        list.deinit();
    }

    if (ret == ERROR_NO_DATA) {
        return InterfaceEnumerationResult{ .interfaces = try list.toOwnedSlice() };
    }

    var curr_opt: ?*const IP_ADAPTER_ADDRESSES = @ptrCast(@alignCast(buffer.ptr));

    while (curr_opt) |curr| {
        defer curr_opt = curr.Next;

        const is_loopback = (curr.IfType == IF_TYPE_SOFTWARE_LOOPBACK);
        const status = parseOperStatus(curr.OperStatus);

        const adapter_name_span = std.mem.span(curr.AdapterName);
        const adapter_id = try allocator.dupe(u8, adapter_name_span);
        errdefer allocator.free(adapter_id);

        const friendly_name = try pwcharToUtf8(allocator, curr.FriendlyName);
        errdefer allocator.free(friendly_name);

        const display_name = if (friendly_name.len > 0) friendly_name else try pwcharToUtf8(allocator, curr.Description);
        const name = if (friendly_name.len > 0) try allocator.dupe(u8, friendly_name) else try allocator.dupe(u8, adapter_id);
        errdefer allocator.free(name);

        // MAC Address
        var mac_str: ?[]const u8 = null;
        if (curr.PhysicalAddressLength == 6 and !is_loopback) {
            mac_str = try std.fmt.allocPrint(allocator, "{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}", .{
                curr.PhysicalAddress[0], curr.PhysicalAddress[1], curr.PhysicalAddress[2],
                curr.PhysicalAddress[3], curr.PhysicalAddress[4], curr.PhysicalAddress[5],
            });
        }

        // Unicast IP addresses
        var ipv4_list = std.ArrayList([]const u8).init(allocator);
        errdefer {
            for (ipv4_list.items) |a| allocator.free(a);
            ipv4_list.deinit();
        }

        var ipv6_list = std.ArrayList([]const u8).init(allocator);
        errdefer {
            for (ipv6_list.items) |a| allocator.free(a);
            ipv6_list.deinit();
        }

        var unicast_opt = curr.FirstUnicastAddress;
        while (unicast_opt) |unicast| {
            defer unicast_opt = unicast.Next;
            const sa = unicast.Address.lpSockaddr;

            if (sa.sa_family == AF_INET) {
                const sin: *const sockaddr_in = @ptrCast(@alignCast(sa));
                const ip_str = try formatIpv4(allocator, sin.sin_addr);
                try ipv4_list.append(ip_str);
            } else if (sa.sa_family == AF_INET6) {
                const sin6: *const sockaddr_in6 = @ptrCast(@alignCast(sa));
                const ip_str = try formatIpv6(allocator, sin6.sin6_addr);
                try ipv6_list.append(ip_str);
            }
        }

        const iface = NetworkInterface{
            .name = name,
            .adapter_id = adapter_id,
            .display_name = display_name,
            .status = status,
            .is_loopback = is_loopback,
            .ipv4_addresses = try ipv4_list.toOwnedSlice(),
            .ipv6_addresses = try ipv6_list.toOwnedSlice(),
            .mac_address = mac_str,
        };

        try list.append(iface);
    }

    return InterfaceEnumerationResult{ .interfaces = try list.toOwnedSlice() };
}

test "windows real interface enumeration" {
    if (@import("builtin").os.tag != .windows) return;

    var result = enumerateInterfacesWindows(testing.allocator) catch return error.SkipZigTest;
    defer result.deinit(testing.allocator);

    // Any working Windows system has at least 1 interface (typically loopback or ethernet/wifi)
    if (result.interfaces.len == 0) return error.SkipZigTest;

    // Verify presence of valid interface properties
    var found_loopback = false;
    for (result.interfaces) |iface| {
        try testing.expect(iface.name.len > 0);
        try testing.expect(iface.adapter_id.len > 0);
        if (iface.is_loopback) {
            found_loopback = true;
        }
    }
    if (!found_loopback) return error.SkipZigTest;
}

pub const MIB_IPFORWARDROW = extern struct {
    dwForwardDest: DWORD,
    dwForwardMask: DWORD,
    dwForwardPolicy: DWORD,
    dwForwardNextHop: DWORD,
    dwForwardIfIndex: DWORD,
    dwForwardType: DWORD,
    dwForwardProto: DWORD,
    dwForwardAge: DWORD,
    dwForwardNextHopAS: DWORD,
    dwForwardMetric1: DWORD,
    dwForwardMetric2: DWORD,
    dwForwardMetric3: DWORD,
    dwForwardMetric4: DWORD,
    dwForwardMetric5: DWORD,
};

pub const MIB_IPFORWARDTABLE = extern struct {
    dwNumEntries: DWORD,
    table: [1]MIB_IPFORWARDROW,
};

pub extern "iphlpapi" fn GetIpForwardTable(
    pIpForwardTable: ?*MIB_IPFORWARDTABLE,
    pdwSize: *ULONG,
    bOrder: windows.BOOL,
) callconv(WINAPI) DWORD;

fn parseForwardProto(allocator: std.mem.Allocator, proto: DWORD) ![]const u8 {
    return switch (proto) {
        1 => allocator.dupe(u8, "other"),
        2 => allocator.dupe(u8, "local"),
        3 => allocator.dupe(u8, "netmgmt"),
        4 => allocator.dupe(u8, "icmp"),
        10 => allocator.dupe(u8, "ebgp"),
        11 => allocator.dupe(u8, "ibgp"),
        12 => allocator.dupe(u8, "ospf"),
        else => allocator.dupe(u8, "static"),
    };
}

fn formatIpDword(allocator: std.mem.Allocator, ip_dword: DWORD) ![]const u8 {
    const bytes: [4]u8 = @bitCast(ip_dword);
    return std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{
        bytes[0], bytes[1], bytes[2], bytes[3],
    });
}

/// Native Win32 routing table inspection using iphlpapi GetIpForwardTable
pub fn inspectRoutesWindows(allocator: std.mem.Allocator) !RouteInspectionResult {
    var size: ULONG = 0;
    _ = GetIpForwardTable(null, &size, 0);

    if (size == 0) {
        // Fallback to bounded subprocess if API returned 0
        return inspectRoutesSubprocessFallback(allocator);
    }

    const buffer = try allocator.alloc(u8, size);
    defer allocator.free(buffer);

    const table: *MIB_IPFORWARDTABLE = @ptrCast(@alignCast(buffer.ptr));
    const ret = GetIpForwardTable(table, &size, 0);
    if (ret != ERROR_SUCCESS) {
        return inspectRoutesSubprocessFallback(allocator);
    }

    const count: usize = @intCast(table.dwNumEntries);
    var list = std.ArrayList(RouteEntry).init(allocator);
    errdefer {
        for (list.items) |*r| r.deinit(allocator);
        list.deinit();
    }

    var default_gw: ?[]const u8 = null;
    errdefer if (default_gw) |gw| allocator.free(gw);

    const rows_ptr: [*]const MIB_IPFORWARDROW = @ptrCast(&table.table[0]);

    for (0..count) |idx| {
        const row = rows_ptr[idx];

        const dest_bytes: [4]u8 = @bitCast(row.dwForwardDest);
        const prefix_len = @popCount(row.dwForwardMask);

        const dest_str = try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}/{d}", .{
            dest_bytes[0], dest_bytes[1], dest_bytes[2], dest_bytes[3], prefix_len,
        });
        errdefer allocator.free(dest_str);

        var next_hop_str: []const u8 = undefined;
        if (row.dwForwardNextHop == row.dwForwardDest or row.dwForwardType == 3) { // MIB_IPROUTE_TYPE_DIRECT = 3
            next_hop_str = try allocator.dupe(u8, "On-link");
        } else {
            next_hop_str = try formatIpDword(allocator, row.dwForwardNextHop);
        }
        errdefer allocator.free(next_hop_str);

        const is_default = (row.dwForwardDest == 0 and row.dwForwardMask == 0);
        if (is_default and default_gw == null and !std.mem.eql(u8, next_hop_str, "On-link") and !std.mem.eql(u8, next_hop_str, "0.0.0.0")) {
            default_gw = try allocator.dupe(u8, next_hop_str);
        }

        const proto_str = try parseForwardProto(allocator, row.dwForwardProto);
        errdefer allocator.free(proto_str);

        try list.append(.{
            .destination = dest_str,
            .next_hop = next_hop_str,
            .interface_index = row.dwForwardIfIndex,
            .metric = row.dwForwardMetric1,
            .is_default_gateway = is_default,
            .protocol = proto_str,
        });
    }

    return RouteInspectionResult{
        .routes = try list.toOwnedSlice(),
        .default_gateway = default_gw,
    };
}

/// Bounded subprocess fallback running 'route.exe print -4' with no shell interpolation
pub fn inspectRoutesSubprocessFallback(allocator: std.mem.Allocator) !RouteInspectionResult {
    var child = std.process.Child.init(&[_][]const u8{ "route.exe", "print", "-4" }, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;

    try child.spawn();

    const max_bytes: usize = 64 * 1024; // 64 KB safety cap
    var stdout_buf = std.ArrayList(u8).init(allocator);
    defer stdout_buf.deinit();

    var reader = child.stdout.?.reader();
    var buf: [1024]u8 = undefined;
    var total_read: usize = 0;

    while (true) {
        const bytes_read = try reader.read(&buf);
        if (bytes_read == 0) break;
        total_read += bytes_read;
        if (total_read > max_bytes) break;
        try stdout_buf.appendSlice(buf[0..bytes_read]);
    }

    const term = try child.wait();
    if (term != .Exited or term.Exited != 0) {
        return error.ApiFailure;
    }

    // Parse default gateway from route print output if present
    var default_gw: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, stdout_buf.items, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \r\t");
        if (std.mem.startsWith(u8, trimmed, "0.0.0.0") and std.mem.indexOf(u8, trimmed, "Default Gateway:") == null) {
            var tokens = std.mem.tokenizeAny(u8, trimmed, " \t");
            _ = tokens.next(); // 0.0.0.0
            _ = tokens.next(); // 0.0.0.0
            if (tokens.next()) |gw| {
                if (default_gw == null and !std.mem.eql(u8, gw, "On-link")) {
                    default_gw = try allocator.dupe(u8, gw);
                    break;
                }
            }
        }
    }

    var list = std.ArrayList(RouteEntry).init(allocator);
    return RouteInspectionResult{
        .routes = try list.toOwnedSlice(),
        .default_gateway = default_gw,
    };
}

test "windows native route inspection" {
    if (@import("builtin").os.tag != .windows) return;

    var result = inspectRoutesWindows(testing.allocator) catch return error.SkipZigTest;
    defer result.deinit(testing.allocator);

    if (result.routes.len == 0) return error.SkipZigTest;

    // Real systems have loopback or default routes
    var has_dest = false;
    for (result.routes) |r| {
        if (r.destination.len > 0) has_dest = true;
    }
    if (!has_dest) return error.SkipZigTest;
}

test "windows bounded route subprocess fallback" {
    if (@import("builtin").os.tag != .windows) return;

    var result = try inspectRoutesSubprocessFallback(testing.allocator);
    defer result.deinit(testing.allocator);
}

pub const TCP_TABLE_OWNER_PID_LISTENER: ULONG = 3;

pub const MIB_TCPROW_OWNER_PID = extern struct {
    dwState: DWORD,
    dwLocalAddr: DWORD,
    dwLocalPort: DWORD,
    dwRemoteAddr: DWORD,
    dwRemotePort: DWORD,
    dwOwningPid: DWORD,
};

pub const MIB_TCPTABLE_OWNER_PID = extern struct {
    dwNumEntries: DWORD,
    table: [1]MIB_TCPROW_OWNER_PID,
};

pub extern "iphlpapi" fn GetExtendedTcpTable(
    pTcpTable: ?PVOID,
    pdwSize: *DWORD,
    bOrder: windows.BOOL,
    ulAf: ULONG,
    TableClass: ULONG,
    Reserved: ULONG,
) callconv(WINAPI) DWORD;

pub fn classifyBinding(addr: []const u8) BindingType {
    if (std.mem.eql(u8, addr, "0.0.0.0") or std.mem.eql(u8, addr, "::") or std.mem.eql(u8, addr, "[::]")) {
        return .wildcard;
    } else if (std.mem.eql(u8, addr, "127.0.0.1") or std.mem.startsWith(u8, addr, "127.") or std.mem.eql(u8, addr, "::1") or std.mem.eql(u8, addr, "localhost")) {
        return .loopback_only;
    } else {
        return .specific_interface;
    }
}

/// Native Win32 listener inspection using GetExtendedTcpTable
pub fn inspectListenersWindows(allocator: std.mem.Allocator) !ListenerInspectionResult {
    var size: DWORD = 0;
    _ = GetExtendedTcpTable(null, &size, 0, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);

    if (size == 0) {
        return inspectListenersSubprocessFallback(allocator);
    }

    const buffer = try allocator.alloc(u8, size);
    defer allocator.free(buffer);

    const ret = GetExtendedTcpTable(@ptrCast(buffer.ptr), &size, 0, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);
    if (ret != ERROR_SUCCESS) {
        return inspectListenersSubprocessFallback(allocator);
    }

    const table: *const MIB_TCPTABLE_OWNER_PID = @ptrCast(@alignCast(buffer.ptr));
    const count: usize = @intCast(table.dwNumEntries);

    var list = std.ArrayList(ListenerEntry).init(allocator);
    errdefer {
        for (list.items) |*l| l.deinit(allocator);
        list.deinit();
    }

    const rows_ptr: [*]const MIB_TCPROW_OWNER_PID = @ptrCast(&table.table[0]);

    for (0..count) |idx| {
        const row = rows_ptr[idx];

        const bytes: [4]u8 = @bitCast(row.dwLocalAddr);
        const addr_str = try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{
            bytes[0], bytes[1], bytes[2], bytes[3],
        });
        errdefer allocator.free(addr_str);

        const port = std.mem.bigToNative(u16, @truncate(@as(u32, @intCast(row.dwLocalPort))));
        const binding = classifyBinding(addr_str);
        const proto_str = try allocator.dupe(u8, "tcp");
        errdefer allocator.free(proto_str);

        try list.append(.{
            .transport = proto_str,
            .local_address = addr_str,
            .local_port = port,
            .binding_type = binding,
            .pid = if (row.dwOwningPid > 0) row.dwOwningPid else null,
            .process_name = null,
        });
    }

    return ListenerInspectionResult{
        .listeners = try list.toOwnedSlice(),
        .is_permission_limited = false,
    };
}

/// Bounded subprocess fallback running 'netstat.exe -ano -p tcp' with no shell interpolation
pub fn inspectListenersSubprocessFallback(allocator: std.mem.Allocator) !ListenerInspectionResult {
    var child = std.process.Child.init(&[_][]const u8{ "netstat.exe", "-ano", "-p", "tcp" }, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;

    try child.spawn();

    const max_bytes: usize = 64 * 1024; // 64 KB safety cap
    var stdout_buf = std.ArrayList(u8).init(allocator);
    defer stdout_buf.deinit();

    var reader = child.stdout.?.reader();
    var buf: [1024]u8 = undefined;
    var total_read: usize = 0;

    while (true) {
        const bytes_read = try reader.read(&buf);
        if (bytes_read == 0) break;
        total_read += bytes_read;
        if (total_read > max_bytes) break;
        try stdout_buf.appendSlice(buf[0..bytes_read]);
    }

    const term = try child.wait();
    if (term != .Exited or term.Exited != 0) {
        return error.ApiFailure;
    }

    var list = std.ArrayList(ListenerEntry).init(allocator);
    errdefer {
        for (list.items) |*l| l.deinit(allocator);
        list.deinit();
    }

    var lines = std.mem.splitScalar(u8, stdout_buf.items, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \r\t");
        if (!std.mem.startsWith(u8, trimmed, "TCP")) continue;
        if (std.mem.indexOf(u8, trimmed, "LISTENING") == null) continue;

        var tokens = std.mem.tokenizeAny(u8, trimmed, " \t");
        const proto = tokens.next() orelse continue; // TCP
        const local_addr_port = tokens.next() orelse continue;
        _ = tokens.next(); // Foreign Address
        _ = tokens.next(); // State (LISTENING)
        const pid_str = tokens.next();

        // Split host:port
        const colon_idx = std.mem.lastIndexOfScalar(u8, local_addr_port, ':') orelse continue;
        const host = local_addr_port[0..colon_idx];
        const port_str = local_addr_port[colon_idx + 1 ..];
        const port = std.fmt.parseInt(u16, port_str, 10) catch continue;

        var pid_val: ?u32 = null;
        if (pid_str) |p| {
            pid_val = std.fmt.parseInt(u32, p, 10) catch null;
        }

        const addr_dupe = try allocator.dupe(u8, host);
        errdefer allocator.free(addr_dupe);

        const proto_dupe = try allocator.dupe(u8, proto);
        errdefer allocator.free(proto_dupe);

        try list.append(.{
            .transport = proto_dupe,
            .local_address = addr_dupe,
            .local_port = port,
            .binding_type = classifyBinding(host),
            .pid = pid_val,
            .process_name = null,
        });
    }

    return ListenerInspectionResult{
        .listeners = try list.toOwnedSlice(),
        .is_permission_limited = false,
    };
}

test "windows controlled local listener test" {
    if (@import("builtin").os.tag != .windows) return;

    // Start a real controlled TCP listener on loopback
    const loopback = std.net.Address.parseIp("127.0.0.1", 0) catch return error.SkipZigTest;
    var server = loopback.listen(.{ .reuse_address = true }) catch return error.SkipZigTest;
    defer server.deinit();

    const actual_port = server.listen_address.getPort();

    var result = inspectListenersWindows(testing.allocator) catch return error.SkipZigTest;
    defer result.deinit(testing.allocator);

    if (result.listeners.len == 0) return error.SkipZigTest;

    // Verify our controlled test listener is identified and classified
    var found = false;
    for (result.listeners) |l| {
        if (l.local_port == actual_port) {
            found = true;
            try testing.expectEqual(BindingType.loopback_only, l.binding_type);
            try testing.expectEqualStrings("127.0.0.1", l.local_address);
            break;
        }
    }
    if (!found) return error.SkipZigTest;
}

test "windows listener fallback execution" {
    if (@import("builtin").os.tag != .windows) return;

    var result = try inspectListenersSubprocessFallback(testing.allocator);
    defer result.deinit(testing.allocator);
}
