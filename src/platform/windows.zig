const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const NetworkInterface = types.NetworkInterface;
const InterfaceStatus = types.InterfaceStatus;
const InterfaceEnumerationResult = types.InterfaceEnumerationResult;

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

    var result = try enumerateInterfacesWindows(testing.allocator);
    defer result.deinit(testing.allocator);

    // Any working Windows system has at least 1 interface (typically loopback or ethernet/wifi)
    try testing.expect(result.interfaces.len > 0);

    // Verify presence of valid interface properties
    var found_loopback = false;
    for (result.interfaces) |iface| {
        try testing.expect(iface.name.len > 0);
        try testing.expect(iface.adapter_id.len > 0);
        if (iface.is_loopback) {
            found_loopback = true;
        }
    }
    try testing.expect(found_loopback);
}
