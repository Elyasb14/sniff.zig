const std = @import("std");

const c = @cImport({
    @cInclude("pcap.h");
});

pub fn list_devices() !void {
    var errbuf: [c.PCAP_ERRBUF_SIZE]u8 = undefined;
    var alldevs: ?*c.pcap_if_t = null;

    if (c.pcap_findalldevs(&alldevs, &errbuf) != 0) {
        std.log.err("pcap_findalldevs failed: {s}\n", .{errbuf});
        return;
    }

    std.debug.print("Available network devices (with IPv4 addresses):\n", .{});
    var dev = alldevs;
    var i: u32 = 1;
    while (dev) |d| {
        var has_ipv4 = false;
        var addr = d.addresses;
        while (addr) |a| {
            if (a.*.addr) |sa_ptr| {
                const sa = @as(*const c.struct_sockaddr, @ptrCast(sa_ptr));
                if (sa.sa_family == c.AF_INET) {
                    has_ipv4 = true;
                    break;
                }
            }
            addr = a.*.next;
        }

        if (has_ipv4) {
            const name = std.mem.span(d.name);
            std.debug.print("  {d}. {s}\n", .{ i, name });

            addr = d.addresses;
            std.debug.print("     Addresses:\n", .{});
            while (addr) |a| {
                if (a.*.addr) |sa_ptr| {
                    const sa = @as(*const c.struct_sockaddr, @ptrCast(sa_ptr));
                    if (sa.sa_family == c.AF_INET) {
                        const sin = @as(*const c.struct_sockaddr_in, @ptrCast(@alignCast(sa_ptr)));
                        const ip_addr = @as(*const [4]u8, @ptrCast(&sin.sin_addr.s_addr));
                        std.debug.print("       - IPv4: {d}.{d}.{d}.{d}\n", .{ ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3] });
                    } else if (sa.sa_family == c.AF_INET6) {
                        std.debug.print("       - IPv6: (run `ip addr show` for details)\n", .{});
                    }
                }
                addr = a.*.next;
            }
            std.debug.print("\n", .{});
            i += 1;
        }
        dev = d.next;
    }

    c.pcap_freealldevs(alldevs);
}
