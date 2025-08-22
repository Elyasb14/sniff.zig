const std = @import("std");
const c = @cImport({
    @cInclude("pcap.h");
});

const Packet = @This();

const IpVersion = enum(u8) {
    IPV4 = 4,
    IPV6 = 6,
};

datalink: c_int,
dst_mac: [6]u8,
src_mac: [6]u8,
ip_version: ?IpVersion, // null if not an IP packet
len: c_uint,
id: [2]u8,
// missing flags and fragment offset
ttl: ?u8,
protocol: ?u8,
checksum: [2]u8,
src_addr: [4]u8,
dst_addr: [4]u8,
src_port: ?u16,
dst_port: ?u16,
buf: []const u8,
ts: c.struct_timeval,

pub fn init(dlt: c_int, buf: [*c]const u8, header: *c.struct_pcap_pkthdr) ?Packet {
    var pkt = Packet{
        .datalink = dlt,
        .dst_mac = [_]u8{0} ** 6,
        .src_mac = [_]u8{0} ** 6,
        .ip_version = undefined,
        .len = header.*.len,
        .id = [_]u8{0} ** 2,
        .ttl = null,
        .protocol = null,
        .checksum = undefined,
        .src_addr = [_]u8{0} ** 4,
        .dst_addr = [_]u8{0} ** 4,
        .src_port = null,
        .dst_port = null,
        .buf = std.mem.span(buf),
        .ts = header.*.ts,
    };

    switch (dlt) {
        // full ethernet (e.g. en0)
        1 => {
            // Ethernet
            @memcpy(&pkt.dst_mac, buf[0..6]);
            @memcpy(&pkt.src_mac, buf[6..12]);

            const ether_type: u16 = (@as(u16, buf[12]) << 8) | buf[13];
            if (ether_type != 0x0800) return null; // Not IPv4

            // IPV4 header starts at offset 14
            const ip_header = buf[14..];

            pkt.ip_version = switch (ip_header[0] >> 4) {
                4 => .IPV4,
                6 => .IPV6,
                else => return null,
            };

            @memcpy(&pkt.id, ip_header[4..6]);
            pkt.ttl = ip_header[8];
            pkt.protocol = ip_header[9];

            @memcpy(&pkt.checksum, ip_header[10..12]);

            @memcpy(&pkt.src_addr, ip_header[12..16]);
            @memcpy(&pkt.dst_addr, ip_header[16..20]);
        },
        else => return null,
    }

    return pkt;
}

pub fn pp(packet: Packet) !void {
    const stdout = std.io.getStdOut().writer();
    const dst_addr = packet.dst_addr;
    const src_addr = packet.src_addr;
    try stdout.print("dst addr: {d}.{d}.{d}.{d}\n", .{ dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3] });
    try stdout.print("src addr: {d}.{d}.{d}.{d}\n", .{ src_addr[0], src_addr[1], src_addr[2], src_addr[3] });
}
