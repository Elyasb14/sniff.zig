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
        0 => {},
        1 => {
            // ethernet
            @memcpy(&pkt.dst_mac, buf[0..6]);
            @memcpy(&pkt.src_mac, buf[6..12]);

            // ipv4
            const version = buf[12..14];
            pkt.ip_version = if ((version[0] >> 4) == 4) .IPV4 else if ((version[0] >> 4) == 6) .IPV6 else null;

            @memcpy(&pkt.id, buf[18..20]);

            @memcpy(&pkt.src_addr, buf[26..30]);
            @memcpy(&pkt.dst_addr, buf[30..34]);
        },
        12 => {},
        else => return null,
    }

    return pkt;
}
