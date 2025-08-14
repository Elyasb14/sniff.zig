const std = @import("std");
const c = @cImport({
    @cInclude("pcap.h");
});

const Packet = @This();

const IpVersion = enum(u8) {
    IPV4 = 4,
    IPV6 = 6,
};

// link layer
datalink: c_int,
dst_mac: [6]u8,
src_mac: [6]u8,
ip_version: ?IpVersion, // null if not an IP packet

// network layer
src_addr: [4]u8,
dst_addr: [4]u8,
protocol: ?u8,
ttl: ?u8,

// transport layer
src_port: ?u16,
dst_port: ?u16,

// metadata
buf: []const u8,
len: u32,
ts: c.struct_timeval,

pub fn init(dlt: c_int, buf: [*c]const u8, header: *c.struct_pcap_pkthdr) ?Packet {
    var pkt = Packet{
        .datalink = dlt,
        .ip_version = undefined,
        .dst_mac = [_]u8{0} ** 6,
        .src_mac = [_]u8{0} ** 6,
        .src_addr = [_]u8{0} ** 4,
        .dst_addr = [_]u8{0} ** 4,
        .protocol = null,
        .ttl = null,
        .src_port = null,
        .dst_port = null,
        .buf = std.mem.span(buf),
        .len = header.*.len,
        .ts = header.*.ts,
    };

    switch (dlt) {
        0 => { //loopback
            @memcpy(&pkt.src_addr, buf[12..16]);
            @memcpy(&pkt.dst_addr, buf[16..20]);
        },
        1 => { // Ethernet
            @memcpy(&pkt.dst_mac, buf[0..6]);
            @memcpy(&pkt.src_mac, buf[6..12]);

            const version = buf[14] >> 4;
            pkt.ip_version = if (version == 4) .IPV4 else if (version == 6) .IPV6 else null;

            @memcpy(&pkt.src_addr, buf[14..18]);
            @memcpy(&pkt.dst_addr, buf[18..22]);
        },
        12 => { // Raw IPv4 (no Ethernet)
            pkt.ttl = buf[8];
            pkt.protocol = buf[9];
            pkt.ip_version = .IPV4;
            @memcpy(&pkt.src_addr, buf[12..16]);
            @memcpy(&pkt.dst_addr, buf[16..20]);
        },
        else => return null,
    }

    return pkt;
}
