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
ttl: ?u8,
protocol: ?u8,
checksum: [2]u8,
src_addr: [4]u8,
dst_addr: [4]u8,
src_port: ?u16,
dst_port: ?u16,
ts: c.struct_timeval,

fn parse_ipv4(self: *Packet, ip_header: [*c]const u8) void {
    self.ip_version = .IPV4;

    @memcpy(&self.id, ip_header[4..6]);
    self.ttl = ip_header[8];
    self.protocol = ip_header[9];
    @memcpy(&self.checksum, ip_header[10..12]);
    @memcpy(&self.src_addr, ip_header[12..16]);
    @memcpy(&self.dst_addr, ip_header[16..20]);

    const ihl = (ip_header[0] & 0x0F) * 4;
    const transport_header = ip_header[ihl..];

    self.src_port = std.mem.readInt(u16, transport_header[0..2], .big);
    self.dst_port = std.mem.readInt(u16, transport_header[2..4], .big);
}

pub fn init(dlt: c_int, buf: [*c]const u8, header: *c.struct_pcap_pkthdr) ?Packet {
    var pkt = Packet{
        .datalink = dlt,
        .dst_mac = [_]u8{0} ** 6,
        .src_mac = [_]u8{0} ** 6,
        .ip_version = null,
        .len = header.*.len,
        .id = [_]u8{0} ** 2,
        .ttl = null,
        .protocol = null,
        .checksum = [_]u8{0} ** 2,
        .src_addr = [_]u8{0} ** 4,
        .dst_addr = [_]u8{0} ** 4,
        .src_port = null,
        .dst_port = null,
        .ts = header.*.ts,
    };

    switch (dlt) {
        // Ethernet (DLT_EN10MB)
        c.DLT_EN10MB => {
            @memcpy(&pkt.dst_mac, buf[0..6]);
            @memcpy(&pkt.src_mac, buf[6..12]);

            const ether_type: u16 = (@as(u16, buf[12]) << 8) | buf[13];
            switch (ether_type) {
                0x0800 => pkt.parse_ipv4(buf[14..]), // IPv4 starts at offset 14
                else => return null,
            }
        },
        // Raw IP (DLT_RAW)
        c.DLT_RAW => {
            const version = buf[0] >> 4;
            switch (version) {
                4 => pkt.parse_ipv4(buf[0..]), // IPv4 starts at offset 0
                else => return null,
            }
        },
        else => return null,
    }

    return pkt;
}

pub fn pp(packet: Packet) !void {
    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const dst_addr = packet.dst_addr;
    const src_addr = packet.src_addr;
    try stdout.print("dst addr: {d}.{d}.{d}.{d}\n", .{ dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3] });
    try stdout.print("src addr: {d}.{d}.{d}.{d}\n", .{ src_addr[0], src_addr[1], src_addr[2], src_addr[3] });
    try stdout.print("ip protocol: {d}\n", .{packet.protocol orelse 0});
    if (packet.src_port) |sp| try stdout.print("src port: {d}\n", .{sp});
    if (packet.dst_port) |dp| try stdout.print("dst port: {d}\n", .{dp});
    try stdout.flush();
}
