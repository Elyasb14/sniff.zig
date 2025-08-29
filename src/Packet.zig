const std = @import("std");
const c = @cImport({
    @cInclude("pcap.h");
});

const IpVersion = enum(u8) {
    IPV4 = 4,
    IPV6 = 6,
};

pub const EthernetHeader = struct {
    dst_mac: []const u8 = undefined,
    src_mac: []const u8 = undefined,
    ether_type: u16, // 0x0800 = IPv4
};

pub const Ipv4Header = struct {
    version_ihl: u8, // version (4 bits) + IHL (4 bits)
    dscp_ecn: u8, // DSCP (6 bits) + ECN (2 bits)
    total_length: u16, // bytes (header + payload)
    identification: u16,
    flags_fragment: u16, // flags (3 bits) + fragment offset (13 bits)
    ttl: u8,
    protocol: u8, // TCP=6, UDP=17, ICMP=1, etc.
    header_checksum: u16,
    src_addr: []const u8 = undefined,
    dst_addr: []const u8 = undefined,
    // Options may follow if IHL > 5
};

pub const TcpHeader = packed struct {
    src_port: u16,
    dst_port: u16,
    seq_number: u32,
    ack_number: u32,
    data_offset_reserved_flags: u16, // offset (4 bits), reserved (3), flags (9)
    window_size: u16,
    checksum: u16,
    urgent_pointer: u16,
    // Options may follow if data_offset > 5
};

const UdpHeader = packed struct {
    src_port: u16,
    dst_port: u16,
    length: u16, // header + data
    checksum: u16,
};

pub const Packet = struct {
    datalink: c_int,
    ts: c.struct_timeval,
    caplen: c_uint,

    ethernet: ?EthernetHeader,
    ipv4: ?Ipv4Header, // null if not IPv4
    tcp: ?TcpHeader, // null unless protocol == 6
    udp: ?UdpHeader, // null unless protocol == 17

    pub fn init(dlt: c_int, buf: [*c]const u8, header: *c.struct_pcap_pkthdr) ?Packet {
        var pkt = Packet{ .datalink = dlt, .ts = header.ts, .caplen = header.caplen, .ethernet = null, .ipv4 = null, .tcp = null, .udp = null };

        switch (dlt) {
            // Ethernet (DLT_EN10MB)
            c.DLT_EN10MB => {
                const ether_type: u16 = (@as(u16, buf[12]) << 8) | buf[13];
                const src_mac = buf[0..6];
                const dst_mac = buf[6..12];

                const eth_hdr = EthernetHeader{ .ether_type = ether_type, .src_mac = src_mac, .dst_mac = dst_mac };
                pkt.ethernet = eth_hdr;
                switch (ether_type) {
                    0x0800 => pkt.parse_ipv4(buf[14..]), // IPv4 starts at offset 14
                    0x86dd => {
                        std.log.err("\x1b[31mWe don't support IPV6\x1b[0m", .{});
                        return null;
                    },
                    else => {
                        std.log.err("\x1b[31mWe dont support ether type\x1b[0m: {x}", .{ether_type});
                        return null;
                    },
                }
            },
            // Raw IP (DLT_RAW)
            c.DLT_RAW => {
                const version = buf[0] >> 4;
                switch (version) {
                    4 => {
                        pkt.parse_ipv4(buf[0..]);
                    },

                    6 => {
                        std.log.err("\x1b[31mWe don't support IPV6\x1b[0m", .{});
                        return null;
                    },
                    else => {
                        std.log.err("\x1b[31mWe dont support ip version\x1b[0m: {d}", .{version});
                        return null;
                    },
                }
            },
            else => return null,
        }

        return pkt;
    }

    fn parse_ipv4(self: *Packet, buf: [*c]const u8) void {
        const version_ihl = buf[0];
        const descp_ecn = buf[1];
        const total_length = (@as(u16, buf[2]) << 8) | buf[3];
        const id = buf[4..6];
        const flags_fragment = (@as(u16, buf[6]) << 8) | buf[7];
        const ttl = buf[8];
        const protocol = buf[9];
        const cksm = buf[10..12];
        const src_addr = buf[12..16];
        const dst_addr = buf[16..20];

        const ipv4_hdr = Ipv4Header{
            .version_ihl = version_ihl,
            .dscp_ecn = descp_ecn,
            .total_length = total_length,
            .flags_fragment = flags_fragment,
            .identification = std.mem.readInt(u16, id, .big),
            .ttl = ttl,
            .protocol = protocol,
            .header_checksum = std.mem.readInt(u16, cksm, .big),
            .src_addr = src_addr,
            .dst_addr = dst_addr,
        };
        self.ipv4 = ipv4_hdr;

        switch (self.ipv4.?.protocol) {
            17 => self.parse_tcp(buf[20..]),
            else => return,
        }
    }

    fn parse_tcp(self: *Packet, buf: [*c]const u8) void {
        const dst_port = std.mem.readInt(u16, buf[0..2], .big);
        const src_port = std.mem.readInt(u16, buf[2..4], .big);
        const seq_number = std.mem.readInt(u32, buf[4..8], .big);
        const ack_number = std.mem.readInt(u32, buf[8..12], .big);
        const data_offset_reserved_flags = std.mem.readInt(u16, buf[10..12], .big);
        const window_size = std.mem.readInt(u16, buf[12..14], .big);
        const checksum = std.mem.readInt(u16, buf[14..16], .big);
        const urgent_pointer = std.mem.readInt(u16, buf[16..18], .big);

        const tcp_hdr = TcpHeader{
            .src_port = src_port,
            .dst_port = dst_port,
            .seq_number = seq_number,
            .ack_number = ack_number,
            .data_offset_reserved_flags = data_offset_reserved_flags,
            .window_size = window_size,
            .checksum = checksum,
            .urgent_pointer = urgent_pointer,
        };

        self.tcp = tcp_hdr;
    }

    pub fn pp(packet: Packet) !void {
        var stdout_buffer: [1024]u8 = undefined;
        var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
        const stdout = &stdout_writer.interface;

        const dst_mac = packet.ethernet.?.dst_mac;
        const src_mac = packet.ethernet.?.src_mac;

        const dst_addr = packet.ipv4.?.dst_addr;
        const src_addr = packet.ipv4.?.src_addr;

        try stdout.print("------------------ NEW PACKET ------------------\n", .{});
        try stdout.print("dst mac: {x}:{x}:{x}:{x}:{x}:{x}\n", .{ dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5] });
        try stdout.print("src mac: {x}:{x}:{x}:{x}:{x}:{x}\n", .{ src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5] });
        try stdout.print("id: {d}\n", .{packet.ipv4.?.identification});
        try stdout.print("ttl: {any}\n", .{packet.ipv4.?.ttl});
        try stdout.print("dst addr: {d}.{d}.{d}.{d}\n", .{ dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3] });
        try stdout.print("src addr: {d}.{d}.{d}.{d}\n", .{ src_addr[0], src_addr[1], src_addr[2], src_addr[3] });
        try stdout.print("ip protocol: {d}\n", .{packet.ipv4.?.protocol});
        if (packet.ipv4.?.protocol == 17) {
            try stdout.print("src port: {d}\n", .{packet.tcp.?.src_port});
            try stdout.print("dst port: {d}\n", .{packet.tcp.?.dst_port});
            try stdout.print("seq number: {d}\n", .{packet.tcp.?.seq_number});
        }
        try stdout.print("------------------ END OF PACKET ------------------\n", .{});
        try stdout.flush();
    }
};
