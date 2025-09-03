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

    pub fn parse_flags(self: TcpHeader) TcpFlags {
        const flags = self.data_offset_reserved_flags & 0x1FF;
        return TcpFlags{
            .FIN = (flags & 0x001) != 0,
            .SYN = (flags & 0x002) != 0,
            .RST = (flags & 0x004) != 0,
            .PSH = (flags & 0x008) != 0,
            .ACK = (flags & 0x010) != 0,
            .URG = (flags & 0x020) != 0,
            .ECE = (flags & 0x040) != 0,
            .CWR = (flags & 0x080) != 0,
        };
    }
};

const TcpFlags = struct {
    CWR: bool,
    ECE: bool,
    URG: bool,
    ACK: bool,
    PSH: bool,
    RST: bool,
    SYN: bool,
    FIN: bool,
};

const UdpHeader = packed struct {
    src_port: u16,
    dst_port: u16,
    length: u16, // header + data
    checksum: u16,
};

const IcmpHeader = packed struct {
    type: u8,
    code: u8,
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
    icmp: ?IcmpHeader, // null unless protocol == 1

    pub fn init(dlt: c_int, buf: [*c]const u8, header: *c.struct_pcap_pkthdr) ?Packet {
        var pkt = Packet{ .datalink = dlt, .ts = header.ts, .caplen = header.caplen, .ethernet = null, .ipv4 = null, .tcp = null, .udp = null, .icmp = null };

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
            c.DLT_NULL => {
                // 4-byte pseudo-header
                const family = std.mem.readInt(u32, buf[0..4], .little);
                switch (family) {
                    2 => {
                        pkt.parse_ipv4(buf[4..]);
                    }, // AF_INET
                    24 => {
                        std.log.err("IPv6 not supported", .{});
                        return null;
                    },
                    else => return null,
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

        if (self.ipv4 != null) {
            switch (self.ipv4.?.protocol) {
                6 => self.parse_tcp(buf[20..]),
                17 => self.parse_udp(buf[20..]),
                1 => self.parse_icmp(buf[20..]),
                else => return,
            }
        } else return;
    }

    fn parse_tcp(self: *Packet, buf: [*c]const u8) void {
        const src_port = std.mem.readInt(u16, buf[0..2], .big);
        const dst_port = std.mem.readInt(u16, buf[2..4], .big);
        const seq_number = std.mem.readInt(u32, buf[4..8], .big);
        const ack_number = std.mem.readInt(u32, buf[8..12], .big);
        const data_offset_reserved_flags = std.mem.readInt(u16, buf[12..14], .big);
        const window_size = std.mem.readInt(u16, buf[14..16], .big);
        const checksum = std.mem.readInt(u16, buf[16..18], .big);
        const urgent_pointer = std.mem.readInt(u16, buf[18..20], .big);

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

    fn parse_udp(self: *Packet, buf: [*c]const u8) void {
        const src_port = std.mem.readInt(u16, buf[0..2], .big);
        const dst_port = std.mem.readInt(u16, buf[2..4], .big);
        const len = std.mem.readInt(u16, buf[4..6], .big);
        const cksum = std.mem.readInt(u16, buf[6..8], .big);

        const udp_hdr = UdpHeader{
            .src_port = src_port,
            .dst_port = dst_port,
            .length = len,
            .checksum = cksum,
        };

        self.udp = udp_hdr;
    }

    fn parse_icmp(self: *Packet, buf: [*c]const u8) void {
        const icmp_type = buf[0];
        const code = buf[1];
        const cksum = std.mem.readInt(u16, buf[2..4], .big);

        const icmp_hdr = IcmpHeader{
            .type = icmp_type,
            .code = code,
            .checksum = cksum,
        };

        self.icmp = icmp_hdr;
    }

    pub fn pp(packet: Packet) !void {
        var stdout_buffer: [2048]u8 = undefined;
        var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
        const stdout = &stdout_writer.interface;

        try stdout.print("\n================== NEW PACKET ==================\n", .{});

        // --- Ethernet ---
        if (packet.ethernet) |eth| {
            try stdout.print("Ethernet:\n", .{});
            try stdout.print("  dst mac: {x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}\n", .{ eth.dst_mac[0], eth.dst_mac[1], eth.dst_mac[2], eth.dst_mac[3], eth.dst_mac[4], eth.dst_mac[5] });
            try stdout.print("  src mac: {x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}\n", .{ eth.src_mac[0], eth.src_mac[1], eth.src_mac[2], eth.src_mac[3], eth.src_mac[4], eth.src_mac[5] });
            try stdout.print("  ether type: 0x{x}\n", .{eth.ether_type});
        }

        // --- IPv4 ---
        if (packet.ipv4) |ip| {
            const ihl = ip.version_ihl & 0x0F;
            const version = ip.version_ihl >> 4;

            try stdout.print("IPv4:\n", .{});
            try stdout.print("  version: {d}, ihl: {d} (header {d} bytes)\n", .{ version, ihl, ihl * 4 });
            try stdout.print("  total length: {d} bytes\n", .{ip.total_length});
            try stdout.print("  identification: {d}\n", .{ip.identification});
            try stdout.print("  flags+frag offset: 0x{x}\n", .{ip.flags_fragment});
            try stdout.print("  ttl: {d}\n", .{ip.ttl});
            try stdout.print("  protocol: {d}\n", .{ip.protocol});
            try stdout.print("  checksum: 0x{x}\n", .{ip.header_checksum});
            try stdout.print("  src addr: {d}.{d}.{d}.{d}\n", .{ ip.src_addr[0], ip.src_addr[1], ip.src_addr[2], ip.src_addr[3] });
            try stdout.print("  dst addr: {d}.{d}.{d}.{d}\n", .{ ip.dst_addr[0], ip.dst_addr[1], ip.dst_addr[2], ip.dst_addr[3] });

            // --- Transport ---
            switch (ip.protocol) {
                6 => if (packet.tcp) |tcp| {
                    const data_offset = (tcp.data_offset_reserved_flags >> 12) & 0xF;
                    const flags = tcp.data_offset_reserved_flags & 0x1FF;

                    try stdout.print("TCP:\n", .{});
                    try stdout.print("  src port: {d}\n", .{tcp.src_port});
                    try stdout.print("  dst port: {d}\n", .{tcp.dst_port});
                    try stdout.print("  seq number: {d}\n", .{tcp.seq_number});
                    try stdout.print("  ack number: {d}\n", .{tcp.ack_number});
                    try stdout.print("  data offset: {d} (header {d} bytes)\n", .{ data_offset, data_offset * 4 });
                    try stdout.print("  flags: 0b{b:09}\n", .{flags});
                    try stdout.print("  window size: {d}\n", .{tcp.window_size});
                    try stdout.print("  checksum: 0x{x}\n", .{tcp.checksum});
                    try stdout.print("  urgent pointer: {d}\n", .{tcp.urgent_pointer});
                },
                17 => if (packet.udp) |udp| {
                    try stdout.print("UDP:\n", .{});
                    try stdout.print("  src port: {d}\n", .{udp.src_port});
                    try stdout.print("  dst port: {d}\n", .{udp.dst_port});
                    try stdout.print("  length: {d}\n", .{udp.length});
                    try stdout.print("  checksum: 0x{x}\n", .{udp.checksum});
                },
                1 => if (packet.icmp) |icmp| {
                    try stdout.print("ICMP\n", .{});
                    try stdout.print("  icmp type: {d}\n", .{icmp.type});
                },
                else => try stdout.print("Transport: protocol {d} not parsed\n", .{ip.protocol}),
            }
        }

        try stdout.print("================ END OF PACKET =================\n\n", .{});
        try stdout.flush();
    }
};
