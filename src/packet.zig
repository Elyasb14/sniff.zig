const std = @import("std");
const c = @cImport({
    @cInclude("pcap.h");
});

pub const Transport = union(enum) {
    tcp: TcpHeader,
    udp: UdpHeader,
    icmp: IcmpHeader,
    unknown: []const u8,
};

const IpVersion = enum(u8) {
    IPV4 = 4,
    IPV6 = 6,
};

const EthernetHeader = struct {
    dst_mac: []const u8,
    src_mac: []const u8,
    ether_type: u16,

    pub fn init(buf: [*c]const u8) EthernetHeader {
        const ether_type: u16 = (@as(u16, buf[12]) << 8) | buf[13];
        const dst_mac = buf[0..6];
        const src_mac = buf[6..12];
        return EthernetHeader{
            .ether_type = ether_type,
            .src_mac = src_mac,
            .dst_mac = dst_mac,
        };
    }
};

const Ipv4Header = struct {
    version_ihl: u8,
    dscp_ecn: u8,
    total_length: u16,
    identification: u16,
    flags_fragment: u16,
    ttl: u8,
    protocol: u8,
    header_checksum: u16,
    src_addr: []const u8,
    dst_addr: []const u8,
    options: ?[]const u8,

    pub fn init(buf: [*c]const u8, endian: std.builtin.Endian) Ipv4Header {
        const version_ihl = buf[0];
        const ihl = version_ihl & 0x0F;
        const hdr_len = ihl * 4;

        const descp_ecn = buf[1];
        const total_length = (@as(u16, buf[2]) << 8) | buf[3];
        const identification = std.mem.readInt(u16, buf[4..6], endian);
        const flags_fragment = (@as(u16, buf[6]) << 8) | buf[7];
        const ttl = buf[8];
        const protocol = buf[9];
        const header_checksum = std.mem.readInt(u16, buf[10..12], .big);
        const src_addr = buf[12..16];
        const dst_addr = buf[16..20];
        const options: ?[]const u8 = if (hdr_len > 20) buf[20..hdr_len] else null;

        return Ipv4Header{
            .version_ihl = version_ihl,
            .dscp_ecn = descp_ecn,
            .total_length = total_length,
            .identification = identification,
            .flags_fragment = flags_fragment,
            .ttl = ttl,
            .protocol = protocol,
            .header_checksum = header_checksum,
            .src_addr = src_addr,
            .dst_addr = dst_addr,
            .options = options,
        };
    }
};

const TcpHeader = struct {
    src_port: u16,
    dst_port: u16,
    seq_number: u32,
    ack_number: u32,
    data_offset_reserved_flags: u16,
    window_size: u16,
    checksum: u16,
    urgent_pointer: u16,
    options: ?[]const u8,
    payload: []const u8,

    pub fn init(buf: [*c]const u8, endian: std.builtin.Endian) TcpHeader {
        const src_port = std.mem.readInt(u16, buf[0..2], endian);
        const dst_port = std.mem.readInt(u16, buf[2..4], endian);
        const seq_number = std.mem.readInt(u32, buf[4..8], endian);
        const ack_number = std.mem.readInt(u32, buf[8..12], endian);
        const data_offset_reserved_flags = std.mem.readInt(u16, buf[12..14], endian);
        const window_size = std.mem.readInt(u16, buf[14..16], endian);
        const checksum = std.mem.readInt(u16, buf[16..18], endian);
        const urgent_pointer = std.mem.readInt(u16, buf[18..20], endian);

        var hdr = TcpHeader{
            .src_port = src_port,
            .dst_port = dst_port,
            .seq_number = seq_number,
            .ack_number = ack_number,
            .data_offset_reserved_flags = data_offset_reserved_flags,
            .window_size = window_size,
            .checksum = checksum,
            .urgent_pointer = urgent_pointer,
            .options = null,
            .payload = &[_]u8{},
        };

        const hdr_len = hdr.header_length();
        if (hdr_len > 20) {
            hdr.options = buf[20..hdr_len];
        }
        hdr.payload = std.mem.span(buf[hdr_len..]);
        return hdr;
    }

    fn data_offset(self: TcpHeader) u16 {
        return self.data_offset_reserved_flags >> 12 & 0xF;
    }
    fn header_length(self: TcpHeader) u16 {
        return self.data_offset() * 4;
    }

    fn parse_flags(self: TcpHeader) TcpFlags {
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

const UdpHeader = struct {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
    payload: []const u8,

    pub fn init(buf: [*c]const u8, endian: std.builtin.Endian) UdpHeader {
        const src_port = std.mem.readInt(u16, buf[0..2], endian);
        const dst_port = std.mem.readInt(u16, buf[2..4], endian);
        const length = std.mem.readInt(u16, buf[4..6], endian);
        const checksum = std.mem.readInt(u16, buf[6..8], endian);
        const payload = buf[8..length];
        return UdpHeader{
            .src_port = src_port,
            .dst_port = dst_port,
            .length = length,
            .checksum = checksum,
            .payload = payload,
        };
    }
};

const IcmpHeader = struct {
    type: u8,
    code: u8,
    checksum: u16,
    payload: []const u8,

    pub fn init(buf: [*c]const u8, endian: std.builtin.Endian) IcmpHeader {
        const icmp_type = buf[0];
        const code = buf[1];
        const checksum = std.mem.readInt(u16, buf[2..4], endian);
        const payload = buf[4..];
        return IcmpHeader{
            .type = icmp_type,
            .code = code,
            .checksum = checksum,
            .payload = std.mem.span(payload),
        };
    }
};

pub const Packet = struct {
    datalink: c_int,
    ts: c.struct_timeval,
    caplen: c_uint,
    endianess: std.builtin.Endian,

    ethernet: ?EthernetHeader,
    ipv4: ?Ipv4Header,
    transport: ?Transport,

    pub fn init(dlt: c_int, buf: [*c]const u8, header: *c.struct_pcap_pkthdr, endianess: std.builtin.Endian) ?Packet {
        var pkt = Packet{
            .datalink = dlt,
            .ts = header.ts,
            .caplen = header.caplen,
            .endianess = endianess,
            .ethernet = null,
            .ipv4 = null,
            .transport = null,
        };

        switch (dlt) {
            c.DLT_EN10MB => {
                const eth = EthernetHeader.init(buf[0..14]);
                pkt.ethernet = eth;
                switch (eth.ether_type) {
                    0x0800 => pkt.parse_ipv4(buf[14..]),
                    0x86dd => {
                        std.log.err("\x1b[31mIPv6 not supported\x1b[0m", .{});
                        return null;
                    },
                    else => return null,
                }
            },
            c.DLT_RAW => {
                const version = buf[0] >> 4;
                switch (version) {
                    4 => pkt.parse_ipv4(buf[0..]),
                    6 => {
                        std.log.err("IPv6 not supported", .{});
                        return null;
                    },
                    else => return null,
                }
            },
            c.DLT_NULL => {
                const family = std.mem.readInt(u32, buf[0..4], .little);
                switch (family) {
                    2 => pkt.parse_ipv4(buf[4..]),
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
        const ip = Ipv4Header.init(buf, self.endianess);
        self.ipv4 = ip;

        const ihl = (ip.version_ihl & 0x0F) * 4;
        const payload = buf[ihl..];

        switch (ip.protocol) {
            6 => self.transport = Transport{ .tcp = TcpHeader.init(payload, self.endianess) },
            17 => self.transport = Transport{ .udp = UdpHeader.init(payload, self.endianess) },
            1 => self.transport = Transport{ .icmp = IcmpHeader.init(payload, self.endianess) },
            else => {},
        }
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
            if (ip.options) |opt| try stdout.print("  options: {any}\n", .{opt});

            if (packet.transport) |transport|
                switch (transport) {
                    .tcp => |tcp| {
                        const data_offset = (tcp.data_offset_reserved_flags >> 12) & 0xF;
                        const flags = tcp.parse_flags();

                        try stdout.print("TCP:\n", .{});
                        try stdout.print("  src port: {d}\n", .{tcp.src_port});
                        try stdout.print("  dst port: {d}\n", .{tcp.dst_port});
                        try stdout.print("  seq number: {d}\n", .{tcp.seq_number});
                        try stdout.print("  ack number: {d}\n", .{tcp.ack_number});
                        try stdout.print("  data offset: {d} (header {d} bytes)\n", .{ data_offset, data_offset * 4 });
                        try stdout.print("  flags: ", .{});
                        inline for (std.meta.fields(TcpFlags)) |field| {
                            if (@field(flags, field.name))
                                try stdout.print("{s} ", .{field.name});
                        }
                        try stdout.print("\n", .{});
                        try stdout.print("  window size: {d}\n", .{tcp.window_size});
                        try stdout.print("  checksum: 0x{x}\n", .{tcp.checksum});
                        try stdout.print("  urgent pointer: {d}\n", .{tcp.urgent_pointer});
                        if (tcp.options) |opt| try stdout.print("  options: {any}\n", .{opt});
                        try stdout.print("  payload: \n\x1b[32m{s}\x1b[0m\n", .{tcp.payload});
                    },
                    .udp => |udp| {
                        try stdout.print("UDP:\n", .{});
                        try stdout.print("  src port: {d}\n", .{udp.src_port});
                        try stdout.print("  dst port: {d}\n", .{udp.dst_port});
                        try stdout.print("  length: {d}\n", .{udp.length});
                        try stdout.print("  checksum: 0x{x}\n", .{udp.checksum});
                        try stdout.print("  payload: \n\x1b[32m{s}\x1b[0m\n", .{udp.payload});
                    },
                    .icmp => |icmp| {
                        try stdout.print("ICMP\n", .{});
                        try stdout.print("  icmp type: {d}\n", .{icmp.type});
                        try stdout.print("  payload: \n\x1b[32m{s}\x1b[0m\n", .{icmp.payload});
                    },
                    else => try stdout.print("Transport: protocol {d} not parsed\n", .{ip.protocol}),
                };
        }

        try stdout.print("================ END OF PACKET =================\n\n", .{});
        try stdout.flush();
    }
};
