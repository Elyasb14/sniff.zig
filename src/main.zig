const std = @import("std");
const Args = @import("Args.zig");

const c = @cImport({
    @cInclude("pcap.h");
});

const IpVersion = enum(u8) {
    IPV4 = 4,
    IPV6 = 6,
};

const Packet = struct {
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
                @memcpy(&pkt.src_addr, buf[12..16]);
                @memcpy(&pkt.dst_addr, buf[16..20]);
            },
            else => return null,
        }

        return pkt;
    }

    pub fn pp(self: Packet) void {
        inline for (@typeInfo(@TypeOf(self)).@"struct".fields) |field| {
            std.debug.print("Field Name: {s}, Field Type: {any}\n", .{ field.name, field.type });
        }
    }
};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const args = try Args.parse(allocator);
    var errbuf: [c.PCAP_ERRBUF_SIZE]u8 = undefined;

    if (c.pcap_init(c.PCAP_CHAR_ENC_UTF_8, &errbuf) != 0) {
        std.debug.print("Failed to initialize pcap\n", .{});
        return;
    }

    var alldevs: ?*c.pcap_if_t = null;
    if (c.pcap_findalldevs(&alldevs, &errbuf) != 0) {
        std.debug.print("pcap_findalldevs failed: {s}\n", .{errbuf});
        return;
    }

    var dev = alldevs;
    while (dev) |d| {
        if (std.mem.eql(u8, std.mem.span(d.name), args.device)) {
            const chan = c.pcap_create(@ptrCast(args.device), &errbuf);
            if (chan == null) {
                std.debug.print("channel was null\n", .{});
                return;
            }

            //NOTE: we set nonblocking here, can also set timeout if we want
            _ = c.pcap_setnonblock(chan, 1, &errbuf);
            if (c.pcap_activate(chan) != 0) {
                std.debug.print("failed to activate\n", .{});
                c.pcap_close(chan);
                return;
            }
            const dlt = c.pcap_datalink(chan);
            std.debug.print("Link-layer type: {any} ({s})\n", .{
                dlt, c.pcap_datalink_val_to_name(dlt),
            });

            while (true) {
                var hdr: [*c]c.struct_pcap_pkthdr = undefined;
                var buf: [*c]const u8 = undefined;

                const res = c.pcap_next_ex(chan, &hdr, &buf);
                switch (res) {
                    1 => {
                        // We got a valid packet
                        const pkt = Packet.init(dlt, buf, @ptrCast(hdr)) orelse undefined;
                        pkt.pp();
                    },
                    0 => {
                        // No packet available yet (nonblocking)
                        continue;
                    },
                    -1 => {
                        std.log.err("Error: {s}", .{c.pcap_geterr(chan)});
                        break;
                    },
                    -2 => {
                        std.log.err("EOF", .{});
                        break;
                    },
                    else => {
                        std.log.err("Unexpected return {d}", .{res});
                        break;
                    },
                }
            }
        } else {
            dev = d.next;
            continue;
        }

        dev = d.next;
    }

    c.pcap_freealldevs(alldevs);
}
