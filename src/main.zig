const std = @import("std");
const Args = @import("Args.zig");

const c = @cImport({
    @cInclude("pcap.h");
});

const IpVersion = enum(u8) {
    IPv4 = 4,
    IPv6 = 6,
};

const Packet = struct {
    // link layer
    datalink: c_int,
    ip_version: ?IpVersion, // null if not an IP packet
    src_mac: [6]u8,
    dst_mac: [6]u8,

    // network layer
    src_addr: [4]u8,
    dst_addr: [4]u8,
    protocol: ?u8,
    ttl: ?u8,

    // transport layer
    src_port: ?u16,
    dst_port: ?u16,

    // metadata
    payload: []const u8,
    len: u32,
    ts: c.struct_timeval,

    pub fn init(dlt: c_int, packet: [*c]const u8, header: *c.struct_pcap_pkthdr) ?Packet {
        var pkt = Packet{
            .datalink = dlt,
            .ip_version = undefined,
            .src_mac = [_]u8{0} ** 6,
            .dst_mac = [_]u8{0} ** 6,
            .src_addr = [_]u8{0} ** 4,
            .dst_addr = [_]u8{0} ** 4,
            .protocol = null,
            .ttl = null,
            .src_port = null,
            .dst_port = null,
            .payload = std.mem.span(packet),
            .len = header.*.len,
            .ts = header.*.ts,
        };

        switch (dlt) {
            0 => { //loopback
                @memcpy(&pkt.src_addr, packet[12..16]);
                @memcpy(&pkt.dst_addr, packet[16..20]);
            },
            1 => { // Ethernet
                // IPv4 header starts after 14-byte Ethernet header
                const ip_header = packet[14..];

                @memcpy(&pkt.src_mac, packet[0..6]);

                @memcpy(&pkt.src_addr, ip_header[12..16]);
                @memcpy(&pkt.dst_addr, ip_header[16..20]);
            },
            12 => { // Raw IPv4 (no Ethernet)
                @memcpy(&pkt.src_addr, packet[12..16]);
                @memcpy(&pkt.dst_addr, packet[16..20]);
            },
            else => return null,
        }

        return pkt;
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
                var header: [*c]c.struct_pcap_pkthdr = undefined;
                var packet: [*c]const u8 = undefined;

                const res = c.pcap_next_ex(chan, &header, &packet);
                switch (res) {
                    1 => {
                        // We got a valid packet
                        const pack = Packet.init(dlt, packet, @ptrCast(header));
                        for (pack.?.src_mac) |x| std.debug.print("{x}\n", .{x});
                        std.debug.print("len={d} caplen={d} src_addr={d} src_mac= {any}\n", .{
                            header.*.len,
                            header.*.caplen,
                            pack.?.src_addr,
                            pack.?.src_mac,
                        });
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
