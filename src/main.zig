const std = @import("std");
const Args = @import("Args.zig");
const packet = @import("packet.zig");
const http = @import("application/http.zig");
const wireguard = @import("wireguard.zig");

const c = @cImport({
    @cInclude("pcap.h");
});

const PCAP_OK = 1;
const PCAP_TIMEOUT = 0;
const PCAP_ERROR = -1;
const PCAP_EOF = -2;

fn list_devices() !void {
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
                        const ip_addr = @as([4]u8, @bitCast(sin.sin_addr.s_addr));
                        std.debug.print("       - IPv4: {d}.{d}.{d}.{d}\n", .{ ip_addr[3], ip_addr[2], ip_addr[1], ip_addr[0] });
                    } else if (sa.sa_family == c.AF_INET6) {
                        std.debug.print("       - IPv6: (see ifconfig for details)\n", .{});
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

fn wg(pkt: packet.Packet) void {
    const payload = pkt.transport.?.udp.payload;
    if (wireguard.WgPacket.init(payload)) |wg_pkt| {
        wg_pkt.pp() catch return;
    }
}

fn dissect_transport_packet(pkt: packet.Packet) void {
    std.debug.assert(pkt.transport != null); // need a Transport to unrwap
    const transport = pkt.transport.?;
    switch (transport) {
        .tcp => {
            const dst_port = transport.tcp.dst_port;
            const src_port = transport.tcp.src_port;

            if (dst_port == 80 or src_port == 80) {
                const http_pkt = http.HttpPacket.init(pkt);
                if (http_pkt) |x| {
                    std.debug.print("PACKET: {s}\n", .{x.msg.response.body});
                }
            }
        },
        .udp => {
            wg(pkt);

            return;
        },
        else => return,
    }
}

pub fn main() !void {
    // setup
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const args = try Args.parse(allocator);

    if (args.list_devices) {
        try list_devices();
        return;
    }

    if (args.device.len == 0) {
        std.debug.print("Error: No device specified. Use -d <device> or --list to see available devices.\n\n", .{});
        Args.help("sniff_zig");
    }

    if (args.verbose) {
        std.log.info("Starting packet capture on device: {s}", .{args.device});
    }

    var errbuf: [c.PCAP_ERRBUF_SIZE]u8 = undefined;

    if (c.pcap_init(c.PCAP_CHAR_ENC_UTF_8, &errbuf) != 0) {
        std.log.err("Failed to initialize pcap\n", .{});
        return;
    }

    var alldevs: ?*c.pcap_if_t = null;
    if (c.pcap_findalldevs(&alldevs, &errbuf) != 0) {
        std.log.err("pcap_findalldevs failed: {s}\n", .{errbuf});
        return;
    }

    var dev = alldevs;
    while (dev) |d| {
        if (std.mem.eql(u8, std.mem.span(d.name), args.device)) {
            if (args.verbose) {
                std.log.info("Found device: {s}", .{args.device});
            }

            const chan = c.pcap_create(@ptrCast(args.device), &errbuf);
            if (chan == null) {
                std.debug.print("channel was null\n", .{});
                return;
            }
            // Add after pcap_create but before pcap_activate
            if (c.pcap_set_promisc(chan, 0) != 0) {
                std.debug.print("Failed to disable promiscuous mode\n", .{});
                c.pcap_close(chan);
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
            std.log.info("Link-layer type: {any} ({s})", .{
                dlt, c.pcap_datalink_val_to_name(dlt),
            });

            while (true) {
                var hdr: [*c]c.struct_pcap_pkthdr = undefined;
                var buf: [*c]const u8 = undefined;

                const res = c.pcap_next_ex(chan, &hdr, &buf);
                switch (res) {
                    PCAP_OK => {
                        // We got a valid packet

                        if (packet.Packet.init(dlt, buf, @ptrCast(hdr), std.builtin.Endian.big)) |pkt| {
                            if (pkt.transport) |_| {
                                // wireshark has the notion of "dissector tree"
                                dissect_transport_packet(pkt);
                            } else try pkt.pp();
                        } else {
                            continue;
                        }
                    },
                    PCAP_TIMEOUT => continue, // No packet available yet (nonblocking)
                    PCAP_ERROR => {
                        std.log.err("\x1b[31m" ++ "{s}" ++ "\x1b[0m", .{c.pcap_geterr(chan)});
                        break;
                    },
                    PCAP_EOF => {
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

    std.log.err("Can't open requested device: \x1b[31m{s}\x1b[0m", .{args.device});
    c.pcap_freealldevs(alldevs);
}
