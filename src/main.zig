const std = @import("std");
const Args = @import("Args.zig");
const packet = @import("packet.zig");
const http = @import("application/http.zig");
const wireguard = @import("application/wireguard.zig");
const helpers = @import("helpers.zig");

const c = @cImport({
    @cInclude("pcap.h");
});

const PCAP_OK = 1;
const PCAP_TIMEOUT = 0;
const PCAP_ERROR = -1;
const PCAP_EOF = -2;

fn dissect_transport_packet(pkt: packet.Packet, wireguard_only: bool) !void {
    std.debug.assert(pkt.transport != null); // need a Transport to unrwap
    const transport = pkt.transport.?;
    switch (transport) {
        .tcp => {
            if (wireguard_only) return;
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
            const dst_port = transport.udp.dst_port;
            const src_port = transport.udp.src_port;

            if (dst_port == 51820 or src_port == 51820) {
                if (wireguard.WireGuardPacket.init(transport.udp.payload.ptr, transport.udp.payload.len)) |wg| {
                    std.debug.print("\x1b[33mWireGuard:\x1b[0m\n", .{});
                    std.debug.print("  type: {d} ({s})\n", .{ wg.msg_type, wg.msgTypeName() });
                    std.debug.print("  sender index: 0x{x}\n", .{wg.sender_index});
                    if (wg.receiver_index) |ri| std.debug.print("  receiver index: 0x{x}\n", .{ri});
                    std.debug.print("  payload length: {d} bytes\n", .{wg.payload.len});
                } else {
                    std.debug.print("WireGuard: (invalid packet)\n", .{});
                }
            } else if (!wireguard_only) {
                try pkt.pp();
            }
        },
        else => {
            if (wireguard_only) return;
        },
    }
}

pub fn main() !void {
    // setup
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const args = try Args.parse(allocator);

    if (args.list_devices) {
        try helpers.list_devices();
        return;
    }

    if (args.device.len == 0) {
        std.debug.print("Error: No device specified. Use -d <device> or --list to see available devices.\n\n", .{});
        Args.help("sniff_zig");
    }

    if (args.verbose) {
        std.log.info("\x1b[32mStarting packet capture on device: {s}\x1b[0m", .{args.device});
    }

    var errbuf: [c.PCAP_ERRBUF_SIZE]u8 = undefined;

    if (c.pcap_init(c.PCAP_CHAR_ENC_UTF_8, &errbuf) != 0) {
        std.log.err("\x1b[31mFailed to initialize pcap\n\x1b[0m", .{});
        return;
    }

    var alldevs: ?*c.pcap_if_t = null;
    if (c.pcap_findalldevs(&alldevs, &errbuf) != 0) {
        std.log.err("\x1b[31mpcap_findalldevs failed: {s}\n\x1b[0m", .{errbuf});
        return;
    }

    // Filter entrypoint
    // used for filtering traffic based on various parameters
    // e.g. in_addr and out_addr
    const file = std.fs.cwd().openFile(args.filter_path, .{}) catch |err| switch (err) {
        error.FileNotFound => {
            std.log.err("\x1b[31mCan't find provided filter config file: {s}\x1b[0m", .{args.filter_path});
            return error.FileNotFound;
        },
        else => return err,
    };
    defer file.close();

    var file_buf: [1024]u8 = undefined;
    const n = try file.read(&file_buf);

    var filter_map = std.StringHashMap(std.ArrayList([]const u8)).init(allocator);

    var file_it = std.mem.splitAny(u8, file_buf[0..n], "\n");
    while (file_it.next()) |line| {
        if (line.len == 0) continue;
        var line_it = std.mem.splitAny(u8, line, "=");
        const key = line_it.next() orelse continue;
        const value = line_it.next() orelse "";

        const gop = try filter_map.getOrPut(key);
        if (!gop.found_existing) {
            gop.value_ptr.* = try std.ArrayList([]const u8).initCapacity(allocator, 1024);
        }
        try gop.value_ptr.append(allocator, value);
    }

    if (args.verbose) {
        var key_it = filter_map.keyIterator();
        while (key_it.next()) |key| {
            const values = filter_map.get(key.*).?;
            std.log.info("\x1b[32mKEY: {s} ({d} values)\x1b[0m", .{ key.*, values.items.len });
            for (values.items) |value| {
                std.log.info("\x1b[32m  {s}\x1b[0m", .{value});
            }
        }
    }

    //TODO: add a filter dump in args.verbose

    var dev = alldevs;
    while (dev) |d| {
        if (std.mem.eql(u8, std.mem.span(d.name), args.device)) {
            if (args.verbose) {
                std.log.info("\x1b[32mFound device: {s}\x1b[0m", .{args.device});
                const name = std.mem.span(d.name);
                std.log.info("\x1b[32mDevice: {s}\x1b[0m", .{name});
                if (d.description) |desc| {
                    std.log.info("\x1b[32m  Description: {s}\x1b[0m", .{std.mem.span(desc)});
                }
                std.log.info("\x1b[32m  Addresses:\x1b[0m", .{});
                var addr = d.addresses;
                while (addr) |a| {
                    if (a.*.addr) |sa_ptr| {
                        const sa = @as(*const c.struct_sockaddr, @ptrCast(sa_ptr));
                        if (sa.sa_family == c.AF_INET) {
                            const sin = @as(*const c.struct_sockaddr_in, @ptrCast(@alignCast(sa_ptr)));
                            const ip_addr = @as(*const [4]u8, @ptrCast(&sin.sin_addr.s_addr));
                            std.log.info("\x1b[32m    IPv4: {d}.{d}.{d}.{d}\x1b[0m", .{ ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3] });
                        } else if (sa.sa_family == c.AF_INET6) {
                            std.log.info("\x1b[32m    IPv6: (see ifconfig for details)\x1b[0m", .{});
                        }
                    }
                    addr = a.*.next;
                }
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
            std.log.info("\x1b[32mLink-layer type: {any} ({s})\x1b[0m", .{
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
                                try dissect_transport_packet(pkt, args.wireguard_only);
                            } else if (!args.wireguard_only) try pkt.pp();
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
                        std.log.err("\x1b[31mEOF\x1b[0m", .{});
                        break;
                    },
                    else => {
                        std.log.err("\x1b[31mUnexpected return {d}\x1b[0m", .{res});
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

    std.log.err("\x1b[31mCan't open requested device: {s}\x1b[0m", .{args.device});
    c.pcap_freealldevs(alldevs);
}
