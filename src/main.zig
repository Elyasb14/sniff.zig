const std = @import("std");
const Args = @import("Args.zig");
const transport = @import("transport.zig");
const http = @import("application/http.zig");

const c = @cImport({
    @cInclude("pcap.h");
});

const PCAP_OK = 1;
const PCAP_TIMEOUT = 0;
const PCAP_ERROR = -1;
const PCAP_EOF = -2;

pub fn main() !void {
    // setup
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

                        if (transport.Packet.init(dlt, buf, @ptrCast(hdr), std.builtin.Endian.big)) |pkt| {
                            // try pkt.pp();
                            if (pkt.transport) |x| {
                                // NOTE: this is a bad way to enter this stage of application level processing
                                // we really need to figure out what we want the entry point to application level processing is
                                // also we just assume transport is tcp
                                switch (x) {
                                    .tcp => {
                                        if (x.tcp.dst_port == 8081 or x.tcp.src_port == 8081 or x.tcp.dst_port == 80) {
                                            const http_port = http.HttpPacket.init(pkt);
                                            _ = http_port;
                                        }
                                    },
                                    else => {
                                        // We need to handle this better
                                        continue;
                                    },
                                }
                            }
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

    c.pcap_freealldevs(alldevs);
}
