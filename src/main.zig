const std = @import("std");
const Args = @import("Args.zig");

const c = @cImport({
    @cInclude("pcap.h");
});

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
            const datalink = c.pcap_datalink(chan);
            std.debug.print("Link-layer type: {d} ({s})\n", .{
                datalink, c.pcap_datalink_val_to_name(datalink),
            });

            while (true) {
                var header: [*c]c.struct_pcap_pkthdr = undefined;
                var packet: [*c]const u8 = undefined;

                const res = c.pcap_next_ex(chan, &header, &packet);
                switch (res) {
                    1 => {
                        // We got a valid packet
                        std.debug.print("len={d} caplen={d} first_byte={x}\n", .{
                            header.*.len,
                            header.*.caplen,
                            packet[0], // first byte of packet
                        });
                    },
                    0 => {
                        // No packet available yet (nonblocking)
                        continue;
                    },
                    -1 => {
                        std.debug.print("Error: {s}\n", .{c.pcap_geterr(chan)});
                        break;
                    },
                    -2 => {
                        std.debug.print("EOF\n", .{});
                        break;
                    },
                    else => {
                        std.debug.print("Unexpected return {d}\n", .{res});
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
