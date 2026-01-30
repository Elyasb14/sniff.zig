const std = @import("std");
const Args = @import("Args.zig");
const packet = @import("packet.zig");
const http = @import("application/http.zig");
const helpers = @import("helpers.zig");

fn coloredLog(
    comptime message_level: std.log.Level,
    comptime scope: @TypeOf(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    const color_code = switch (message_level) {
        .err => "\x1b[31m",
        .warn => "\x1b[33m",
        .info => "\x1b[32m",
        .debug => "\x1b[36m",
    };
    const reset_code = "\x1b[0m";

    const colored_format = color_code ++ format ++ reset_code;
    std.log.defaultLog(message_level, scope, colored_format, args);
}

pub const std_options: std.Options = .{
    .logFn = coloredLog,
};

const c = @cImport({
    @cInclude("pcap.h");
});

const PCAP_OK = 1;
const PCAP_TIMEOUT = 0;
const PCAP_ERROR = -1;
const PCAP_EOF = -2;

/// filter packet based on transport type
/// returns true if packet has provided tpt
fn filter_transport(pkt: packet.Packet, filter: [][]const u8) bool {
    if (pkt.transport) |x| {
        for (filter) |y| {
            if (std.mem.eql(u8, @tagName(x), y))
                return true;
        }
        return false;
    }
    return false;
}

pub fn main() !void {
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
                const name = std.mem.span(d.name);
                std.log.info("Device: {s}", .{name});
                if (d.description) |desc| {
                    std.log.info("  Description: {s}", .{std.mem.span(desc)});
                }
                std.log.info("  Addresses:", .{});
                var addr = d.addresses;
                while (addr) |a| {
                    if (a.*.addr) |sa_ptr| {
                        const sa = @as(*const c.struct_sockaddr, @ptrCast(sa_ptr));
                        if (sa.sa_family == c.AF_INET) {
                            const sin = @as(*const c.struct_sockaddr_in, @ptrCast(@alignCast(sa_ptr)));
                            const ip_addr = @as(*const [4]u8, @ptrCast(&sin.sin_addr.s_addr));
                            std.log.info("    IPv4: {d}.{d}.{d}.{d}", .{ ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3] });
                        } else if (sa.sa_family == c.AF_INET6) {
                            std.log.info("    IPv6: (run `ip addr show` for details)", .{});
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
            std.log.info("Link-layer type: {any} ({s})", .{
                dlt, c.pcap_datalink_val_to_name(dlt),
            });

            // where filtering starts
            var filter = try allocator.alloc([]const u8, 1024);
            filter[0] = "icmp";

            var is_valid_tpt_filter = false;
            const tpt_count: usize = @as(usize, @intFromBool(args.icmp)) + @as(usize, @intFromBool(args.tcp)) + @as(usize, @intFromBool(args.udp)) + @as(usize, @intFromBool(args.can));

            if (tpt_count == 1) {
                is_valid_tpt_filter = true;
            } else {
                std.log.err("only one transport filter rule and be applied, {d} provided", .{tpt_count});
                return;
            }

            while (true) {
                var hdr: [*c]c.struct_pcap_pkthdr = undefined;
                var buf: [*c]const u8 = undefined;

                const res = c.pcap_next_ex(chan, &hdr, &buf);
                switch (res) {
                    PCAP_OK => {
                        // We got a valid packet
                        if (packet.Packet.init(dlt, buf, @ptrCast(hdr), std.builtin.Endian.big)) |pkt| {
                            if (is_valid_tpt_filter) {
                                try pkt.pp();
                            } else {
                                continue;
                            }
                        } else {
                            continue;
                        }
                    },
                    PCAP_TIMEOUT => continue, // No packet available yet (nonblocking)
                    PCAP_ERROR => {
                        std.log.err("{s}", .{c.pcap_geterr(chan)});
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

    std.log.err("Can't open requested device: {s}", .{args.device});
    c.pcap_freealldevs(alldevs);
}
