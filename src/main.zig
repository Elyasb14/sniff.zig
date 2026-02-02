const std = @import("std");
const posix = std.posix;
const Args = @import("Args.zig");
const packet = @import("packet.zig");
const http = @import("application/http.zig");
const helpers = @import("helpers.zig");
const Filter = @import("Filter.zig").Filter;
const Trace = @import("trace.zig").Trace;

var running: bool = true;

fn sigint_handler(_: c_int) callconv(.c) void {
    running = false;
}

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
fn should_filter_transport_packet(pkt: packet.Packet, args: Args) bool {
    if (pkt.transport) |tpt| {
        const ret = switch (tpt) {
            .tcp => args.tcp,
            .udp => args.udp,
            .icmp => args.icmp,
            .can => args.can,
            .unknown => false,
        };

        // TODO: this should be printed before we even receive any packets
        if (ret and args.verbose) {
            std.log.info("filtering packets with {s} transport", .{@tagName(tpt)});
        }

        return ret;
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

            const filter = try Filter.init(args) orelse return error.BAD;

            var trace: ?Trace = null;
            if (args.write_file != null) {
                trace = Trace.init(allocator, @intCast(dlt));
                if (args.verbose) {
                    std.log.info("Trace capture enabled, will write to: {s}", .{args.write_file.?});
                }
            }
            defer if (trace) |*t| t.deinit();

            const sigact = posix.Sigaction{
                .handler = .{ .handler = sigint_handler },
                .mask = posix.sigemptyset(),
                .flags = 0,
            };
            posix.sigaction(posix.SIG.INT, &sigact, null);

            var packet_count: u32 = 0;

            while (running) {
                var hdr: [*c]c.struct_pcap_pkthdr = undefined;
                var buf: [*c]const u8 = undefined;

                const res = c.pcap_next_ex(chan, &hdr, &buf);
                switch (res) {
                    PCAP_OK => {
                        if (packet.Packet.init(dlt, buf, @ptrCast(hdr), std.builtin.Endian.big)) |pkt| {
                            if (filter.match_w_packet(pkt)) {
                                try pkt.pp();

                                if (trace) |*t| {
                                    const caplen = hdr.*.caplen;
                                    const ts_sec: u32 = @intCast(hdr.*.ts.tv_sec);
                                    const ts_usec: u32 = @intCast(hdr.*.ts.tv_usec);
                                    try t.append(buf[0..caplen], ts_sec, ts_usec);
                                }

                                packet_count += 1;

                                if (args.max_packets) |max| {
                                    if (packet_count >= max) {
                                        if (args.verbose) {
                                            std.log.info("Reached max packet count: {d}", .{max});
                                        }
                                        break;
                                    }
                                }
                            } else {
                                if (args.verbose) std.log.info("filtering out packet here", .{});
                                continue;
                            }
                        } else {
                            continue;
                        }
                    },
                    PCAP_TIMEOUT => continue,
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

            if (trace) |t| {
                if (args.write_file) |path| {
                    t.write_pcap(path) catch |err| {
                        std.log.err("Failed to write pcap file: {any}", .{err});
                        return;
                    };
                    std.log.info("Wrote {d} packets to {s}", .{ t.packet_count(), path });
                }
            }

            c.pcap_close(chan);
            c.pcap_freealldevs(alldevs);
            return;
        } else {
            dev = d.next;
            continue;
        }

        dev = d.next;
    }

    std.log.err("Can't open requested device: {s}", .{args.device});
    c.pcap_freealldevs(alldevs);
}
