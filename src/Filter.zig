const std = @import("std");
const Args = @import("Args.zig");
const Packet = @import("packet.zig").Packet;

pub const TransportType = enum(u8) {
    icmp,
    tcp,
    udp,
    can,
};

pub const Filter = struct {
    transport: ?TransportType = null,
    src_ip: ?[]const u8 = null,
    dst_ip: ?[]const u8 = null,
    src_port: ?u16 = null,
    dst_port: ?u16 = null,

    pub fn init(args: Args) !?Filter {
        var is_valid_tpt_filter = false;
        const tpt_count: usize = @as(usize, @intFromBool(args.icmp)) + @as(usize, @intFromBool(args.tcp)) + @as(usize, @intFromBool(args.udp)) + @as(usize, @intFromBool(args.can));

        if (tpt_count == 1) {
            is_valid_tpt_filter = true;
        } else {
            std.log.err("only one transport filter rule can be applied, {d} provided", .{tpt_count});
            return null;
        }

        var filter: Filter = undefined;
        if (args.tcp) filter.transport = .tcp;
        if (args.udp) filter.transport = .udp;
        if (args.can) filter.transport = .can;
        if (args.icmp) filter.transport = .icmp;

        if (args.dst_ip) |ip| filter.dst_ip = ip;
        if (args.src_ip) |ip| filter.src_ip = ip;
        if (args.dst_port) |port| filter.dst_port = try std.fmt.parseInt(u16, port, 10);
        if (args.src_port) |port| filter.src_port = try std.fmt.parseInt(u16, port, 10);

        return filter;
    }

    pub fn match_w_packet(self: Filter, pkt: Packet) bool {
        inline for (std.meta.fields(Filter)) |field| {
            if (@field(self, field.name))
                std.debug.assert(field.name != null);
        }
        var matched = false;

        if (pkt.transport) |tpt| {
            if (std.mem.eql(u8, @tagName(tpt), @tagName(self.transport.?)))
                matched = true;
        }

        if (pkt.ipv4) |ipv4| {
            if (std.mem.eql(u8, self.dst_ip.?, ipv4.dst_addr))
                matched = true;

            if (std.mem.eql(u8, self.src_ip.?, ipv4.src_addr))
                matched = true;
        }
    }
};
