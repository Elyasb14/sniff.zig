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
        if (self.transport) |tpt| {
            if (tpt == .can) {
                if (pkt.can == null) return false;
            } else {
                if (pkt.transport) |pkt_tpt| {
                    const is_match = switch (pkt_tpt) {
                        .tcp => tpt == .tcp,
                        .udp => tpt == .udp,
                        .icmp => tpt == .icmp,
                        else => false,
                    };
                    if (!is_match) return false;
                } else {
                    return false;
                }
            }
        }

        if (self.src_ip) |ip| {
            if (pkt.ipv4) |ipv4| {
                if (!std.mem.eql(u8, ip, ipv4.src_addr)) return false;
            } else {
                return false;
            }
        }

        if (self.dst_ip) |ip| {
            if (pkt.ipv4) |ipv4| {
                if (!std.mem.eql(u8, ip, ipv4.dst_addr)) return false;
            } else {
                return false;
            }
        }

        if (self.src_port) |port| {
            if (pkt.transport) |transport| {
                const match = switch (transport) {
                    .tcp => |tcp| tcp.src_port == port,
                    .udp => |udp| udp.src_port == port,
                    else => false,
                };
                if (!match) return false;
            } else {
                return false;
            }
        }

        if (self.dst_port) |port| {
            if (pkt.transport) |transport| {
                const match = switch (transport) {
                    .tcp => |tcp| tcp.dst_port == port,
                    .udp => |udp| udp.dst_port == port,
                    else => false,
                };
                if (!match) return false;
            } else {
                return false;
            }
        }

        return true;
    }
};
