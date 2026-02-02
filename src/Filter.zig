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
    src_ip: ?[4]u8 = null,
    dst_ip: ?[4]u8 = null,
    src_port: ?u16 = null,
    dst_port: ?u16 = null,

    /// Parse an IPv4 address string like "192.168.1.1" into 4 bytes
    fn parseIpv4(ip_str: []const u8) ?[4]u8 {
        var result: [4]u8 = undefined;
        var octet_idx: usize = 0;
        var it = std.mem.splitScalar(u8, ip_str, '.');

        while (it.next()) |octet_str| {
            if (octet_idx >= 4) return null;
            result[octet_idx] = std.fmt.parseInt(u8, octet_str, 10) catch return null;
            octet_idx += 1;
        }

        if (octet_idx != 4) return null;
        return result;
    }

    pub fn init(args: Args) !?Filter {
        var is_valid_tpt_filter = false;
        const tpt_count: usize = @as(usize, @intFromBool(args.icmp)) + @as(usize, @intFromBool(args.tcp)) + @as(usize, @intFromBool(args.udp)) + @as(usize, @intFromBool(args.can));

        if (tpt_count <= 1) {
            is_valid_tpt_filter = true;
        } else {
            std.log.err("only one transport filter rule can be applied, {d} provided", .{tpt_count});
            return null;
        }

        var filter: Filter = .{};
        if (args.tcp) filter.transport = .tcp;
        if (args.udp) filter.transport = .udp;
        if (args.can) filter.transport = .can;
        if (args.icmp) filter.transport = .icmp;

        if (args.dst_ip) |ip| {
            filter.dst_ip = parseIpv4(ip) orelse {
                std.log.err("invalid destination IP address: {s}", .{ip});
                return null;
            };
        }
        if (args.src_ip) |ip| {
            filter.src_ip = parseIpv4(ip) orelse {
                std.log.err("invalid source IP address: {s}", .{ip});
                return null;
            };
        }
        if (args.dst_port) |port| filter.dst_port = try std.fmt.parseInt(u16, port, 10);
        if (args.src_port) |port| filter.src_port = try std.fmt.parseInt(u16, port, 10);

        if (args.verbose) filter.logRules();

        return filter;
    }

    fn logRules(self: Filter) void {
        std.log.info("Active filter rules:", .{});
        if (self.transport) |tpt| {
            std.log.info("  transport: {s}", .{@tagName(tpt)});
        }
        if (self.src_ip) |ip| {
            std.log.info("  src-ip: {d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] });
        }
        if (self.dst_ip) |ip| {
            std.log.info("  dst-ip: {d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] });
        }
        if (self.src_port) |port| {
            std.log.info("  src-port: {d}", .{port});
        }
        if (self.dst_port) |port| {
            std.log.info("  dst-port: {d}", .{port});
        }
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
                if (!std.mem.eql(u8, &ip, ipv4.src_addr)) return false;
            } else {
                return false;
            }
        }

        if (self.dst_ip) |ip| {
            if (pkt.ipv4) |ipv4| {
                if (!std.mem.eql(u8, &ip, ipv4.dst_addr)) return false;
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
