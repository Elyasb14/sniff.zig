const std = @import("std");
const transport = @import("../transport.zig");

const HttpHeaders = []const struct {
    name: []const u8,
    value: []const u8,
};

const HttpRequest = struct {
    method: []const u8,
    target: []const u8,
    version: []const u8,
    headers: HttpHeaders,
    body: []const u8,
};

const HttpResponse = struct {
    version: []const u8,
    status_code: u16,
    reason: []const u8,
    headers: HttpHeaders,
    body: []const u8,
};

const HttpMsg = union(enum) { request: HttpRequest, response: HttpResponse };

pub const HttpPacket = struct {
    packet: transport.Packet,
    msg: HttpMsg,

    pub fn init(pkt: transport.Packet) void {
        std.debug.assert(pkt.transport != null); // why are you trying to parse a null packet as an http packet
        std.debug.assert(std.meta.eql(@tagName(pkt.transport.?), @tagName(transport.Transport.tcp)));

        var payload = std.mem.splitAny(u8, pkt.transport.?.tcp.payload, "\r\n");
        while (payload.next()) |x| {
            std.debug.print("\x1b[32m{s}\x1b[0m\n", .{x});
        }
    }
};
