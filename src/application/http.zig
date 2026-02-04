const std = @import("std");
const packet = @import("../packet.zig");
const t = std.testing;

const HttpHeader = struct {
    name: []const u8,
    value: []const u8,
};

const HttpRequest = struct {
    method: []const u8,
    target: []const u8,
    version: []const u8,
    body: []const u8,
    headers: []const HttpHeader,
};

const HttpResponse = struct {
    version: []const u8,
    reason: []const u8,
    body: []const u8,
    headers: []const HttpHeader,
    status_code: u16,
};

const HttpMsg = union(enum) { request: HttpRequest, response: HttpResponse };

fn get_headers(buf: []const u8) []const HttpHeader {
    var it = std.http.HeaderIterator.init(buf);
    var storage: [32]HttpHeader = undefined;
    var count: usize = 0;

    while (it.next()) |h| {
        if (count >= storage.len) break; // avoid overflow
        storage[count] = .{ .name = h.name, .value = h.value };
        count += 1;
    }

    return storage[0..count];
}

pub const HttpPacket = struct {
    packet: packet.Packet,
    msg: HttpMsg,

    pub fn init(pkt: packet.Packet) ?HttpPacket {
        std.debug.assert(pkt.transport.? == .tcp); // need to pass in tcp transport packet to parse http
        const payload = pkt.transport.?.tcp.payload;

        if (std.mem.indexOf(u8, payload, "\r\n")) |idx| {
            const method = payload[0..idx];

            if (std.mem.startsWith(u8, method, "HTTP")) {
                const headers = get_headers(payload[idx + 2 ..]);
                const body = payload[headers.len..];
                const resp = HttpResponse{
                    .headers = headers,
                    .body = body,
                    .reason = "blah",
                    .status_code = 200,
                    .version = "blah",
                };

                return HttpPacket{ .msg = HttpMsg{ .response = resp }, .packet = pkt };
            } else {
                return null;
            }
        } else {
            return null;
        }
    }
};
