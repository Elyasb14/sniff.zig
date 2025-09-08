const std = @import("std");
const transport = @import("../transport.zig");

const HttpHeader = struct {
    name: []const u8,
    value: []const u8,
};

const HttpHeaders = []const HttpHeader;

const HttpRequest = struct {
    method: []const u8,
    target: []const u8,
    version: []const u8,
    body: []const u8,
    headers: HttpHeaders,
};

const HttpResponse = struct {
    version: []const u8,
    reason: []const u8,
    body: []const u8,
    headers: HttpHeaders,
    status_code: u16,
};

const HttpMsg = union(enum) { request: HttpRequest, response: HttpResponse };

pub const HttpPacket = struct {
    packet: transport.Packet,
    msg: HttpMsg,

    fn get_headers(buf: []const u8) HttpHeaders {
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

    pub fn init(pkt: transport.Packet) HttpPacket {
        std.debug.assert(pkt.transport.? == .tcp); // need to pass in tcp transport packet to parse http
        const payload = pkt.transport.?.tcp.payload;

        if (std.mem.indexOf(u8, payload, "\r\n")) |idx| {
            const method = payload[0..idx];
            std.debug.print("method: {s}\n", .{method});

            if (std.mem.startsWith(u8, method, "HTTP")) {
                const headers = get_headers(payload[idx + 2 ..]);
                const resp = HttpResponse{ .headers = headers };

                return HttpPacket{ .msg = resp, .packet = pkt };
            } else {
                return;
            }
        } else {
            std.debug.print("not HTTP (no CRLF)\n", .{});
        }
    }
};
