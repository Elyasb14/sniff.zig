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

test "parse http msg" {
    const example_response =
        "HTTP/1.1 200 OK\r\n" ++
        "Date: Sun, 14 Sep 2025 05:00:00 GMT\r\n" ++
        "Server: ZigTestServer/1.0\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "Content-Length: 13\r\n" ++
        "\r\n" ++
        "Hello, Zig!\n";

    var pkt = packet.Packet{
        .transport = .{
            .tcp = .{
                .payload = example_response,
                // fill in other tcp fields as needed for your Packet type
            },
        },
        // fill in any required Packet fields here
    };

    const http_packet = HttpPacket.init(&pkt) orelse {
        return t.expect(false); // parsing failed
    };

    switch (http_packet.msg) {
        .response => |resp| {
            try t.expectEqualStrings("HTTP/1.1", resp.version);
            try t.expectEqual(@as(u16, 200), resp.status_code);
            try t.expectEqualStrings("Hello, Zig!\n", resp.body);
        },
        .request => {
            return t.expect(false); // shouldn't parse as request here
        },
    }
}
