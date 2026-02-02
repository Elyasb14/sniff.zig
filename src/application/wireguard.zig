const std = @import("std");
const helpers = @import("../helpers.zig");

pub const MsgType = enum(u8) {
    handshake_initiation = 1,
    handshake_response = 2,
    cookie_reply = 3,
    transport_data = 4,
};

pub const HandshakeInitiation = struct {
    sender: u32,
    ephemeral: [32]u8,
    encrypted_static: [48]u8,
    encrypted_timestamp: [28]u8,
    mac1: [16]u8,
    mac2: [16]u8,
};

pub const HandshakeResponse = struct {
    sender: u32,
    receiver: u32,
    ephemeral: [32]u8,
    encrypted_empty: [16]u8,
    mac1: [16]u8,
    mac2: [16]u8,
};

pub const CookieReply = struct {
    receiver: u32,
    nonce: [24]u8,
    encrypted_cookie: [32]u8,
};

pub const TransportData = struct {
    receiver: u32,
    counter: u64,
    encrypted_len: usize,
};

pub const MessageData = union(MsgType) {
    handshake_initiation: HandshakeInitiation,
    handshake_response: HandshakeResponse,
    cookie_reply: CookieReply,
    transport_data: TransportData,
};

pub const WireGuardPacket = struct {
    data: MessageData,

    pub fn is_wireguard(payload: []const u8) bool {
        if (payload.len < 4) return false;

        const msg_type = payload[0];
        const reserved_zero = payload[1] == 0 and payload[2] == 0 and payload[3] == 0;

        return switch (msg_type) {
            1 => payload.len == 148,
            2 => payload.len == 92,
            3 => payload.len == 64 and reserved_zero,
            4 => payload.len >= 32 and reserved_zero,
            else => false,
        };
    }

    pub fn init(payload: []const u8) ?WireGuardPacket {
        if (payload.len < 4) return null;

        const msg_type = std.meta.intToEnum(MsgType, payload[0]) catch return null;

        switch (msg_type) {
            .handshake_initiation => {
                if (payload.len != 148) return null;
                return WireGuardPacket{
                    .data = .{ .handshake_initiation = .{
                        .sender = std.mem.readInt(u32, payload[4..8], .little),
                        .ephemeral = payload[8..40].*,
                        .encrypted_static = payload[40..88].*,
                        .encrypted_timestamp = payload[88..116].*,
                        .mac1 = payload[116..132].*,
                        .mac2 = payload[132..148].*,
                    } },
                };
            },
            .handshake_response => {
                if (payload.len != 92) return null;
                return WireGuardPacket{
                    .data = .{ .handshake_response = .{
                        .sender = std.mem.readInt(u32, payload[4..8], .little),
                        .receiver = std.mem.readInt(u32, payload[8..12], .little),
                        .ephemeral = payload[12..44].*,
                        .encrypted_empty = payload[44..60].*,
                        .mac1 = payload[60..76].*,
                        .mac2 = payload[76..92].*,
                    } },
                };
            },
            .cookie_reply => {
                if (payload.len != 64) return null;
                return WireGuardPacket{
                    .data = .{ .cookie_reply = .{
                        .receiver = std.mem.readInt(u32, payload[4..8], .little),
                        .nonce = payload[8..32].*,
                        .encrypted_cookie = payload[32..64].*,
                    } },
                };
            },
            .transport_data => {
                if (payload.len < 32) return null;
                return WireGuardPacket{
                    .data = .{ .transport_data = .{
                        .receiver = std.mem.readInt(u32, payload[4..8], .little),
                        .counter = std.mem.readInt(u64, payload[8..16], .little),
                        .encrypted_len = payload.len - 16,
                    } },
                };
            },
        }
    }

    pub fn msg_type_name(self: WireGuardPacket) []const u8 {
        return switch (self.data) {
            .handshake_initiation => "Handshake Initiation",
            .handshake_response => "Handshake Response",
            .cookie_reply => "Cookie Reply",
            .transport_data => "Transport Data",
        };
    }

    pub fn pp(self: WireGuardPacket, writer: anytype) !void {
        try writer.print("WireGuard [{s}]:\n", .{self.msg_type_name()});

        switch (self.data) {
            .handshake_initiation => |hi| {
                var b64_buf: [44]u8 = undefined;
                const ephemeral_b64 = helpers.base64_encode(&hi.ephemeral, &b64_buf);

                try writer.print("  sender: 0x{x:0>8}\n", .{hi.sender});
                try writer.print("  ephemeral: {s}\n", .{ephemeral_b64});
                try writer.print("  encrypted static: ({d} bytes)\n", .{hi.encrypted_static.len});
                try writer.print("  encrypted timestamp: ({d} bytes)\n", .{hi.encrypted_timestamp.len});
                try writer.print("  mac1: ", .{});
                for (hi.mac1) |b| try writer.print("{x:0>2} ", .{b});
                try writer.print("\n", .{});
                try writer.print("  mac2: ", .{});
                for (hi.mac2) |b| try writer.print("{x:0>2} ", .{b});
                try writer.print("\n", .{});
            },
            .handshake_response => |hr| {
                var b64_buf: [44]u8 = undefined;
                const ephemeral_b64 = helpers.base64_encode(&hr.ephemeral, &b64_buf);

                try writer.print("  sender: 0x{x:0>8}\n", .{hr.sender});
                try writer.print("  receiver: 0x{x:0>8}\n", .{hr.receiver});
                try writer.print("  ephemeral: {s}\n", .{ephemeral_b64});
                try writer.print("  encrypted empty: ({d} bytes)\n", .{hr.encrypted_empty.len});
                try writer.print("  mac1: ", .{});
                for (hr.mac1) |b| try writer.print("{x:0>2} ", .{b});
                try writer.print("\n", .{});
                try writer.print("  mac2: ", .{});
                for (hr.mac2) |b| try writer.print("{x:0>2} ", .{b});
                try writer.print("\n", .{});
            },
            .cookie_reply => |cr| {
                try writer.print("  receiver: 0x{x:0>8}\n", .{cr.receiver});
                try writer.print("  nonce: ", .{});
                for (cr.nonce) |b| try writer.print("{x:0>2} ", .{b});
                try writer.print("\n", .{});
                try writer.print("  encrypted cookie: ({d} bytes)\n", .{cr.encrypted_cookie.len});
            },
            .transport_data => |td| {
                try writer.print("  receiver: 0x{x:0>8}\n", .{td.receiver});
                try writer.print("  counter: {d}\n", .{td.counter});
                try writer.print("  encrypted: {d} bytes\n", .{td.encrypted_len});
            },
        }
    }
};
