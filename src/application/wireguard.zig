const std = @import("std");
const packet = @import("../packet.zig");

pub const WireGuardPacket = struct {
    msg_type: u8,
    sender_index: u32,
    receiver_index: ?u32,
    payload: []const u8,

    pub fn init(buf: [*c]const u8, length: usize) ?WireGuardPacket {
        if (length < 8) return null;

        const msg_type = buf[0];
        const sender_index = std.mem.readInt(u32, buf[4..8], .little);

        var receiver: ?u32 = null;
        var payload_start: usize = 8;

        switch (msg_type) {
            1 => {
                if (length < 8 + 32 + 8 + 24 + 16 + 48) return null;
                payload_start = 8 + 32 + 8 + 24 + 16 + 48;
            },
            2 => {
                if (length < 8 + 4 + 32 + 8 + 24 + 16 + 48) return null;
                receiver = std.mem.readInt(u32, buf[8..12], .little);
                payload_start = 8 + 4 + 32 + 8 + 24 + 16 + 48;
            },
            3 => {
                if (length < 8 + 4 + 32 + 16) return null;
                receiver = std.mem.readInt(u32, buf[8..12], .little);
                payload_start = 8 + 4 + 32 + 16;
            },
            4 => {
                if (length < 8 + 4 + 4) return null;
                receiver = std.mem.readInt(u32, buf[8..12], .little);
                payload_start = 8 + 4 + 4;
            },
            else => return null,
        }

        return WireGuardPacket{
            .msg_type = msg_type,
            .sender_index = sender_index,
            .receiver_index = receiver,
            .payload = buf[payload_start..length],
        };
    }

    pub fn msgTypeName(self: WireGuardPacket) []const u8 {
        return switch (self.msg_type) {
            1 => "Handshake Initiation",
            2 => "Handshake Response",
            3 => "Cookie Reply",
            4 => "Transport Data",
            else => "Unknown",
        };
    }
};
