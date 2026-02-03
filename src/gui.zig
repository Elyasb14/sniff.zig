const std = @import("std");
const rl = @cImport({
    @cInclude("raylib.h");
});
const packet = @import("packet.zig");

const MAX_PACKETS = 1000;
const PACKET_ITEM_HEIGHT = 60;
const WINDOW_WIDTH = 1200;
const WINDOW_HEIGHT = 800;

const PacketEntry = struct {
    timestamp: i64,
    summary: [256]u8,
    full_packet: packet.Packet,
};

pub const PacketGui = struct {
    allocator: std.mem.Allocator,
    packets: std.ArrayListUnmanaged(PacketEntry),
    scroll_y: f32,
    selected_index: ?usize,
    font_size: i32,

    pub fn init(allocator: std.mem.Allocator) PacketGui {
        return .{
            .allocator = allocator,
            .packets = .{},
            .scroll_y = 0,
            .selected_index = null,
            .font_size = 14,
        };
    }

    pub fn deinit(self: *PacketGui) void {
        self.packets.deinit(self.allocator);
    }

    pub fn add_packet(self: *PacketGui, pkt: packet.Packet) !void {
        if (self.packets.items.len >= MAX_PACKETS) {
            _ = self.packets.orderedRemove(0);
        }

        var entry: PacketEntry = .{
            .timestamp = std.time.timestamp(),
            .summary = undefined,
            .full_packet = pkt,
        };

        var summary_buf: [256]u8 = undefined;
        const summary = try format_packet_summary(&summary_buf, pkt);
        @memcpy(entry.summary[0..summary.len], summary);
        entry.summary[summary.len] = 0;

        try self.packets.append(self.allocator, entry);
    }

    pub fn run(self: *PacketGui) void {
        rl.InitWindow(WINDOW_WIDTH, WINDOW_HEIGHT, "sniff - Packet Capture");
        defer rl.CloseWindow();

        rl.SetTargetFPS(60);

        while (!rl.WindowShouldClose()) {
            self.handle_input();
            self.draw();
        }
    }

    pub fn draw(self: *PacketGui) void {
        rl.BeginDrawing();
        defer rl.EndDrawing();

        rl.ClearBackground(rl.BLACK);

        self.draw_header();
        self.draw_packet_list();
        self.draw_details();
        self.draw_scrollbar();
    }

    pub fn handle_input(self: *PacketGui) void {
        const wheel = rl.GetMouseWheelMove();
        if (wheel != 0) {
            self.scroll_y += wheel * 30;
            const max_scroll = @as(f32, @floatFromInt(self.packets.items.len)) * PACKET_ITEM_HEIGHT - (WINDOW_HEIGHT - 100);
            if (self.scroll_y < 0) self.scroll_y = 0;
            if (self.scroll_y > max_scroll and max_scroll > 0) self.scroll_y = max_scroll;
        }

        if (rl.IsMouseButtonPressed(rl.MOUSE_LEFT_BUTTON)) {
            const mouse_y = rl.GetMouseY();
            if (mouse_y > 50 and mouse_y < WINDOW_HEIGHT - 200) {
                const y_pos = @as(f32, @floatFromInt(mouse_y - 50)) + self.scroll_y;
                const index = @as(usize, @intFromFloat(y_pos / PACKET_ITEM_HEIGHT));
                if (index < self.packets.items.len) {
                    self.selected_index = index;
                }
            }
        }
    }

    fn draw_header(self: *PacketGui) void {
        rl.DrawRectangle(0, 0, WINDOW_WIDTH, 50, rl.DARKGRAY);
        rl.DrawText("sniff - Live Packet Capture", 10, 15, 20, rl.RAYWHITE);

        var count_buf: [64]u8 = undefined;
        const count_text = std.fmt.bufPrintZ(&count_buf, "Packets: {d}", .{self.packets.items.len}) catch "Packets: 0";
        rl.DrawText(count_text.ptr, WINDOW_WIDTH - 150, 15, 16, rl.LIGHTGRAY);
    }

    fn draw_packet_list(self: *PacketGui) void {
        const list_height = WINDOW_HEIGHT - 250;
        rl.DrawRectangle(0, 50, WINDOW_WIDTH, list_height, rl.BLACK);

        var i: usize = 0;
        while (i < self.packets.items.len) : (i += 1) {
            const y = @as(f32, @floatFromInt(i)) * PACKET_ITEM_HEIGHT - self.scroll_y + 50;

            if (y < -PACKET_ITEM_HEIGHT or y > list_height + 50) continue;

            const entry = self.packets.items[i];
            const is_selected = self.selected_index == i;

            const bg_color = if (is_selected) rl.DARKBLUE else if (i % 2 == 0) rl.BLACK else rl.Color{ .r = 20, .g = 20, .b = 20, .a = 255 };
            rl.DrawRectangle(0, @as(i32, @intFromFloat(y)), WINDOW_WIDTH, PACKET_ITEM_HEIGHT, bg_color);

            rl.DrawLine(0, @as(i32, @intFromFloat(y + PACKET_ITEM_HEIGHT)), WINDOW_WIDTH, @as(i32, @intFromFloat(y + PACKET_ITEM_HEIGHT)), rl.DARKGRAY);

            const summary = std.mem.sliceTo(&entry.summary, 0);
            rl.DrawText(summary.ptr, 10, @as(i32, @intFromFloat(y + 20)), self.font_size, rl.LIGHTGRAY);
        }
    }

    fn draw_details(self: *PacketGui) void {
        const details_y = WINDOW_HEIGHT - 200;
        rl.DrawRectangle(0, details_y, WINDOW_WIDTH, 200, rl.DARKGRAY);
        rl.DrawLine(0, details_y, WINDOW_WIDTH, details_y, rl.GRAY);

        if (self.selected_index) |idx| {
            if (idx < self.packets.items.len) {
                const entry = self.packets.items[idx];
                var buf: [1024]u8 = undefined;
                const details = format_packet_details(&buf, entry.full_packet) catch "Error formatting";
                rl.DrawText("Packet Details:", 10, details_y + 10, 16, rl.RAYWHITE);
                rl.DrawText(details.ptr, 10, details_y + 35, 12, rl.LIGHTGRAY);
            }
        } else {
            rl.DrawText("Select a packet to view details", 10, details_y + 80, 16, rl.GRAY);
        }
    }

    fn draw_scrollbar(self: *PacketGui) void {
        const list_height = WINDOW_HEIGHT - 250;
        const total_height = @as(f32, @floatFromInt(self.packets.items.len)) * PACKET_ITEM_HEIGHT;

        if (total_height > list_height) {
            const scrollbar_height = (list_height / total_height) * list_height;
            const scrollbar_y = (self.scroll_y / total_height) * list_height + 50;

            rl.DrawRectangle(WINDOW_WIDTH - 10, @as(i32, @intFromFloat(scrollbar_y)), 8, @as(i32, @intFromFloat(scrollbar_height)), rl.GRAY);
        }
    }
};

fn format_packet_summary(buf: []u8, pkt: packet.Packet) ![]const u8 {
    var stream = std.io.fixedBufferStream(buf);
    const writer = stream.writer();

    if (pkt.ethernet) |eth| {
        try writer.print("ETH {x:0>4} | ", .{eth.ether_type});
    }

    if (pkt.ipv4) |ip| {
        try writer.print("{d}.{d}.{d}.{d} -> {d}.{d}.{d}.{d} | ", .{
            ip.src_addr[0], ip.src_addr[1], ip.src_addr[2], ip.src_addr[3],
            ip.dst_addr[0], ip.dst_addr[1], ip.dst_addr[2], ip.dst_addr[3],
        });
    }

    if (pkt.transport) |tpt| {
        switch (tpt) {
            .tcp => |tcp| try writer.print("TCP {d} -> {d}", .{ tcp.src_port, tcp.dst_port }),
            .udp => |udp| try writer.print("UDP {d} -> {d}", .{ udp.src_port, udp.dst_port }),
            .icmp => try writer.print("ICMP", .{}),
            .can => |can| try writer.print("CAN 0x{x}", .{can.id}),
            else => try writer.print("Unknown", .{}),
        }
    }

    return stream.getWritten();
}

fn format_packet_details(buf: []u8, pkt: packet.Packet) ![:0]const u8 {
    var stream = std.io.fixedBufferStream(buf);
    const writer = stream.writer();

    if (pkt.ethernet) |eth| {
        try writer.print("Ethernet: SRC={x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2} DST={x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2} Type=0x{x}\n", .{
            eth.src_mac[0], eth.src_mac[1], eth.src_mac[2], eth.src_mac[3], eth.src_mac[4], eth.src_mac[5],
            eth.dst_mac[0], eth.dst_mac[1], eth.dst_mac[2], eth.dst_mac[3], eth.dst_mac[4], eth.dst_mac[5],
            eth.ether_type,
        });
    }

    if (pkt.ipv4) |ip| {
        try writer.print("IPv4: {d}.{d}.{d}.{d} -> {d}.{d}.{d}.{d} TTL={d} Protocol={d}\n", .{
            ip.src_addr[0], ip.src_addr[1], ip.src_addr[2], ip.src_addr[3],
            ip.dst_addr[0], ip.dst_addr[1], ip.dst_addr[2], ip.dst_addr[3],
            ip.ttl,         ip.protocol,
        });
    }

    if (pkt.transport) |tpt| {
        switch (tpt) {
            .tcp => |tcp| try writer.print("TCP: {d} -> {d} SEQ={d} ACK={d}", .{ tcp.src_port, tcp.dst_port, tcp.seq_number, tcp.ack_number }),
            .udp => |udp| try writer.print("UDP: {d} -> {d} LEN={d}", .{ udp.src_port, udp.dst_port, udp.length }),
            .icmp => try writer.print("ICMP", .{}),
            .can => |can| try writer.print("CAN: ID=0x{x} DLC={d}", .{ can.id, can.dlc }),
            else => try writer.print("Unknown transport", .{}),
        }
    }

    const written = stream.getWritten();
    return written[0..written.len :0];
}
