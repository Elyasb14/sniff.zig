const std = @import("std");
const packet = @import("packet.zig");

pub const Filter = struct {
    allocator: std.mem.Allocator,
    filter_map: std.StringHashMap(std.ArrayList([]const u8)),

    pub fn init(allocator: std.mem.Allocator) Filter {
        return Filter{
            .allocator = allocator,
            .filter_map = std.StringHashMap(std.ArrayList([]const u8)).init(allocator),
        };
    }

    pub fn deinit(self: *Filter) void {
        var iterator = self.filter_map.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.*.deinit(self.allocator);
        }
        self.filter_map.deinit();
    }

    pub fn loadFromFile(self: *Filter, path: []const u8) !void {
        const file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
            error.FileNotFound => {
                std.log.err("Can't find provided filter config file: {s}", .{path});
                return error.FileNotFound;
            },
            else => return err,
        };
        defer file.close();

        var file_buf: [1024]u8 = undefined;
        const n = try file.read(&file_buf);

        var file_it = std.mem.splitAny(u8, file_buf[0..n], "\n");
        while (file_it.next()) |line| {
            if (line.len == 0) continue;
            var line_it = std.mem.splitAny(u8, line, "=");
            const key = line_it.next() orelse continue;
            const value = line_it.next() orelse "";

            const trimmed_key = std.mem.trim(u8, key, " \t");
            const trimmed_value = std.mem.trim(u8, value, " \t");

            const gop = try self.filter_map.getOrPut(trimmed_key);
            if (!gop.found_existing) {
                gop.value_ptr.* = try std.ArrayList([]const u8).initCapacity(self.allocator, 1024);
            }
            try gop.value_ptr.append(self.allocator, trimmed_value);
        }
    }

    pub fn logFilters(self: Filter) void {
        var iterator = self.filter_map.iterator();
        while (iterator.next()) |entry| {
            std.log.info("KEY: {s} ({d} values)", .{ entry.key_ptr.*, entry.value_ptr.items.len });
            for (entry.value_ptr.items) |value| {
                std.log.info("  {s}", .{value});
            }
        }
    }

    // TODO: Implement this function to check if a packet matches the filter criteria
    // Should return true if packet should be shown, false if it should be filtered out
    pub fn matches(self: Filter, pkt: packet.Packet) bool {
        _ = self;
        _ = pkt;
        return true; // Show all packets for now - implement filtering logic here
    }
};
