const std = @import("std");

const Filter = @This();

buf: [1024]u8,
len: usize,

pub fn init(filter_path: []const u8) !Filter {
    const file = std.fs.cwd().openFile(filter_path, .{}) catch |err| switch (err) {
        error.FileNotFound => {
            std.log.err("Can't find provided filter config file: {s}", .{filter_path});
            return error.FileNotFound;
        },
        else => return err,
    };
    defer file.close();

    var buf: [1024]u8 = undefined;
    const n = try file.read(&buf);

    return .{ .buf = buf, .len = n };
}

pub fn parse_filter(alloc: std.mem.Allocator, self: *Filter) void {
    var it = std.mem.splitAny(u8, self.buf[0..self.len], "\n");

    var keys = std.ArrayList([]const u8).initCapacity(alloc, 1024 / 2);
    var values = std.ArrayList([]const u8).initCapacity(alloc, 1024 / 2);

    while (it.next()) |x| {
        var kv_it = std.mem.splitAny(u8, self.buf[0..self.len], "=");
    }
}
