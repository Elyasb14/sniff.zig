const std = @import("std");

const Filter = @This();

file_contents: []u8,

pub fn init(filter_path: []const u8) !?Filter {
    const file = std.fs.cwd().openFile(filter_path, .{}) catch |err| switch (err) {
        error.FileNotFound => {
            std.log.err("Can't find provided filter config file: {s}", .{filter_path});
            return null;
        },
        else => return err,
    };
    defer file.close();

    var buf: [1024]u8 = undefined;
    const n = try file.read(&buf);

    return .{ .file_contents = buf[0..n] };
}

pub fn parse_filter(self: *Filter) void {
    var it = std.mem.splitAny(u8, self.file_contents, "\n");
    while (it.next()) |x| {
        std.debug.print("LINE: {s}\n", .{x});
    }
}
