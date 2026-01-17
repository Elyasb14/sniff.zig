const std = @import("std");

const Filter = @This();

contents: []u8,

pub fn init(filter_path: []const u8) !?Filter {
    const file = std.fs.cwd().openFile(filter_path, .{}) catch |err| switch (err) {
        error.FileNotFound => {
            std.log.err("Can't find provided filter config file: {s}", .{filter_path});
            return null;
        },
        else => return err,
    };

    var buf: [1024]u8 = undefined;
    const n = try file.read(&buf);

    return .{ .contents = buf[0..n] };
}
