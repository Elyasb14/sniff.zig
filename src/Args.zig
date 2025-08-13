const std = @import("std");

const Args = @This();

device: []const u8,
it: std.process.ArgIterator,

const Option = enum {
    @"--device",
    @"--help",
};

fn help(process_name: []const u8) noreturn {
    std.debug.print(
        \\Usage: 
        \\ TODO
        \\ {s}
    , .{process_name});
    std.process.exit(1);
}

pub fn deinit(self: *Args) void {
    self.it.deinit();
}

pub fn parse(allocator: std.mem.Allocator) !Args {
    var args = try std.process.argsWithAllocator(allocator);
    const process_name = args.next() orelse "sniff_zig";

    var device: []const u8 = undefined;

    while (args.next()) |arg| {
        const option = std.meta.stringToEnum(Option, arg) orelse {
            std.debug.print("{s} is not a valid argument\n", .{arg});
            help(process_name);
        };

        switch (option) {
            .@"--device" => {
                device = args.next() orelse {
                    std.debug.print("--device provided with no argument\n", .{});
                    help(process_name);
                };
            },
            .@"--help" => help(process_name),
        }
    }
    return .{
        .device = device,
        .it = args,
    };
}
