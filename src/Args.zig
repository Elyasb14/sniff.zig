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
        \\  ./{s} --address [ip_address] --port [port]
        \\
        \\Options:
        \\  device  The IP address to bind to (default: 127.0.0.1)
        \\  port (optional)        The port to listen on (default: 8080)
        \\Example:
        \\  ./{s} --address 10.0.0.7 --port 9090 
        \\
    , .{ process_name, process_name });
    std.process.exit(1);
}

pub fn deinit(self: *Args) void {
    self.it.deinit();
}

pub fn parse(allocator: std.mem.Allocator) !Args {
    var args = try std.process.argsWithAllocator(allocator);
    const process_name = args.next() orelse "tinyweather-node";

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
