const std = @import("std");

const Args = @This();

device: []const u8,
filter_path: []const u8,
verbose: bool,
list_devices: bool,
it: std.process.ArgIterator,

const Option = enum {
    @"--device",
    @"-d",
    @"--filter-path",
    @"-fp",
    @"--help",
    @"-h",
    @"--list",
    @"-l",
    @"--verbose",
    @"-v",
};

pub fn help(process_name: []const u8) noreturn {
    std.debug.print(
        \\Usage: {s} [OPTIONS]
        \\
        \\OPTIONS:
        \\  -d, --device <name>    Network device to sniff (required)
        \\  -fp, --filter-path     Path to filter config file
        \\  -l, --list             List available network devices
        \\  -v, --verbose          Enable verbose output
        \\  -h, --help             Show this help message
        \\
        \\EXAMPLES:
        \\  {s} -d en0                      # Sniff on device en0
        \\  {s} --list                      # List available devices
        \\  {s} --filter-path filter.txt    # path to filter config file 
        \\
    , .{ process_name, process_name, process_name, process_name });
    std.process.exit(0);
}

pub fn deinit(self: *Args) void {
    self.it.deinit();
}

pub fn parse(allocator: std.mem.Allocator) !Args {
    var args = try std.process.argsWithAllocator(allocator);
    const process_name = args.next() orelse "sniff_zig";

    var device: []const u8 = "";
    var filter_path: []const u8 = "";
    var verbose: bool = false;
    var list_devices: bool = false;

    while (args.next()) |arg| {
        const option = std.meta.stringToEnum(Option, arg) orelse {
            std.debug.print("Error: Unknown option '{s}'\n\n", .{arg});
            help(process_name);
        };

        switch (option) {
            .@"--device", .@"-d" => {
                device = args.next() orelse {
                    std.debug.print("Error: --device/-d requires a device name\n\n", .{});
                    help(process_name);
                };
            },
            .@"--help", .@"-h" => help(process_name),
            .@"--list", .@"-l" => {
                list_devices = true;
            },
            .@"--verbose", .@"-v" => {
                verbose = true;
            },
            .@"--filter-path", .@"-fp" => {
                filter_path = args.next() orelse {
                    std.debug.print("Error: Unknown option '{s}'\n\n", .{arg});
                    help(process_name);
                };
            },
        }
    }

    return .{
        .device = device,
        .filter_path = filter_path,
        .verbose = verbose,
        .list_devices = list_devices,
        .it = args,
    };
}
