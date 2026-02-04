const std = @import("std");

const Args = @This();

device: []const u8,
config_path: []const u8,
verbose: bool,
list_devices: bool,

// Transport filters
tcp: bool,
udp: bool,
icmp: bool,
can: bool,

// application filters
wireguard: bool,

// IP/port filters
src_ip: ?[]const u8 = null,
dst_ip: ?[]const u8 = null,
src_port: ?[]const u8 = null,
dst_port: ?[]const u8 = null,

it: std.process.ArgIterator,

const Option = enum {
    @"--device",
    @"-d",
    @"--config",
    @"--help",
    @"-h",
    @"--list",
    @"-l",
    @"--verbose",
    @"-v",
    @"--tcp",
    @"--udp",
    @"--icmp",
    @"--can",
    @"--src-ip",
    @"--dst-ip",
    @"--src-port",
    @"--dst-port",
    @"--wireguard",
};

pub fn help(process_name: []const u8) noreturn {
    std.debug.print(
        \\Usage: {s} [OPTIONS]
        \\
        \\OPTIONS:
        \\  -d, --device <name>    Network device to sniff (required)
        \\  --config <file>        Load filter defaults from config file
        \\  -l, --list             List available network devices
        \\  -v, --verbose          Enable verbose output
        \\  -h, --help             Show this help message
        \\
        \\TRANSPORT FILTERS:
        \\  --tcp                  Show only TCP packets
        \\  --udp                  Show only UDP packets
        \\  --icmp                 Show only ICMP packets
        \\  --can                  Show only CAN packets
        \\APPLICATION FILTERS
        \\  --wireguard            Show only wireguard packets
        \\
        \\IP/PORT FILTERS:
        \\  --src-ip <address>     Filter by source IP address
        \\  --dst-ip <address>     Filter by destination IP address
        \\  --src-port <port>      Filter by source port
        \\  --dst-port <port>      Filter by destination port
        \\
        \\EXAMPLES:
        \\  {s} -d en0                      # Sniff on device en0
        \\  {s} -d en0 --tcp               # Only TCP packets
        \\  {s} -d en0 --tcp --dst-port 80 # TCP port 80 traffic
        \\  {s} -d en0 --config filter.txt # Use config file defaults
        \\
    , .{ process_name, process_name, process_name, process_name, process_name });
    std.process.exit(0);
}

pub fn deinit(self: *Args) void {
    self.it.deinit();
}

pub fn parse(allocator: std.mem.Allocator) !Args {
    var args = try std.process.argsWithAllocator(allocator);
    const process_name = args.next() orelse "sniff_zig";

    var device: []const u8 = "";
    var config_path: []const u8 = "";
    var verbose: bool = false;
    var list_devices: bool = false;

    // Transport filters
    var tcp: bool = false;
    var udp: bool = false;
    var icmp: bool = false;
    var can: bool = false;

    var wireguard: bool = false;

    // IP/port filters
    var src_ip: ?[]const u8 = null;
    var dst_ip: ?[]const u8 = null;
    var src_port: ?[]const u8 = null;
    var dst_port: ?[]const u8 = null;

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
            .@"--config" => {
                config_path = args.next() orelse {
                    std.debug.print("Error: --config requires a file path\n\n", .{});
                    help(process_name);
                };
            },
            .@"--tcp" => {
                tcp = true;
            },
            .@"--udp" => {
                udp = true;
            },
            .@"--icmp" => {
                icmp = true;
            },
            .@"--can" => {
                can = true;
            },
            .@"--src-ip" => {
                src_ip = args.next() orelse {
                    std.debug.print("Error: --src-ip requires an IP address\n\n", .{});
                    help(process_name);
                };
            },
            .@"--dst-ip" => {
                dst_ip = args.next() orelse {
                    std.debug.print("Error: --dst-ip requires an IP address\n\n", .{});
                    help(process_name);
                };
            },
            .@"--src-port" => {
                src_port = args.next() orelse {
                    std.debug.print("Error: --src-port requires a port number\n\n", .{});
                    help(process_name);
                };
            },
            .@"--dst-port" => {
                dst_port = args.next() orelse {
                    std.debug.print("Error: --dst-port requires a port number\n\n", .{});
                    help(process_name);
                };
            },
            .@"--wireguard" => {
                wireguard = true;
            },
        }
    }

    return .{
        .device = device,
        .config_path = config_path,
        .verbose = verbose,
        .list_devices = list_devices,
        .tcp = tcp,
        .udp = udp,
        .icmp = icmp,
        .can = can,
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .wireguard = wireguard,
        .it = args,
    };
}
