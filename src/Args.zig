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
src_ips: ?[][]const u8 = null,
dst_ips: ?[][]const u8 = null,
src_ports: ?[][]const u8 = null,
dst_ports: ?[][]const u8 = null,

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
    var src_ips_list: ?std.ArrayListUnmanaged([]const u8) = null;
    var dst_ips_list: ?std.ArrayListUnmanaged([]const u8) = null;
    var src_ports_list: ?std.ArrayListUnmanaged([]const u8) = null;
    var dst_ports_list: ?std.ArrayListUnmanaged([]const u8) = null;

    // Defer cleanup in case of error
    errdefer if (src_ips_list) |*l| l.deinit(allocator);
    errdefer if (dst_ips_list) |*l| l.deinit(allocator);
    errdefer if (src_ports_list) |*l| l.deinit(allocator);
    errdefer if (dst_ports_list) |*l| l.deinit(allocator);

    var collector: ?std.ArrayListUnmanaged([]const u8) = null;

    while (args.next()) |arg| {
        if (collector) |*coll| {
            if (std.meta.stringToEnum(Option, arg) != null) {
                collector = null;
            } else {
                try coll.append(allocator, arg);
                continue;
            }
        }

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
            // Multi-value flags (start collecting)
            .@"--src-ip" => {
                if (src_ips_list == null) src_ips_list = .{};
                collector = src_ips_list.?;
            },
            .@"--dst-ip" => {
                if (dst_ips_list == null) dst_ips_list = .{};
                collector = dst_ips_list.?;
            },
            .@"--src-port" => {
                if (src_ports_list == null) src_ports_list = .{};
                collector = src_ports_list.?;
            },
            .@"--dst-port" => {
                if (dst_ports_list == null) dst_ports_list = .{};
                collector = dst_ports_list.?;
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
        .src_ips = if (src_ips_list) |*l| try l.toOwnedSlice(allocator) else &[_][]const u8{},
        .dst_ips = if (dst_ips_list) |*l| try l.toOwnedSlice(allocator) else &[_][]const u8{},
        .src_ports = if (src_ports_list) |*l| try l.toOwnedSlice(allocator) else &[_][]const u8{},
        .dst_ports = if (dst_ports_list) |*l| try l.toOwnedSlice(allocator) else &[_][]const u8{},
        .wireguard = wireguard,
        .it = args,
    };
}
