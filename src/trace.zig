const std = @import("std");

const PCAP_MAGIC_MICROSECONDS: u32 = 0xa1b2c3d4;
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const DEFAULT_SNAPLEN: u32 = 262144;

const PcapGlobalHeader = extern struct {
    magic_number: u32 = PCAP_MAGIC_MICROSECONDS,
    version_major: u16 = PCAP_VERSION_MAJOR,
    version_minor: u16 = PCAP_VERSION_MINOR,
    thiszone: i32 = 0,
    sigfigs: u32 = 0,
    snaplen: u32,
    linktype: u32,
};

const PcapPacketHeader = extern struct {
    ts_sec: u32,
    ts_usec: u32,
    caplen: u32,
    origlen: u32,
};

const StoredPacket = struct {
    header: PcapPacketHeader,
    data: []u8,
};

pub const Trace = struct {
    allocator: std.mem.Allocator,
    packets: std.ArrayListUnmanaged(StoredPacket),
    linktype: u32,
    snaplen: u32,

    pub fn init(allocator: std.mem.Allocator, linktype: u32) Trace {
        return .{
            .allocator = allocator,
            .packets = .{},
            .linktype = linktype,
            .snaplen = DEFAULT_SNAPLEN,
        };
    }

    pub fn deinit(self: *Trace) void {
        for (self.packets.items) |pkt| {
            self.allocator.free(pkt.data);
        }
        self.packets.deinit(self.allocator);
    }

    pub fn append(self: *Trace, raw: []const u8, ts_sec: u32, ts_usec: u32) !void {
        const data = try self.allocator.dupe(u8, raw);
        errdefer self.allocator.free(data);

        const caplen: u32 = @intCast(raw.len);
        try self.packets.append(self.allocator, .{
            .header = .{
                .ts_sec = ts_sec,
                .ts_usec = ts_usec,
                .caplen = caplen,
                .origlen = caplen,
            },
            .data = data,
        });
    }

    pub fn packet_count(self: Trace) usize {
        return self.packets.items.len;
    }

    pub fn write_pcap(self: Trace, path: []const u8) !void {
        const file = try std.fs.cwd().createFile(path, .{});
        defer file.close();

        const global_header = PcapGlobalHeader{
            .snaplen = self.snaplen,
            .linktype = self.linktype,
        };
        try file.writeAll(std.mem.asBytes(&global_header));

        for (self.packets.items) |pkt| {
            try file.writeAll(std.mem.asBytes(&pkt.header));
            try file.writeAll(pkt.data);
        }
    }
};
