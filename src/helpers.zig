const std = @import("std");

const c = @cImport({
    @cInclude("pcap.h");
});

pub fn list_devices() !void {
    var errbuf: [c.PCAP_ERRBUF_SIZE]u8 = undefined;
    var alldevs: ?*c.pcap_if_t = null;

    if (c.pcap_findalldevs(&alldevs, &errbuf) != 0) {
        std.log.err("pcap_findalldevs failed: {s}\n", .{errbuf});
        return;
    }

    std.debug.print("Available network devices (with IPv4 addresses):\n", .{});
    var dev = alldevs;
    var i: u32 = 1;
    while (dev) |d| {
        var has_ipv4 = false;
        var addr = d.addresses;
        while (addr) |a| {
            if (a.*.addr) |sa_ptr| {
                const sa = @as(*const c.struct_sockaddr, @ptrCast(sa_ptr));
                if (sa.sa_family == c.AF_INET) {
                    has_ipv4 = true;
                    break;
                }
            }
            addr = a.*.next;
        }

        if (has_ipv4) {
            const name = std.mem.span(d.name);
            std.debug.print("  {d}. {s}\n", .{ i, name });

            addr = d.addresses;
            std.debug.print("     Addresses:\n", .{});
            while (addr) |a| {
                if (a.*.addr) |sa_ptr| {
                    const sa = @as(*const c.struct_sockaddr, @ptrCast(sa_ptr));
                    if (sa.sa_family == c.AF_INET) {
                        const sin = @as(*const c.struct_sockaddr_in, @ptrCast(@alignCast(sa_ptr)));
                        const ip_addr = @as(*const [4]u8, @ptrCast(&sin.sin_addr.s_addr));
                        std.debug.print("       - IPv4: {d}.{d}.{d}.{d}\n", .{ ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3] });
                    } else if (sa.sa_family == c.AF_INET6) {
                        std.debug.print("       - IPv6: (run `ip addr show` for details)\n", .{});
                    }
                }
                addr = a.*.next;
            }
            std.debug.print("\n", .{});
            i += 1;
        }
        dev = d.next;
    }

    c.pcap_freealldevs(alldevs);
}

const base64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(input: []const u8, output: []u8) []u8 {
    const output_len = ((input.len + 2) / 3) * 4;
    if (output.len < output_len) return output[0..0];

    var i: usize = 0;
    var j: usize = 0;

    while (i + 3 <= input.len) {
        const b0 = input[i];
        const b1 = input[i + 1];
        const b2 = input[i + 2];

        output[j] = base64_alphabet[b0 >> 2];
        output[j + 1] = base64_alphabet[((b0 & 0x03) << 4) | (b1 >> 4)];
        output[j + 2] = base64_alphabet[((b1 & 0x0f) << 2) | (b2 >> 6)];
        output[j + 3] = base64_alphabet[b2 & 0x3f];

        i += 3;
        j += 4;
    }

    const remaining = input.len - i;
    if (remaining == 1) {
        const b0 = input[i];
        output[j] = base64_alphabet[b0 >> 2];
        output[j + 1] = base64_alphabet[(b0 & 0x03) << 4];
        output[j + 2] = '=';
        output[j + 3] = '=';
        j += 4;
    } else if (remaining == 2) {
        const b0 = input[i];
        const b1 = input[i + 1];
        output[j] = base64_alphabet[b0 >> 2];
        output[j + 1] = base64_alphabet[((b0 & 0x03) << 4) | (b1 >> 4)];
        output[j + 2] = base64_alphabet[(b1 & 0x0f) << 2];
        output[j + 3] = '=';
        j += 4;
    }

    return output[0..j];
}
