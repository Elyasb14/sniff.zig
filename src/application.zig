const std = @import("std");
const transport = @import("transport.zig");

const KnownPorts = enum(u16) {
    HTTPS = 443,
    HTTP = 80,
    SSH = 22,
};
