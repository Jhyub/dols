const std = @import("std");
const config = @import("config.zig");

const c = @cImport({
    @cInclude("ipconfig.h");
});

pub fn ipconfig(allocator: std.mem.Allocator, conf: *const config.Config) !void {
    var argv: std.ArrayList(?[*:0]const u8) = .empty;
    defer argv.deinit(allocator);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();

    try argv.append(allocator, "ipconfig");

    if (conf.ip) |ip| {
        if (ip.timeout) |timeout| {
            try argv.append(allocator, "-t");
            try argv.append(allocator, @as([*:0]const u8, try std.fmt.allocPrintSentinel(arena_allocator, "{d}", .{timeout}, 0)));
        }
        for (ip.interfaces) |interface| {
            try argv.append(allocator, try arena_allocator.dupeZ(u8, interface));
        }
    } // else {
    //    const interface = std.process.getEnvVarOwned(arena_allocator, "ip");
    //    if (interface) |i| {
    //        try argv.append(allocator, try arena_allocator.dupeZ(u8, i));
    //    } else |_| {
    //
    //    }
    //}

    try argv.append(allocator, null);

    const ret = c.ipconfig_main(@intCast(argv.items.len - 1), @ptrCast(argv.items));
    if (ret != 0) {
        return error.IpConfigFailed;
    }
    return;
}
