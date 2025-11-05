const std = @import("std");

const c = @cImport({
    @cInclude("errno.h");
    @cInclude("signal.h");
    @cInclude("time.h");
});

pub const Ask = struct {
    arena: *std.heap.ArenaAllocator,
    echo: bool,
    icon: ?[]const u8,
    message: ?[]const u8,
    not_after: i32,
    pid: u32,
    socket: []const u8,

    const Self = @This();

    pub fn list(allocator: std.mem.Allocator) ![][]const u8 {
        var ret: std.ArrayList([]const u8) = .empty;
        defer ret.deinit(allocator);
        errdefer {
            for (ret.items) |item| {
                allocator.free(item);
            }
        }

        var files = std.fs.cwd().openDir("/run/systemd/ask-password", .{ .iterate = true }) catch return ret.toOwnedSlice(allocator);
        defer files.close();

        var it = files.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.startsWith(u8, entry.name, "ask.")) continue;
            try ret.append(allocator, try allocator.dupe(u8, entry.name));
        }

        return ret.toOwnedSlice(allocator);
    }

    pub fn readFrom(allocator: std.mem.Allocator, file: std.fs.File) !Ask {
        const arena = try allocator.create(std.heap.ArenaAllocator);
        errdefer allocator.destroy(arena);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const arena_allocator = arena.allocator();

        var buf: [4096]u8 = undefined;
        var file_reader = file.reader(&buf);
        const reader = &file_reader.interface;

        var echo: ?bool = null;
        var icon: ?[]const u8 = null;
        var message: ?[]const u8 = null;
        var not_after: ?i32 = null;
        var pid: ?u32 = null;
        var socket: ?[]const u8 = null;

        var is_section_ask = false;
        while (reader.takeDelimiterInclusive('\n')) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r\n");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            if (std.mem.eql(u8, trimmed, "[Ask]")) {
                is_section_ask = true;
                continue;
            }

            if (!is_section_ask) continue;

            if (std.mem.indexOf(u8, trimmed, "=")) |eq_pos| {
                const key = std.mem.trim(u8, trimmed[0..eq_pos], " \t");
                const value = std.mem.trim(u8, trimmed[eq_pos + 1 ..], " \t");

                if (std.mem.eql(u8, key, "Echo")) {
                    echo = !std.mem.eql(u8, value, "0");
                } else if (std.mem.eql(u8, key, "Icon")) {
                    icon = arena_allocator.dupe(u8, value) catch null;
                } else if (std.mem.eql(u8, key, "Message")) {
                    message = arena_allocator.dupe(u8, value) catch null;
                } else if (std.mem.eql(u8, key, "NotAfter")) {
                    not_after = std.fmt.parseInt(i32, value, 10) catch 0;
                } else if (std.mem.eql(u8, key, "PID")) {
                    pid = std.fmt.parseInt(u32, value, 10) catch 0;
                } else if (std.mem.eql(u8, key, "Socket")) {
                    socket = arena_allocator.dupe(u8, value) catch return error.InvalidSocket;
                }
            }
        } else |err| {
            switch (err) {
                error.EndOfStream => {},
                else => {
                    return err;
                },
            }
        }

        return Ask{
            .arena = arena,
            .echo = echo orelse false,
            .icon = icon,
            .message = message,
            .not_after = not_after orelse 0,
            .pid = pid orelse return error.InvalidPID,
            .socket = socket orelse return error.InvalidSocket,
        };
    }

    pub fn answer(self: *const Self, allocator: std.mem.Allocator, password: []const u8, was_entry_successful: bool, ignore_skip: bool) !void {
        const kill_ret = c.kill(@intCast(self.pid), 0);
        if (kill_ret == c.ESRCH and !ignore_skip) {
            return error.NoSuchProcess;
        }

        if (self.not_after != 0) {
            var timespec: c.struct_timespec = .{};
            const gettime_ret = c.clock_gettime(c.CLOCK_MONOTONIC, &timespec);
            if (gettime_ret != 0) return error.GetTimeFailed;
            if (@divTrunc(@as(i64, timespec.tv_nsec), 1000) > @as(i64, self.not_after) and !ignore_skip) {
                return error.Timeout;
            }
        }

        const sockfd = try std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.DGRAM, 0);
        const addr = try std.net.Address.initUnix(self.socket);
        try std.posix.connect(sockfd, &addr.any, addr.getOsSockLen());
        const socket = std.net.Stream{ .handle = sockfd };
        defer socket.close();
        var buf: [1024]u8 = undefined;
        var sock_writer = socket.writer(&buf);
        const writer = &sock_writer.interface;

        const msg = blk: {
            if (was_entry_successful) {
                break :blk try std.fmt.allocPrint(allocator, "+{s}\x00", .{password});
            } else {
                break :blk try std.fmt.allocPrint(allocator, "-{s}\x00", .{password});
            }
        };
        defer allocator.free(msg);

        try writer.writeAll(msg);
        try writer.flush(); // not sure why we need this seperately
    }

    pub fn deinit(self: *const Self) void {
        const allocator = self.arena.child_allocator;
        self.arena.deinit();
        allocator.destroy(self.arena);
    }
};
