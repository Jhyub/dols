const std = @import("std");

pub const CrypttabEntry = struct {
    volumeName: [:0]const u8,
    encryptedDevice: [:0]const u8,
    keyFile: ?[:0]const u8,
    options: ?[:0]const u8,

    const Self = @This();

    fn init(allocator: std.mem.Allocator, line: []const u8) !Self {
        var parts = std.mem.splitSequence(u8, line, " ");
        return Self{
            .volumeName = try allocator.dupeZ(u8, parts.next().?),
            .encryptedDevice = try allocator.dupeZ(u8, parts.next().?),
            .keyFile = if (parts.next()) |p| try allocator.dupeZ(u8, p) else null,
            .options = if (parts.next()) |p| try allocator.dupeZ(u8, p) else null,
        };
    }

    fn deinit(self: *const Self, allocator: std.mem.Allocator) void {
        allocator.free(self.volumeName);
        allocator.free(self.encryptedDevice);
        if (self.keyFile) |keyFile| {
            allocator.free(keyFile);
        }
        if (self.options) |options| {
            allocator.free(options);
        }
    }
};

pub fn parseCrypttab(allocator: std.mem.Allocator, crypttab: []const u8) ![]CrypttabEntry {
    var lines = std.mem.splitSequence(u8, crypttab, "\n");
    var list = std.ArrayList(CrypttabEntry).init(allocator);
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (line[0] == '#') continue;
        if (line[0] == '\n') continue;
        const entry = try CrypttabEntry.init(allocator, line);
        try list.append(entry);
    }
    return list.toOwnedSlice();
}

pub fn freeCrypttab(allocator: std.mem.Allocator, entries: []CrypttabEntry) void {
    for (entries) |entry| {
        entry.deinit(allocator);
    }
}
