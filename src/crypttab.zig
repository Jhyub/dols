const std = @import("std");

pub const CrypttabEntry = struct {
    volumeName: [:0]const u8,
    encryptedDevice: [:0]const u8,
    keyFile: ?[:0]const u8,
    options: ?[:0]const u8,
};

fn parseCrypttabEntry(allocator: std.mem.Allocator, line: []const u8) !CrypttabEntry {
    var parts = std.mem.splitSequence(u8, line, " ");
    return CrypttabEntry{
        .volumeName = try allocator.dupeZ(u8, parts.next().?),
        .encryptedDevice = try allocator.dupeZ(u8, parts.next().?),
        .keyFile = if (parts.next()) |p| try allocator.dupeZ(u8, p) else null,
        .options = if (parts.next()) |p| try allocator.dupeZ(u8, p) else null,
    };
}

pub fn parseCrypttab(allocator: std.mem.Allocator, crypttab: []const u8) ![]CrypttabEntry {
    var lines = std.mem.splitSequence(u8, crypttab, "\n");
    var list = std.ArrayList(CrypttabEntry).init(allocator);
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (line[0] == '#') continue;
        if (line[0] == '\n') continue;
        const entry = try parseCrypttabEntry(allocator, line);
        std.debug.print("{s} {s} {?s} {?s}\n", .{ entry.volumeName, entry.encryptedDevice, entry.keyFile, entry.options });
        try list.append(entry);
    }
    return list.toOwnedSlice();
}

pub fn freeCrypttab(allocator: std.mem.Allocator, entries: []CrypttabEntry) void {
    for (entries) |entry| {
        allocator.free(entry.volumeName);
        allocator.free(entry.encryptedDevice);
        if (entry.keyFile) |keyFile| {
            allocator.free(keyFile);
        }
        if (entry.options) |options| {
            allocator.free(options);
        }
    }
}
