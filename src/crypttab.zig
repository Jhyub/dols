const std = @import("std");

pub const CrypttabEntry = struct {
    volumeName: []const u8,
    encryptedDevice: []const u8,
    keyFile: ?[]const u8,
    options: ?[]const u8,
};

fn parseCrypttabEntry(line: []const u8) !CrypttabEntry {
    var parts = std.mem.splitSequence(u8, line, " ");
    return CrypttabEntry{
        .volumeName = parts.next().?,
        .encryptedDevice = parts.next().?,
        .keyFile = parts.next(),
        .options = parts.next(),
    };
}

pub fn parseCrypttab(allocator: std.mem.Allocator, crypttab: []const u8) ![]CrypttabEntry {
    var lines = std.mem.splitSequence(u8, crypttab, "\n");
    var list = std.ArrayList(CrypttabEntry).init(allocator);
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (line[0] == '#') continue;
        if (line[0] == '\n') continue;
        const entry = try parseCrypttabEntry(line);
        std.debug.print("{s} {s} {?s} {?s}\n", .{ entry.volumeName, entry.encryptedDevice, entry.keyFile, entry.options });
        try list.append(entry);
    }
    return list.toOwnedSlice();
}