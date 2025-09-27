const std = @import("std");

pub const CrypttabEntry = struct {
    allocator: *const std.mem.Allocator,
    volumeName: [:0]const u8,
    encryptedDevice: [:0]const u8,
    keyFile: ?[:0]const u8,
    options: ?[:0]const u8,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, line: []const u8) !Self {
        var parts = std.mem.splitSequence(u8, line, " ");
        return Self{
            .allocator = &allocator,
            .volumeName = try allocator.dupeZ(u8, parts.next().?),
            .encryptedDevice = try allocator.dupeZ(u8, parts.next().?),
            .keyFile = if (parts.next()) |p| try allocator.dupeZ(u8, p) else null,
            .options = if (parts.next()) |p| try allocator.dupeZ(u8, p) else null,
        };
    }

    pub fn deinit(self: *const Self) void {
        self.allocator.free(self.volumeName);
        self.allocator.free(self.encryptedDevice);
        if (self.keyFile) |keyFile| {
            self.allocator.free(keyFile);
        }
        if (self.options) |options| {
            self.allocator.free(options);
        }
    }
};

pub fn parseCrypttab(allocator: std.mem.Allocator, crypttab: []const u8) ![]CrypttabEntry {
    var lines = std.mem.splitSequence(u8, crypttab, "\n");
    var list: std.ArrayList(CrypttabEntry) = .empty;
    defer list.deinit(allocator);
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (line[0] == '#') continue;
        if (line[0] == '\n') continue;
        const entry = try CrypttabEntry.init(allocator, line);
        try list.append(allocator, entry);
    }
    return list.toOwnedSlice(allocator);
}
