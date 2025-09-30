const std = @import("std");

pub const CrypttabEntry = struct {
    arena: *std.heap.ArenaAllocator,
    volumeName: [:0]const u8,
    encryptedDevice: [:0]const u8,
    keyFile: ?[:0]const u8,
    options: ?[:0]const u8,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, line: []const u8) !Self {
        const arena = try allocator.create(std.heap.ArenaAllocator);
        errdefer allocator.destroy(arena);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        const arena_allocator = arena.allocator();

        var parts = std.mem.splitSequence(u8, line, " ");
        return Self{
            .arena = arena,
            .volumeName = try arena_allocator.dupeZ(u8, parts.next().?),
            .encryptedDevice = try arena_allocator.dupeZ(u8, parts.next().?),
            .keyFile = if (parts.next()) |p| try arena_allocator.dupeZ(u8, p) else null,
            .options = if (parts.next()) |p| try arena_allocator.dupeZ(u8, p) else null,
        };
    }

    pub fn deinit(self: *const Self) void {
        const allocator = self.arena.child_allocator;
        self.arena.deinit();
        allocator.destroy(self.arena);
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
