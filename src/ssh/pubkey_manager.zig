const std = @import("std");

const c = @import("c.zig").c;

pub const PubkeyManager = struct {
    arena: *std.heap.ArenaAllocator,
    keys: std.StringHashMap([]const *c.ssh_key_struct),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, authorized_keys_path: []const u8) !PubkeyManager {
        const arena = try allocator.create(std.heap.ArenaAllocator);
        errdefer allocator.destroy(arena);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const arena_allocator = arena.allocator();

        var path_root = try std.fs.cwd().openDir(authorized_keys_path, .{ .iterate = true });
        defer path_root.close();

        var keys = std.StringHashMap([]const *c.ssh_key_struct).init(arena_allocator);
        errdefer keys.deinit();
        errdefer freeKeys(&keys);

        var it = path_root.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .directory) continue;
            const username = try arena_allocator.dupe(u8, entry.name);

            var path_user = try path_root.openDir(username, .{ .iterate = true });
            defer path_user.close();

            var it_user = path_user.iterate();
            while (try it_user.next()) |entry_user| {
                if (entry_user.kind != .file) continue;
                const key = try parsePubkeyFile(allocator, try path_user.openFile(entry_user.name, .{}));
                try keys.put(username, key);
            }
        }

        return Self{
            .arena = arena,
            .keys = keys,
        };
    }

    fn parsePubkeyFile(allocator: std.mem.Allocator, file: std.fs.File) ![]const *c.ssh_key_struct {
        var buf: [4096]u8 = undefined;
        var file_reader = file.reader(&buf);
        const reader = &file_reader.interface;

        var ret: std.ArrayList(*c.ssh_key_struct) = .empty;
        defer ret.deinit(allocator);

        while (reader.takeDelimiterInclusive('\n')) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            var idx: usize = 0;

            while (idx < trimmed.len) {
                const char = trimmed[idx];
                if (char == ' ' or char == '\t' or char == '\r' or char == '\n' or char == '\x0B') break;
                idx += 1;
            }

            if (idx == trimmed.len) return error.InvalidPubkey;

            const key_type_pos = idx;
            const key_type_str = try allocator.dupeZ(u8, trimmed[0..key_type_pos]);
            defer allocator.free(key_type_str);
            const key_type = c.ssh_key_type_from_name(@ptrCast(key_type_str));

            idx += 1;
            while (idx < trimmed.len) {
                const char = trimmed[idx];
                if (char == ' ' or char == '\t' or char == '\r' or char == '\n' or char == '\x0B') break;
                idx += 1;
            }

            if (idx == trimmed.len) return error.InvalidPubkey;

            const key_pos = idx;
            const key_str = try allocator.dupeZ(u8, trimmed[key_type_pos + 1 .. key_pos]);
            defer allocator.free(key_str);

            var key: *c.ssh_key_struct = undefined;

            const r = c.ssh_pki_import_pubkey_base64(@ptrCast(key_str), key_type, @ptrCast(&key));
            if (r != 0) return error.InvalidPubkey;

            try ret.append(allocator, key);
        } else |err| {
            switch (err) {
                error.EndOfStream => {},
                else => {
                    return err;
                },
            }
        }
        return ret.toOwnedSlice(allocator);
    }

    pub fn freeKeys(keys: *const std.StringHashMap([]const *c.ssh_key_struct)) void {
        var it = keys.valueIterator();
        while (it.next()) |value| {
            for (value.*) |item| {
                c.ssh_key_free(item);
            }
        }
    }

    pub fn hasKey(self: *const Self, username: []const u8, key: *c.ssh_key_struct) bool {
        const keys = self.keys.get(username);
        if (keys == null) return false;
        for (keys.?) |item| {
            if (c.ssh_key_cmp(item, key, c.SSH_KEY_CMP_PUBLIC) == 0) return true;
        }
        return false;
    }

    pub fn deinit(self: *const Self) void {
        const allocator = self.arena.child_allocator;
        freeKeys(&self.keys);
        var it = self.keys.valueIterator();
        while (it.next()) |value| {
            allocator.free(value.*);
        }
        self.arena.deinit();
        allocator.destroy(self.arena);
    }
};
