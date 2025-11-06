const std = @import("std");
const config = @import("config.zig");
const crypttab = @import("crypttab.zig");
const cryptsetup = @import("cryptsetup.zig");
const shadow = @import("shadow.zig");
const sap = @import("systemd_ask_password.zig");

const c = @cImport({
    @cInclude("libssh/libssh.h");
    @cInclude("libssh/server.h");
});

pub fn startSshd(allocator: std.mem.Allocator, conf: *const config.Config, entries: []crypttab.CrypttabEntry) !void {
    defer _ = c.ssh_finalize();
    var auth_try_count: u32 = 0;
    std.debug.print("Starting SSH daemon at port {}...\n", .{conf.port});
    const sshbind = c.ssh_bind_new().?;
    defer c.ssh_bind_free(sshbind);

    const pubkey_manager = try PubkeyManager.init(allocator, "/usr/share/dols/authorized_keys");
    defer pubkey_manager.deinit();

    _ = c.ssh_bind_options_set(sshbind, c.SSH_BIND_OPTIONS_RSAKEY, "/etc/ssh/ssh_host_rsa_key");
    _ = c.ssh_bind_options_set(sshbind, c.SSH_BIND_OPTIONS_ECDSAKEY, "/etc/ssh/ssh_host_ecdsa_key");
    _ = c.ssh_bind_options_set(sshbind, c.SSH_BIND_OPTIONS_BINDPORT, &conf.port);

    while (conf.auth_try_limit == 0 or auth_try_count < conf.auth_try_limit) {
        if (c.ssh_bind_listen(sshbind) < 0) {
            std.debug.print("ssh_bind_listen failed: {s}\n", .{c.ssh_get_error(sshbind)});
            std.debug.print("Failed to listen on port {}\n", .{conf.port});
            return;
        }

        std.debug.print("SSH daemon started on port {}\n", .{conf.port});

        const session = c.ssh_new().?;
        const r = c.ssh_bind_accept(sshbind, session);
        defer c.ssh_disconnect(session);

        if (r == c.SSH_ERROR) {
            std.debug.print("Failed to accept connection: {s}\n", .{c.ssh_get_error(sshbind)});
            continue;
        }

        if (c.ssh_handle_key_exchange(session) != 0) {
            std.debug.print("ssh_handle_key_exchange: {s}\n", .{c.ssh_get_error(session)});
            continue;
        }

        if (!try authenticateUser(allocator, session, &pubkey_manager)) {
            std.debug.print("Authentication failed\n", .{});
            auth_try_count += 1;
            continue;
        }
        std.debug.print("User authenticated successfully\n", .{});

        var idx: usize = 0;
        while (idx < entries.len) {
            if (!try tryDecrypt(allocator, session, &entries[idx])) {
                std.debug.print("Device decrypt failed\n", .{});
                continue;
            }
            idx += 1;
        }

        std.debug.print("All devices decrypted successfully\n", .{});

        try sap.finishSystemdAskPassword(allocator);

        return;
    }
}

fn authenticateUser(allocator: std.mem.Allocator, session: *c.ssh_session_struct, pkm: *const PubkeyManager) !bool {
    var msg: c.ssh_message = undefined;

    const kbdintName = "Welcome to dols, v0.0.0\n";
    const kbdintInstructionFormat = "Enter ssh password for user {s}";
    var kbdintPrompt: [1][*c]const u8 = .{@ptrCast("Password: ")};
    var kbdintEcho = [1]u8{0};

    var username: [:0]const u8 = try allocator.dupeZ(u8, "");
    defer allocator.free(username);

    while (true) {
        msg = c.ssh_message_get(session);
        defer c.ssh_message_free(msg);

        if (c.ssh_message_type(msg) != c.SSH_REQUEST_AUTH) {
            _ = c.ssh_message_auth_set_methods(msg, c.SSH_AUTH_METHOD_INTERACTIVE | c.SSH_AUTH_METHOD_PUBLICKEY);
            _ = c.ssh_message_reply_default(msg);
            continue;
        }

        switch (c.ssh_message_subtype(msg)) {
            c.SSH_AUTH_METHOD_PASSWORD => {
                allocator.free(username);
                username = try allocator.dupeZ(u8, std.mem.span(c.ssh_message_auth_user(msg)));
                const password = std.mem.span(c.ssh_message_auth_password(msg));
                if (shadow.authenticateByUsername(username, password)) {
                    _ = c.ssh_message_auth_reply_success(msg, 1);
                    return true;
                }
                return false;
            },
            c.SSH_AUTH_METHOD_INTERACTIVE => {
                if (c.ssh_message_auth_kbdint_is_response(msg) == 0) {
                    allocator.free(username);
                    username = try allocator.dupeZ(u8, std.mem.span(c.ssh_message_auth_user(msg)));
                    const kbtintInstruction = try std.fmt.allocPrint(allocator, kbdintInstructionFormat, .{username});
                    defer allocator.free(kbtintInstruction);
                    _ = c.ssh_message_auth_interactive_request(msg, kbdintName, @ptrCast(kbtintInstruction), 1, @ptrCast(&kbdintPrompt), @ptrCast(&kbdintEcho));
                } else {
                    if (c.ssh_userauth_kbdint_getnanswers(session) != 1) return false;
                    const reply = std.mem.span(c.ssh_userauth_kbdint_getanswer(session, 0));
                    if (shadow.authenticateByUsername(username, reply)) {
                        _ = c.ssh_message_auth_reply_success(msg, 1);
                        return true;
                    }
                    return false;
                }
            },
            c.SSH_AUTH_METHOD_PUBLICKEY => {
                allocator.free(username);
                username = try allocator.dupeZ(u8, std.mem.span(c.ssh_message_auth_user(msg)));
                const pubkey: *c.ssh_key_struct = c.ssh_message_auth_pubkey(msg) orelse return error.NoPubkeyBody;
                // We do not free the pubkey here, because it seems to be freed when freeing the message itself.
                // defer c.ssh_key_free(pubkey);
                const signature_state = c.ssh_message_auth_publickey_state(msg);
                if (signature_state == c.SSH_PUBLICKEY_STATE_NONE) { // Key probing: "Hello server, do you accept this key?"
                    if (pkm.hasKey(username, pubkey)) {
                        _ = c.ssh_message_auth_set_methods(msg, c.SSH_AUTH_METHOD_PUBLICKEY);
                        _ = c.ssh_message_auth_reply_pk_ok_simple(msg);
                    } else {
                        _ = c.ssh_message_auth_set_methods(msg, c.SSH_AUTH_METHOD_INTERACTIVE | c.SSH_AUTH_METHOD_PUBLICKEY);
                        _ = c.ssh_message_reply_default(msg);
                    }
                    continue;
                } else if (signature_state != c.SSH_PUBLICKEY_STATE_VALID) {
                    _ = c.ssh_message_auth_set_methods(msg, c.SSH_AUTH_METHOD_INTERACTIVE | c.SSH_AUTH_METHOD_PUBLICKEY);
                    _ = c.ssh_message_reply_default(msg);
                    continue;
                }

                if (pkm.hasKey(username, pubkey)) {
                    _ = c.ssh_message_auth_reply_success(msg, 1);
                    return true;
                }
                return false;
            },
            else => {
                allocator.free(username);
                username = try allocator.dupeZ(u8, std.mem.span(c.ssh_message_auth_user(msg)));
                _ = c.ssh_message_auth_set_methods(msg, c.SSH_AUTH_METHOD_INTERACTIVE | c.SSH_AUTH_METHOD_PUBLICKEY);
                _ = c.ssh_message_reply_default(msg);
            },
        }
    }

    return false;
}

const PubkeyManager = struct {
    arena: *std.heap.ArenaAllocator,
    keys: std.StringHashMap([]const *c.ssh_key_struct),

    const Self = @This();

    fn init(allocator: std.mem.Allocator, authorized_keys_path: []const u8) !PubkeyManager {
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

    fn freeKeys(keys: *const std.StringHashMap([]const *c.ssh_key_struct)) void {
        var it = keys.valueIterator();
        while (it.next()) |value| {
            for (value.*) |item| {
                c.ssh_key_free(item);
            }
        }
    }

    fn hasKey(self: *const Self, username: []const u8, key: *c.ssh_key_struct) bool {
        const keys = self.keys.get(username);
        if (keys == null) return false;
        for (keys.?) |item| {
            if (c.ssh_key_cmp(item, key, c.SSH_KEY_CMP_PUBLIC) == 0) return true;
        }
        return false;
    }

    fn deinit(self: *const Self) void {
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

fn tryDecrypt(allocator: std.mem.Allocator, session: *c.ssh_session_struct, entry: *crypttab.CrypttabEntry) !bool {
    var msg: c.ssh_message = undefined;

    const kbdintName = "Welcome to dols, v0.0.0\n";
    const kbdintInstructionFormat = "Enter disk decryption password for {s}";
    var kbdintPrompt: [1][*c]const u8 = .{@ptrCast("Password: ")};
    var kbdintEcho = [1]u8{0};

    while (true) {
        msg = c.ssh_message_get(session);
        defer c.ssh_message_free(msg);

        if (c.ssh_message_type(msg) != c.SSH_REQUEST_AUTH or c.ssh_message_subtype(msg) != c.SSH_AUTH_METHOD_INTERACTIVE) {
            _ = c.ssh_message_auth_set_methods(msg, c.SSH_AUTH_METHOD_INTERACTIVE);
            _ = c.ssh_message_reply_default(msg);
            continue;
        }

        if (c.ssh_message_auth_kbdint_is_response(msg) == 0) {
            const kbtintInstruction = try std.fmt.allocPrint(allocator, kbdintInstructionFormat, .{entry.volumeName});
            defer allocator.free(kbtintInstruction);
            _ = c.ssh_message_auth_interactive_request(msg, kbdintName, @ptrCast(kbtintInstruction), 1, @ptrCast(&kbdintPrompt), @ptrCast(&kbdintEcho));
        } else {
            if (c.ssh_userauth_kbdint_getnanswers(session) != 1) return false;
            _ = cryptsetup.attachDeviceByPassword(entry, std.mem.span(c.ssh_userauth_kbdint_getanswer(session, 0))) catch {
                _ = c.ssh_message_auth_set_methods(msg, c.SSH_AUTH_METHOD_INTERACTIVE);
                _ = c.ssh_message_reply_default(msg);
                return false;
            };
            _ = c.ssh_message_auth_reply_success(msg, 0);
            return true;
        }
    }

    return false;
}
