const std = @import("std");
const shadow = @import("../shadow.zig");

const c = @import("c.zig").c;

const PubkeyManager = @import("pubkey_manager.zig").PubkeyManager;

pub fn authenticateUser(allocator: std.mem.Allocator, session: *c.ssh_session_struct, pkm: *const PubkeyManager) !bool {
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
