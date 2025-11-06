const std = @import("std");
const auth = @import("auth.zig");
const config = @import("../config.zig");
const cryptsetup = @import("../cryptsetup.zig");
const crypttab = @import("../crypttab.zig");
const sap = @import("../systemd_ask_password.zig");

const PubkeyManager = @import("pubkey_manager.zig").PubkeyManager;

const c = @import("c.zig").c;

pub fn startServer(allocator: std.mem.Allocator, conf: *const config.Config, entries: []crypttab.CrypttabEntry) !void {
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

        if (!try auth.authenticateUser(allocator, session, &pubkey_manager)) {
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
