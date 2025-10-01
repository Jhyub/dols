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

        if (!try authenticateUser(allocator, session)) {
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

        const ask_files = try sap.Ask.list(allocator);
        defer allocator.free(ask_files);

        if (ask_files.len > 0) {
            var dir = try std.fs.cwd().openDir("/run/systemd/ask-password", .{ .iterate = true });
            defer dir.close();
            for (ask_files) |filename| {
                defer allocator.free(filename);

                const ask = try sap.Ask.readFrom(allocator, dir.openFile(filename, .{}) catch continue);
                defer ask.deinit();

                const proc_path = try std.fmt.allocPrint(allocator, "/proc/{d}", .{ask.pid});
                defer allocator.free(proc_path);

                var proc_dir = try std.fs.cwd().openDir(proc_path, .{ .iterate = true });
                defer proc_dir.close();

                var buf: [4096]u8 = undefined;
                const exe = try proc_dir.readLink("exe", &buf);
                if (std.mem.eql(u8, exe, "/usr/bin/systemd-cryptsetup")) {
                    try ask.answer(allocator, "", true, false);
                    break;
                }
            }
        }

        return;
    }
}

fn authenticateUser(allocator: std.mem.Allocator, session: *c.ssh_session_struct) !bool {
    var msg: c.ssh_message = undefined;

    const name = "Welcome to dols, v0.0.0-250913\n";
    const instructionFormat = "Enter ssh password for user {s}";
    var prompt: [1][*c]const u8 = .{@ptrCast("Password: ")};
    var echo = [1]u8{0};

    var username: [:0]const u8 = try allocator.dupeZ(u8, "");
    defer allocator.free(username);

    while (true) {
        msg = c.ssh_message_get(session);
        defer c.ssh_message_free(msg);

        switch (c.ssh_message_type(msg)) {
            c.SSH_REQUEST_AUTH => {
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
                            const instruction = try std.fmt.allocPrint(allocator, instructionFormat, .{username});
                            defer allocator.free(instruction);
                            _ = c.ssh_message_auth_interactive_request(msg, name, @ptrCast(instruction), 1, @ptrCast(&prompt), @ptrCast(&echo));
                        } else {
                            const reply = std.mem.span(c.ssh_userauth_kbdint_getanswer(session, 0));
                            if (shadow.authenticateByUsername(username, reply)) {
                                _ = c.ssh_message_auth_reply_success(msg, 1);
                                return true;
                            }
                            return false;
                        }
                    },
                    else => {
                        allocator.free(username);
                        username = try allocator.dupeZ(u8, std.mem.span(c.ssh_message_auth_user(msg)));
                        _ = c.ssh_message_auth_set_methods(msg, c.SSH_AUTH_METHOD_INTERACTIVE);
                        _ = c.ssh_message_reply_default(msg);
                    },
                }
            },
            else => {
                _ = c.ssh_message_auth_set_methods(msg, c.SSH_AUTH_METHOD_INTERACTIVE);
                _ = c.ssh_message_reply_default(msg);
            },
        }
    }
    return false;
}

fn kbdintCheckResponse(session: *c.ssh_session_struct, answers: []const []const u8) bool {
    const count = c.ssh_userauth_kbdint_getnanswers(session);

    if (count != answers.len) {
        return false;
    }

    for (0..answers.len) |i| {
        const reply = std.mem.span(c.ssh_userauth_kbdint_getanswer(session, @intCast(i)));
        const answer = answers[i];
        if (!std.mem.eql(u8, reply, answer)) {
            return false;
        }
    }
    return true;
}

fn tryDecrypt(allocator: std.mem.Allocator, session: *c.ssh_session_struct, entry: *crypttab.CrypttabEntry) !bool {
    var msg: c.ssh_message = undefined;

    const name = "Welcome to dols, v0.0.0\n";
    const instructionFormat = "Enter disk decryption password for {s}";
    var prompt: [1][*c]const u8 = .{@ptrCast("Password: ")};
    var echo = [1]u8{0};

    while (true) {
        msg = c.ssh_message_get(session);
        defer c.ssh_message_free(msg);

        switch (c.ssh_message_type(msg)) {
            c.SSH_REQUEST_AUTH => {
                switch (c.ssh_message_subtype(msg)) {
                    c.SSH_AUTH_METHOD_INTERACTIVE => {
                        if (c.ssh_message_auth_kbdint_is_response(msg) == 0) {
                            const instruction = try std.fmt.allocPrint(allocator, instructionFormat, .{entry.volumeName});
                            defer allocator.free(instruction);
                            _ = c.ssh_message_auth_interactive_request(msg, name, @ptrCast(instruction), 1, @ptrCast(&prompt), @ptrCast(&echo));
                        } else {
                            _ = cryptsetup.attatchDeviceByPassword(entry, std.mem.span(c.ssh_userauth_kbdint_getanswer(session, 0))) catch {
                                _ = c.ssh_message_auth_set_methods(msg, c.SSH_AUTH_METHOD_INTERACTIVE);
                                _ = c.ssh_message_reply_default(msg);
                                return false;
                            };
                            _ = c.ssh_message_auth_reply_success(msg, 0);
                            return true;
                        }
                    },
                    else => {
                        _ = c.ssh_message_auth_set_methods(msg, c.SSH_AUTH_METHOD_INTERACTIVE);
                        _ = c.ssh_message_reply_default(msg);
                    },
                }
            },
            else => {
                _ = c.ssh_message_auth_set_methods(msg, c.SSH_AUTH_METHOD_INTERACTIVE);
                _ = c.ssh_message_reply_default(msg);
            },
        }
    }
    return false;
}
