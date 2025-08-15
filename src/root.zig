//! By convention, root.zig is the root source file when making a library. If
//! you are making an executable, the convention is to delete this file and
//! start with main.zig instead.
const std = @import("std");
const testing = std.testing;

const c = @cImport({
    @cInclude("libssh/libssh.h");
    @cInclude("libssh/server.h");
    });   

pub export fn start_sshd() void {
    defer _ = c.ssh_finalize();
    std.debug.print("Starting SSH daemon...\n", .{});
    const port = 121;
    const sshbind = c.ssh_bind_new().?;
    defer c.ssh_bind_free(sshbind);
    const session = c.ssh_new().?;
    defer c.ssh_disconnect(session);

    _ = c.ssh_bind_options_set(sshbind, c.SSH_BIND_OPTIONS_RSAKEY, "/etc/ssh/ssh_host_rsa_key");
    _ = c.ssh_bind_options_set(sshbind, c.SSH_BIND_OPTIONS_ECDSAKEY, "/etc/ssh/ssh_host_ecdsa_key");
    _ = c.ssh_bind_options_set(sshbind, c.SSH_BIND_OPTIONS_BINDPORT_STR, "121");
    


    if(c.ssh_bind_listen(sshbind) < 0) {
        std.debug.print("ssh_bind_listen failed: {s}\n", .{c.ssh_get_error(sshbind)});
        std.debug.print("Failed to listen on port {}\n", .{port});
        return;
    }

    std.debug.print("SSH daemon started on port {}\n", .{port});

    const r = c.ssh_bind_accept(sshbind, session);
    if(r == c.SSH_ERROR) {
        std.debug.print("Failed to accept connection: {s}\n", .{c.ssh_get_error(sshbind)});
        return;
    }

    if(c.ssh_handle_key_exchange(session) != 0) {
        std.debug.print("ssh_handle_key_exchange: {s}\n", .{c.ssh_get_error(session)});
        return;
    }

    const auth = authenticateUser(session);
    if(auth != 1) {
        std.debug.print("Authentication failed: {s}\n", .{c.ssh_get_error(session)});
        c.ssh_disconnect(session);
        return;
    }
    std.debug.print("User authenticated successfully\n", .{});

    return;
}

fn authenticateUser(session: *c.ssh_session_struct) i32 {
    var msg: c.ssh_message = undefined;

    const name = "Welcome to dols, v0.0.0\n";
    const instructionFormat = "Enter ssh password for user {s}";
    var prompt: [1][*c]const u8 = .{@ptrCast("Password: ")};
    var echo = [1]u8{0};

    while (true) {
        msg = c.ssh_message_get(session);
        defer c.ssh_message_free(msg);

        switch(c.ssh_message_type(msg)) {
            c.SSH_REQUEST_AUTH => {
                switch(c.ssh_message_subtype(msg)) {
                    c.SSH_AUTH_METHOD_PASSWORD => {
                        const username = std.mem.span(c.ssh_message_auth_user(msg));
                        const password = std.mem.span(c.ssh_message_auth_password(msg));
                        std.debug.print("User {s} wants to authenticate with password {s}\n", .{
                            username,
                            password
                        });
                        if(std.mem.eql(u8, username, "jhyub") and std.mem.eql(u8, password, "test")) {
                            _ = c.ssh_message_auth_reply_success(msg, 0);
                            return 1;
                        }
                        _ = c.ssh_message_auth_set_methods(msg, c.SSH_AUTH_METHOD_PASSWORD);
                        _ = c.ssh_message_reply_default(msg);
                    },
                    c.SSH_AUTH_METHOD_INTERACTIVE => {
                        if(c.ssh_message_auth_kbdint_is_response(msg) == 0) {
                            var gpa = std.heap.GeneralPurposeAllocator(.{}){};
                            defer _ = gpa.deinit();
                            const allocator = gpa.allocator();

                            const username = std.mem.span(c.ssh_message_auth_user(msg));
                            const instruction = std.fmt.allocPrint(allocator, instructionFormat, .{username}) catch {return 1;};
                            defer allocator.free(instruction);
                            _ = c.ssh_message_auth_interactive_request(msg, name, @ptrCast(instruction), 1, @ptrCast(&prompt), @ptrCast(&echo));
                        } else {
                            if(kbdintCheckResponse(session)) {
                                return 1;
                            }
                            _ = c.ssh_message_auth_set_methods(msg, c.SSH_AUTH_METHOD_INTERACTIVE);
                            _ = c.ssh_message_reply_default(msg);
                        }

                    },
                    else => {
                        std.debug.print("User {s} wants to authenticate with method {}\n", .{
                            c.ssh_message_auth_user(msg),
                            c.ssh_message_subtype(msg)
                        });
                    _ = c.ssh_message_auth_set_methods(msg, c.SSH_AUTH_METHOD_INTERACTIVE);
                        _ = c.ssh_message_reply_default(msg);
                    }
                }
            },
            else => {
                _ = c.ssh_message_auth_set_methods(msg, c.SSH_AUTH_METHOD_INTERACTIVE);
                _ = c.ssh_message_reply_default(msg);
            }
        }
    }
    return 0;
}

fn kbdintCheckResponse(session: *c.ssh_session_struct) bool {
    const count = c.ssh_userauth_kbdint_getnanswers(session);

    if(count != 1) {
        return false;
    }
    const password = std.mem.span(c.ssh_userauth_kbdint_getanswer(session, 0));

    return std.mem.eql(u8, password, "test");
}