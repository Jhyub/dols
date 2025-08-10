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
    // Placeholder for starting an SSH daemon
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

    return;
}
