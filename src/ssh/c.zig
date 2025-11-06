pub const c = @cImport({
    @cInclude("libssh/libssh.h");
    @cInclude("libssh/server.h");
});
