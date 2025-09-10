const std = @import("std");

const c = @cImport({
    @cInclude("crypt.h");
    @cInclude("pwd.h");
    @cInclude("shadow.h");
});

pub fn authenticateByUsername(username: [:0]const u8, password: [:0]const u8) bool {
    const passwd: *c.struct_passwd = c.getpwnam(username);
    const pw_passwd: [:0]const u8 = std.mem.span(passwd.pw_passwd);

    if (!std.mem.eql(u8, pw_passwd, "x")) { // we won't need to support non-shadow passwords
        return false;
    }

    _ = c.lckpwdf();
    defer _ = c.ulckpwdf();
    const spwd: *c.struct_spwd = c.getspnam(username);

    const hash_ret: [:0]const u8 = std.mem.span(c.crypt(password, spwd.sp_pwdp));
    const hashed_password: [:0]const u8 = std.mem.span(spwd.sp_pwdp);

    return std.mem.eql(u8, hash_ret, hashed_password);
}
