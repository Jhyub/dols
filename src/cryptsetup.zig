const std = @import("std");
const crypttab = @import("crypttab.zig");

const c = @cImport({
    @cInclude("libcryptsetup.h");
});

pub fn cryptInit(entry: *crypttab.CrypttabEntry) !*c.struct_crypt_device {
    var cd: ?*c.struct_crypt_device = null;
    _ = c.crypt_init(&cd, @ptrCast(entry.encryptedDevice));
    return cd.?;
}

pub fn cryptDeinit(cd: *c.struct_crypt_device) !void {
    _ = c.crypt_free(cd);
}

pub fn attatchDevice(entry: *crypttab.CrypttabEntry, password: [:0]const u8) !void {
    const cd = try cryptInit(entry);
    defer cryptDeinit(cd) catch {};

    _ = c.crypt_load(cd, c.CRYPT_LUKS2, null);
    const ret = c.crypt_activate_by_passphrase(cd, @ptrCast(entry.volumeName), c.CRYPT_ANY_SLOT, @ptrCast(password), password.len, 0);

    if (ret != 0) {
        return error.CryptActivateByPassphraseFailed;
    }

    const cad: ?*c.struct_crypt_active_device = null;
    _ = c.crypt_get_active_device(cd, @ptrCast(entry.volumeName), cad);
}
