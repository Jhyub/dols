const std = @import("std");
const lib = @import("dols_lib");

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    //try lib.start_sshd(allocator, 121);

    const crypttab = "luks-test /dev/disk/by-uuid/47f7ad02-54f4-4033-a288-6853d9836edf";
    const entries= try lib.crypttab.parseCrypttab(allocator, crypttab);
    defer allocator.free(entries);
    defer lib.crypttab.freeCrypttab(allocator, entries);
    for (entries) |entry| {
        std.debug.print("{s}\n{s}\n{?s}\n{?s}\n", .{ entry.volumeName, entry.encryptedDevice, entry.keyFile, entry.options });
    }

    const cstr: [*c] const u8 = @ptrCast(entries[0].volumeName);
    std.debug.print("{s}\n", .{cstr});

    try lib.cryptsetup.attatchDevice(&entries[0]);
}


