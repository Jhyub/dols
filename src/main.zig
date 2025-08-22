const std = @import("std");
const lib = @import("dols_lib");

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();


    const crypttab = try (try std.fs.openFileAbsolute("/etc/crypttab", .{})).readToEndAlloc(allocator, std.math.maxInt(usize));
    defer allocator.free(crypttab);
    const entries= try lib.crypttab.parseCrypttab(allocator, crypttab);
    defer allocator.free(entries);
    defer lib.crypttab.freeCrypttab(allocator, entries);
    for (entries) |entry| {
        std.debug.print("{s}\n{s}\n{?s}\n{?s}\n", .{ entry.volumeName, entry.encryptedDevice, entry.keyFile, entry.options });
    }
    try lib.start_sshd(allocator, 121, entries);
}


