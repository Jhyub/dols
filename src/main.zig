const std = @import("std");
const lib = @import("dols_lib");

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try lib.start_sshd(allocator, 121);

    //const crypttab = try std.fs.cwd().readFileAlloc(allocator, "/etc/crypttab.initramfs", 1024);
    //defer allocator.free(crypttab);
    //const entries = try lib.crypttab.parseCrypttab(allocator, crypttab);
    //defer allocator.free(entries);
    //for (entries) |entry| {
    //    std.debug.print("{s} {s} {?s} {?s}\n", .{ entry.volumeName, entry.encryptedDevice, entry.keyFile, entry.options });
    //}
}


