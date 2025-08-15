const std = @import("std");
const lib = @import("dols_lib");

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try lib.start_sshd(allocator);
}


