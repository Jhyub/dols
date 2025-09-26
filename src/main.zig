const std = @import("std");
const lib = @import("dols_lib");

const toml = @import("toml");

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var parser = toml.Parser(lib.config.ConfigFile).init(std.heap.c_allocator);
    defer parser.deinit();
    const config_file = (try parser.parseFile("/etc/dols.toml")).value;
    const config = lib.config.Config.init(config_file);

    const crypttab = try (try std.fs.cwd().openFile("/etc/crypttab", .{})).readToEndAlloc(allocator, 1024);
    defer allocator.free(crypttab);
    const entries = try lib.crypttab.parseCrypttab(allocator, crypttab);
    defer allocator.free(entries);
    defer lib.crypttab.freeCrypttab(allocator, entries);

    try lib.ssh.startSshd(allocator, &config, entries);
}
