const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Dependencies

    const mkinitcpio_nfs_utils = b.dependency("mkinitcpio-nfs-utils", .{
        .target = target,
        .optimize = optimize,
    });

    const toml = b.dependency("toml", .{
        .target = target,
        .optimize = optimize,
    });

    // Modules

    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    lib_mod.addIncludePath(mkinitcpio_nfs_utils.path("ipconfig"));

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe_mod.addImport("dols_lib", lib_mod);
    exe_mod.addImport("toml", toml.module("toml"));

    // libdols

    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "dols",
        .root_module = lib_mod,
    });

    lib.linkLibC();
    lib.linkSystemLibrary("crypt");
    lib.linkSystemLibrary("cryptsetup");
    lib.linkSystemLibrary("ssh");

    lib.addCSourceFiles(.{
        .root = mkinitcpio_nfs_utils.path("ipconfig"),
        .files = &.{ "bootp_proto.c", "dhcp_proto.c", "netdev.c", "main.c", "packet.c" },
    });
    lib.installHeadersDirectory(mkinitcpio_nfs_utils.path("ipconfig"), "", .{
        .include_extensions = &.{"ipconfig.h"},
    });

    b.installArtifact(lib);

    // dols

    const exe = b.addExecutable(.{
        .name = "dols",
        .root_module = exe_mod,
    });

    b.installArtifact(exe);

    // run

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // tests

    const lib_unit_tests = b.addTest(.{
        .root_module = lib_mod,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const exe_unit_tests = b.addTest(.{
        .root_module = exe_mod,
    });

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_exe_unit_tests.step);
}
