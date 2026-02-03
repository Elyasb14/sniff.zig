const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    const raylib_dep = b.dependency("raylib", .{
        .target = target,
        .optimize = optimize,
    });

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "sniff",
        .root_module = exe_mod,
    });
    exe.root_module.linkSystemLibrary("pcap", .{});
    exe.root_module.linkLibrary(raylib_dep.artifact("raylib"));

    if (target.result.os.tag == .macos) {
        exe.linkFramework("CoreVideo");
        exe.linkFramework("IOKit");
        exe.linkFramework("Cocoa");
        exe.linkFramework("GLUT");
        exe.linkFramework("OpenGL");
    }

    b.installArtifact(exe);
    b.installArtifact(raylib_dep.artifact("raylib"));

    const tests = b.addTest(.{ .root_module = b.addModule("src/application/http.zig", .{ .target = target, .optimize = optimize }) });

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&tests.step);
}
