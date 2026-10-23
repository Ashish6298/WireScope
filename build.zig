const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // 1. Reusable Zig library module
    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addStaticLibrary(.{
        .name = "wirescope",
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (target.result.os.tag == .windows) {
        lib.linkSystemLibrary("iphlpapi");
        lib.linkSystemLibrary("ws2_32");
    } else if (target.result.os.tag == .macos) {
        lib.linkLibC();
    }
    b.installArtifact(lib);

    // 2. CLI Executable
    const exe = b.addExecutable(.{
        .name = "wirescope",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe.root_module.addImport("wirescope", lib_mod);
    if (target.result.os.tag == .windows) {
        exe.linkSystemLibrary("iphlpapi");
        exe.linkSystemLibrary("ws2_32");
    } else if (target.result.os.tag == .macos) {
        exe.linkLibC();
    }
    b.installArtifact(exe);

    // Run step
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the WireScope CLI");
    run_step.dependOn(&run_cmd.step);

    // Test step
    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (target.result.os.tag == .windows) {
        lib_unit_tests.linkSystemLibrary("iphlpapi");
        lib_unit_tests.linkSystemLibrary("ws2_32");
    } else if (target.result.os.tag == .macos) {
        lib_unit_tests.linkLibC();
    }
    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const exe_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_unit_tests.root_module.addImport("wirescope", lib_mod);
    if (target.result.os.tag == .windows) {
        exe_unit_tests.linkSystemLibrary("iphlpapi");
        exe_unit_tests.linkSystemLibrary("ws2_32");
    } else if (target.result.os.tag == .macos) {
        exe_unit_tests.linkLibC();
    }
    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    const test_step = b.step("test", "Run WireScope unit and integration tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_exe_unit_tests.step);

    // Format check step
    const fmt_step = b.step("fmt", "Run source code formatter");
    const fmt = b.addFmt(.{
        .paths = &.{ "src", "build.zig", "poc" },
    });
    fmt_step.dependOn(&fmt.step);
}
