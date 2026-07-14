const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // *******
    // ebpf build system
    dump_vmlinux(b);
    compile_bpf(b);
    compile_commands_json(b);
    // *******

    const mod = b.addModule("jolt", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });

    const translate_c = b.addTranslateC(.{
        .root_source_file = b.path("src/c.h"),
        .target = target,
        .optimize = .Debug,
        .link_libc = true,
    });

    translate_c.addIncludePath(b.path("zig-out/headers"));
    const translate_c_module = translate_c.createModule();
    translate_c_module.optimize = optimize;

    const exe = b.addExecutable(.{
        .name = "jolt",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "jolt", .module = mod },
                .{ .name = "c", .module = translate_c_module },
            },
        }),
    });

    b.installArtifact(exe);

    const run_step = b.step("run", "Run the app");

    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);

    run_cmd.step.dependOn(b.getInstallStep());

    run_cmd.addPassthruArgs();

    const mod_tests = b.addTest(.{
        .root_module = mod,
    });

    const run_mod_tests = b.addRunArtifact(mod_tests);

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });

    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);
}

/// Install vmlinux.h
fn dump_vmlinux(b: *std.Build) void {
    // zig fmt: off
    const dump_vmlinux_run = b.addSystemCommand(&(.{"bpftool"} ++ .{
        "btf", "dump", "file",
        "/sys/kernel/btf/vmlinux",
        "format", "c",
    }));
    // zig fmt: on

    const vmlinux_output = dump_vmlinux_run.captureStdOut(.{});
    b.getInstallStep().dependOn(&b.addInstallFileWithDir(
        vmlinux_output,
        .prefix,
        "headers/vmlinux.h",
    ).step);
}

fn compile_bpf(b: *std.Build) void {
    // zig fmt: off
    const clang_run = b.addSystemCommand(&(.{"clang"} ++ .{
        "-g", "-O2",
        "-target", "bpf",
        "-o",  "zig-out/prog.bpf.o",
        "-c","src/prog.bpf.c",
        "-I", "zig-out/headers"
    }));
    // zig fmt: on
    const bpf_o_step = b.step("compile-bpf", "Compile the eBPF program");
    bpf_o_step.dependOn(&clang_run.step);
    b.getInstallStep().dependOn(bpf_o_step);

    generate_skeleton(b);
}

fn generate_skeleton(b: *std.Build) void {
    const gen_skel_run = b.addSystemCommand(&(.{"bpftool"} ++ .{
        "gen",                "skeleton",
        "zig-out/prog.bpf.o",
    }));
    const skeleton_output = gen_skel_run.captureStdOut(.{});
    b.getInstallStep().dependOn(&b.addInstallFileWithDir(
        skeleton_output,
        .prefix,
        "headers/prog.skel.h",
    ).step);
}

fn compile_commands_json(b: *std.Build) void {
    const cc_json = b.step("compile_commands", "Generate compile_commands.json");
    const gen = b.addWriteFiles();
    const entries = std.fmt.allocPrint(b.allocator,
        \\[
        \\  {{
        \\    "directory": "{f}",
        \\    "file": "src/prog.bpf.c",
        \\    "arguments": ["clang", "-Izig-out/headers", "-c", "src/prog.bpf.c", "-o", "zig-out/prog.bpf.o"]
        \\  }}
        \\]
    , .{b.root}) catch @panic("OOM");
    const file = gen.add("compile_commands.json", entries);
    cc_json.dependOn(&b.addInstallFileWithDir(file, .{ .custom = "../" }, "compile_commands.json").step);
    b.getInstallStep().dependOn(cc_json);
}
