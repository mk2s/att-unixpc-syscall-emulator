const std = @import("std");

// Zig strips the tarball's single top-level directory ("Musashi-<commit>") when
// it unpacks the package, so dependency files are referenced directly by their
// path within that directory (e.g. "m68kmake.c", "softfloat/softfloat.c").
fn mpath(dep: *std.Build.Dependency, comptime rel: []const u8) std.Build.LazyPath {
    return dep.path(rel);
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ---- Musashi C sources ------------------------------------------------
    // Musashi is fetched as a package dependency (see build.zig.zon); `zig
    // build` unpacks it automatically, so there is no manual untar / vendoring.
    // The opcode tables (m68kops.c/.h) are NOT shipped upstream: they are
    // generated from m68k_in.c by the m68kmake tool. We build m68kmake with the
    // host compiler and run it once, emitting the tables into a generated
    // directory that all targets share. Our 68010 config lives in src/m68kconf.h
    // (kept out of the dependency; selected via -DMUSASHI_CNF and src/ on the
    // include path).
    const musashi = b.dependency("musashi", .{});

    // Build m68kmake for the HOST (it is a build-time codegen tool, not part of
    // the emulator), then run it: `m68kmake <out_dir> <m68k_in.c>` writes
    // m68kops.h and m68kops.c into <out_dir>.
    // Stage m68kmake.c into the build's WriteFiles output before compiling it.
    // m68kmake.c is a self-contained code generator (only standard headers),
    // so a straight copy works. This avoids a Zig cache bug where compiling a
    // dependency source file directly into a host-graph executable fails with
    // "file_hash FileNotFound" for the build-local dependency copy
    // (ziglang/zig#21142).
    const m68kmake_src = b.addWriteFiles();
    const m68kmake_c = m68kmake_src.addCopyFile(mpath(musashi, "m68kmake.c"), "m68kmake.c");

    const m68kmake_mod = b.createModule(.{
        .target = b.graph.host,
        .optimize = .Debug,
    });
    m68kmake_mod.addCSourceFile(.{
        .file = m68kmake_c,
        .flags = &.{"-std=gnu11"},
    });
    m68kmake_mod.link_libc = true;
    const m68kmake = b.addExecutable(.{
        .name = "m68kmake",
        .root_module = m68kmake_mod,
    });

    const gen_ops = b.addRunArtifact(m68kmake);
    // arg1: output directory (captured so we can reference the generated files)
    const ops_dir = gen_ops.addOutputDirectoryArg("musashi-ops");
    // arg2: the input opcode description
    gen_ops.addFileArg(mpath(musashi, "m68k_in.c"));

    const musashi_flags = [_][]const u8{
        "-std=gnu11",
        "-fno-sanitize=undefined",
        // Use our 68010 config (found via the src/ include path added below).
        // Deliberately NOT named m68kconf.h to avoid colliding with upstream's
        // stock config, which sits next to m68k.h and would win the quoted
        // `#include MUSASHI_CNF` lookup.
        "-DMUSASHI_CNF=\"upc_m68kconf.h\"",
    };

    // Attach the Musashi C core + generated ops + include paths to a module.
    // Used for the emulator and every C-linked test module so the wiring stays
    // in one place.
    const AddMusashi = struct {
        fn apply(
            bld: *std.Build,
            mod: *std.Build.Module,
            dep: *std.Build.Dependency,
            ops: std.Build.LazyPath,
            flags: []const []const u8,
        ) void {
            // Include paths: our config (src/), the Musashi headers, softfloat,
            // and the generated-ops directory (for m68kops.h).
            mod.addIncludePath(bld.path("src"));
            mod.addIncludePath(mpath(dep, "."));
            mod.addIncludePath(mpath(dep, "softfloat"));
            mod.addIncludePath(ops);

            // Core sources from the dependency. m68kcpu.c #includes m68kfpu.c
            // and m68kops.h, so we compile m68kcpu.c (not m68kfpu.c) plus the
            // disassembler and softfloat.
            mod.addCSourceFile(.{ .file = mpath(dep, "m68kcpu.c"), .flags = flags });
            mod.addCSourceFile(.{ .file = mpath(dep, "m68kdasm.c"), .flags = flags });
            mod.addCSourceFile(.{ .file = mpath(dep, "softfloat/softfloat.c"), .flags = flags });
            // Generated opcode table.
            mod.addCSourceFile(.{ .file = ops.path(bld, "m68kops.c"), .flags = flags });
        }
    };

    // TranslateC step: expose the Musashi public API to Zig as module "musashi".
    // Factored out because several test modules need their own translate step.
    const AddTranslate = struct {
        fn make(
            bld: *std.Build,
            dep: *std.Build.Dependency,
            ops: std.Build.LazyPath,
            tgt: std.Build.ResolvedTarget,
            opt: std.builtin.OptimizeMode,
        ) *std.Build.Step.TranslateC {
            const tr = bld.addTranslateC(.{
                .root_source_file = bld.path("src/musashi_c.h"),
                .target = tgt,
                .optimize = opt,
                .link_libc = true,
            });
            tr.addIncludePath(bld.path("src"));
            tr.addIncludePath(mpath(dep, "."));
            tr.addIncludePath(mpath(dep, "softfloat"));
            tr.addIncludePath(ops);
            return tr;
        }
    };

    // ---- Emulator executable ----------------------------------------------
    const root = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    AddMusashi.apply(b, root, musashi, ops_dir, &musashi_flags);
    const translate = AddTranslate.make(b, musashi, ops_dir, target, optimize);
    root.addImport("musashi", translate.createModule());
    root.addCSourceFile(.{ .file = b.path("src/host_stat.c"), .flags = &.{"-std=gnu11"} });
    root.addCSourceFile(.{ .file = b.path("src/host_dir.c"), .flags = &.{"-std=gnu11"} });
    root.link_libc = true;

    const exe = b.addExecutable(.{
        .name = "runupc",
        .root_module = root,
    });

    // Install per-target so cross-builds don't clobber each other:
    //   zig-out/bin/<arch>-<os>/runupc
    const res = target.result;
    const exe_name = if (res.os.tag == .windows) "runupc.exe" else "runupc";
    const dest_sub_path = b.fmt("{s}-{s}/{s}", .{ @tagName(res.cpu.arch), @tagName(res.os.tag), exe_name });
    const install_exe = b.addInstallArtifact(exe, .{
        .dest_sub_path = dest_sub_path,
        .pdb_dir = .disabled, // keep bin/ tidy; no stray .pdb at the root
    });
    b.getInstallStep().dependOn(&install_exe.step);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(&install_exe.step);
    // Forward extra CLI args after `--` to the emulator, when supported.
    if (@hasField(std.Build, "args")) {
        if (@field(b, "args")) |args| run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the emulator");
    run_step.dependOn(&run_cmd.step);

    // ---- Unit tests -------------------------------------------------------
    const test_step = b.step("test", "Run unit tests");

    // Pure-Zig tests (no C deps).
    for ([_][]const u8{ "src/abi.zig", "src/shlib.zig", "src/mem.zig", "src/coff.zig", "src/process.zig" }) |src| {
        const t = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(src),
                .target = target,
                .optimize = optimize,
            }),
        });
        test_step.dependOn(&b.addRunArtifact(t).step);
    }

    // fs.zig test: uses libc (open/read/...) but not the Musashi core.
    const fs_test_mod = b.createModule(.{
        .root_source_file = b.path("src/fs.zig"),
        .target = target,
        .optimize = optimize,
    });
    fs_test_mod.addCSourceFile(.{ .file = b.path("src/host_stat.c"), .flags = &.{"-std=gnu11"} });
    fs_test_mod.addCSourceFile(.{ .file = b.path("src/host_dir.c"), .flags = &.{"-std=gnu11"} });
    fs_test_mod.link_libc = true;
    const fs_test = b.addTest(.{ .root_module = fs_test_mod });
    test_step.dependOn(&b.addRunArtifact(fs_test).step);

    // procmodel.zig test: libc (fork/wait externs) + host_stat.c; the test
    // itself only checks status encoding (no actual fork). Musashi needed
    // because procmodel imports cpu/coff transitively.
    const pm_mod = b.createModule(.{
        .root_source_file = b.path("src/procmodel.zig"),
        .target = target,
        .optimize = optimize,
    });
    AddMusashi.apply(b, pm_mod, musashi, ops_dir, &musashi_flags);
    pm_mod.addCSourceFile(.{ .file = b.path("src/host_stat.c"), .flags = &.{"-std=gnu11"} });
    pm_mod.addCSourceFile(.{ .file = b.path("src/host_dir.c"), .flags = &.{"-std=gnu11"} });
    pm_mod.link_libc = true;
    const pm_tr = AddTranslate.make(b, musashi, ops_dir, target, optimize);
    pm_mod.addImport("musashi", pm_tr.createModule());
    const pm_test = b.addTest(.{ .root_module = pm_mod });
    test_step.dependOn(&b.addRunArtifact(pm_test).step);

    // cpu.zig test: needs the Musashi C core + translated module.
    const cpu_test_mod = b.createModule(.{
        .root_source_file = b.path("src/cpu_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    AddMusashi.apply(b, cpu_test_mod, musashi, ops_dir, &musashi_flags);
    cpu_test_mod.link_libc = true;
    const cpu_translate = AddTranslate.make(b, musashi, ops_dir, target, optimize);
    cpu_test_mod.addImport("musashi", cpu_translate.createModule());
    const cpu_test = b.addTest(.{ .root_module = cpu_test_mod });
    test_step.dependOn(&b.addRunArtifact(cpu_test).step);

    // C-linked tests (execute guest code, need the Musashi core + module).
    for ([_][]const u8{ "src/runloop.zig", "src/syscalls.zig" }) |src| {
        const m = b.createModule(.{
            .root_source_file = b.path(src),
            .target = target,
            .optimize = optimize,
        });
        AddMusashi.apply(b, m, musashi, ops_dir, &musashi_flags);
        m.addCSourceFile(.{ .file = b.path("src/host_stat.c"), .flags = &.{"-std=gnu11"} });
        m.addCSourceFile(.{ .file = b.path("src/host_dir.c"), .flags = &.{"-std=gnu11"} });
        m.link_libc = true;
        const tr = AddTranslate.make(b, musashi, ops_dir, target, optimize);
        m.addImport("musashi", tr.createModule());
        const t = b.addTest(.{ .root_module = m });
        test_step.dependOn(&b.addRunArtifact(t).step);
    }
}
