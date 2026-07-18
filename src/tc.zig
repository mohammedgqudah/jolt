const std = @import("std");
const mem = std.mem;
const Io = std.Io;
const process = std.process;

pub const TcError = error{
    FailedToAttachQdisc,
} || process.Child.WaitError || process.SpawnError;

/// Setup TC on loopback to work with jolt.
pub fn init(io: Io) TcError!void {
    // Careful: We start by deleting whatever qdisc is attached
    // to "lo". We assume the old qdisc (that we are deleeting) is from a
    // previous session. This seems like a reasonable assumption because
    // I don't see why anyone would buffer packets on lo, if this is wrong
    // then I need to find a workaround.
    var del_qdisc_child = try std.process.spawn(io, .{
        .argv = &(.{"tc"} ++ .{
            "qdisc", "del",
            "dev",   "lo",
            "root",
        }),
        .stdout = .ignore,
        .stderr = .inherit,
    });
    // TODO: check error message, if != not found -> err
    _ = try del_qdisc_child.wait(io);

    // zig fmt: off
    var attach_qdisc_cmd = try std.process.spawn(io, .{
        .argv = &(.{"tc"} ++ .{
            "qdisc",   "add",
            "dev",     "lo",
            // root qdisc of type prio
            "root", "handle", "1:", "prio",
            // prio params, see tc-prio(8)
            //
            // 2 bands, one for normal traffic
            // that is not shaped by jolt,
            // and the second for delayed traffic.
            "bands",   "2",
            "priomap",
            // empty priomap because we will not be using the ToS of a packet
            // to determine the band, instead our eBPF tc-action program
            // will determine the band. see "QDISC PARAMETERS" in the man page.
            "0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"
        } ),
        .stdout = .ignore,
    });
    // zig fmt: on
    const attach_term = try attach_qdisc_cmd.wait(io);
    if (!attach_term.success()) return TcError.FailedToAttachQdisc;

    try setup_bands(io);
}

/// Attach a qdisc for each band created in init.
fn setup_bands(io: Io) !void {
    // band1 is the "unshaped" band
    var band1_child = try std.process.spawn(io, .{
        .argv = &(.{"tc"} ++ .{
            "qdisc",    "add",
            "dev",      "lo",
            // major:minor
            // major -> major of parent (the prio qdisc as defined in init 1:)
            // minor -> band number
            "parent",   "1:1",
            "fq_codel",
        }),
        .stdout = .ignore,
        .stderr = .inherit,
    });
    const band1_term = try band1_child.wait(io);
    if (!band1_term.success()) return TcError.FailedToAttachQdisc;

    // band2 is for delayed traffic, an eBPF program will be attached
    // shortly to determine which packets go into this band.
    var band2_child = try std.process.spawn(io, .{
        // zig fmt: off
        .argv = &(.{"tc"} ++ .{
            "qdisc",  "add",
            "dev",    "lo",
            "parent", "1:2",
            "netem",
            "delay", "1000ms",
        }),
        // zig fmt: on
        .stdout = .inherit,
        .stderr = .inherit,
    });
    const band2_term = try band2_child.wait(io);
    if (!band2_term.success()) return TcError.FailedToAttachQdisc;

    // attach a bpf filter to band2
    var load_bpf_child = try std.process.spawn(io, .{
        .argv = &(.{"tc"} ++ .{
            // zig fmt: off
            "filter",  "add",
            "dev",    "lo",
            "parent", "1:",
            // TODO: use the embedded eBPF object
            "bpf", "obj", "./src/prog.bpf.o",
            "sec", "action/dyn_delay",
            // on band2
            "flowid", "1:2",
            // direct-action
            "da"
            // zig fmt: on
        }),
        .stdout = .ignore,
        .stderr = .inherit,
    });
    const load_bpf_term = try load_bpf_child.wait(io);
    if (!load_bpf_term.success()) return TcError.FailedToAttachQdisc;
}
pub fn deinit(io: Io) !void {
    var del_qdisc_child = try std.process.spawn(io, .{
        .argv = &(.{"tc"} ++ .{
            "qdisc", "del",
            "dev",   "lo",
            "root",
        }),
        .stdout = .ignore,
        .stderr = .inherit,
    });
    _ = try del_qdisc_child.wait(io);
}
