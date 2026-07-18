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
            "root",    "prio",
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
}

pub fn deinit() !void {}
