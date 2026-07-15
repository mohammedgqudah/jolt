const std = @import("std");
const bpf = @import("bpf.zig");
const c = @import("c");
const mem = std.mem;
const Thread = std.Thread;

const print = std.debug.print;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);

    _ = io;
    _ = gpa;

    const node_args = args[1..];
    const ports = try arena.alloc(u16, node_args.len);
    for (node_args, 0..) |arg, i| {
        ports[i] = try std.fmt.parseInt(u16, arg, 10);
    }
    var dummy: *bpf.Object("prog.bpf.o", &.{"block_wx_mprotect"}) = try .init(std.heap.c_allocator);
    defer dummy.deinit(std.heap.c_allocator);

    try dummy.attach();
    //try std.Io.sleep(init.io, .fromSeconds(20), .awake);
}
