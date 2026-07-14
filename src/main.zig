const std = @import("std");
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
}
