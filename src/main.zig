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

    var dummy: *bpf.Object(
        "prog.bpf.o",
        &.{"inet_bind_exit"},
        &.{"events_buf"},
    ) = try .init(std.heap.c_allocator);
    defer dummy.deinit(std.heap.c_allocator);

    try dummy.attach();

    var rb: bpf.RingBuffer = try .init(dummy.maps.events_buf, handle_event);

    while (true) {
        _ = try rb.poll_once(.fromSeconds(1));
    }
}

fn handle_event(ctx: ?*anyopaque, data: ?*anyopaque, size: usize) callconv(.c) c_int {
    _ = ctx;
    _ = size;

    const event: *const c.bind_event = @ptrCast(@alignCast(data.?));

    std.debug.print("[pid={d}] bind on port {d}\n", .{
        event.pid,
        mem.bigToNative(u16, event.port),
    });
    return 0;
}
