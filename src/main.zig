const std = @import("std");
const bpf = @import("bpf.zig");
const c = @import("c");
const mem = std.mem;
const Thread = std.Thread;

const print = std.debug.print;

var ready_ports: usize = 0;
pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);

    _ = io;
    _ = gpa;

    const node_args = args[1..];
    var ports = try arena.alloc(u16, node_args.len);
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

    var rb: bpf.RingBuffer = try .init(dummy.maps.events_buf, handle_event, @ptrCast(&ports));

    print("waiting for ports\n", .{});
    while (ready_ports < ports.len) {
        _ = try rb.poll_once(.fromSeconds(1));
    }
    print("done\n", .{});
}

fn handle_event(ctx: ?*anyopaque, data: ?*anyopaque, size: usize) callconv(.c) c_int {
    _ = size;

    const event: *const c.bind_event = @ptrCast(@alignCast(data.?));
    const port = mem.bigToNative(u16, event.port);

    const _ports: *[]u16 = @ptrCast(@alignCast(ctx.?));
    const ports: []u16 = _ports.*;

    for (ports) |p| {
        if (p == port) {
            ready_ports += 1;
        }
    }

    return 0;
}
