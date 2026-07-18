const std = @import("std");
const bpf = @import("bpf.zig");
const c = @import("c");
const mem = std.mem;
const Thread = std.Thread;

const print = std.debug.print;

var ready_ports: usize = 0;

/// Returns the cookie for the current network namespace (netns).
///
/// A cookie uniquely identifies a netns.
pub fn getCurrentNetNsCookie() !u64 {
    const sockfd: i32 = @intCast(std.os.linux.socket(
        std.os.linux.AF.INET,
        std.os.linux.SOCK.STREAM,
        0,
    ));
    if (sockfd < 0) {
        return std.posix.unexpectedErrno(std.posix.errno(sockfd));
    }

    var cookie: u64 = 0;
    var len: std.posix.socklen_t = @sizeOf(u64);

    const rc = std.os.linux.getsockopt(
        sockfd,
        std.posix.SOL.SOCKET,
        c.SO_NETNS_COOKIE,
        @ptrCast(&cookie),
        &len,
    );

    if (rc != 0) {
        return std.posix.unexpectedErrno(std.posix.errno(rc));
    }

    return cookie;
}

const Port = struct {
    number: u16,
    netns_cookie: u64,
    state: union(enum) {
        /// a socket is bound to this port
        active: struct {
            socket_cookie: u64,
            pid: u32,
        },
        /// nothing is bound to this port
        inactive,
        /// unknown state
        /// example: the program just started, doesn't know if a socket
        /// is bound to this port or not.
        unknown,
    },
};

const Context = struct {
    /// ports we're interested in
    ports: []Port,
};

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);

    _ = io;
    _ = gpa;

    // The ports you provide as arguments are the ports your local services
    // will bind to and listen for connections at. "jolt" will then monitor
    // incoming connections to your services and let delay or drop traffic for
    // any connection (or all connections).
    const node_args = args[1..];
    var ports = try arena.alloc(Port, node_args.len);
    for (node_args, 0..) |arg, i| {
        ports[i] = .{
            .number = try std.fmt.parseInt(u16, arg, 10),
            .state = .unknown,
            // only support current ns for now
            .netns_cookie = try getCurrentNetNsCookie(),
        };
    }

    // This context object will be passed to ebpf hooks.
    // to be more specific, that will be passed to functions that handle new events
    // from eBPF ring buffer maps.
    var ctx: Context = .{
        .ports = ports,
    };

    var dummy: *bpf.Object(
        "prog.bpf.o",
        &.{ "inet_bind_exit", "inet_listen_stop" },
        &.{"events_buf"},
    ) = try .init(std.heap.c_allocator);
    defer dummy.deinit(std.heap.c_allocator);

    try dummy.attach();

    var rb: bpf.RingBuffer = try .init(dummy.maps.events_buf, handle_event, @ptrCast(&ctx));

    print("waiting for ports\n", .{});
    while (true) {
        _ = try rb.poll_once(.fromSeconds(1));
    }
    print("done\n", .{});
}

fn handle_event(_ctx: ?*anyopaque, data: ?*anyopaque, size: usize) callconv(.c) c_int {
    _ = size;

    const event: *const c.bind_event = @ptrCast(@alignCast(data.?));

    print("{d}/{d} - {d} {s}\n", .{
        event.ns_cookie,
        event.cookie,
        event.port,
        if (event.is_release == 1) "stopped" else "listening",
    });

    const ctx: *Context = @ptrCast(@alignCast(_ctx.?));

    for (ctx.ports) |*port| {
        if (port.netns_cookie == event.ns_cookie and port.number == event.port) {
            if (event.is_release == 0) {
                // bind
                port.state = .{ .active = .{ .socket_cookie = event.cookie, .pid = event.pid } };
            } else {
                // close
                port.state = .inactive;
            }
        }
    }

    return 0;
}
