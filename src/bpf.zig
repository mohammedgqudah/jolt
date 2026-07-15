const std = @import("std");
const c = @import("c");

const mem = std.mem;

pub fn Links(comptime programs: []const []const u8, comptime T: type) type {
    var names: [programs.len][:0]const u8 = undefined;
    var types: [programs.len]type = undefined;
    var attrs: [programs.len]std.builtin.Type.Struct.FieldAttributes = undefined;

    inline for (programs, 0..) |name, i| {
        names[i] = name ++ "";
        types[i] = *T;
        attrs[i] = .{};
    }

    return @Struct(
        .@"extern",
        null,
        &names,
        &types,
        &attrs,
    );
}

pub fn Object(comptime path: []const u8, comptime programs: []const [:0]const u8) type {
    const data = @embedFile(path);
    return struct {
        const Self = @This();

        links: Links(programs, c.bpf_link),
        programs: Links(programs, c.bpf_program),
        object: *c.bpf_object,
        skeleton: *c.bpf_object_skeleton,

        /// Create skeleton
        pub fn init(comptime allocator: mem.Allocator) !*Self {
            // i could have used the c allocator directly
            // but I wanted to signal that this function does allocate
            // based on it's signature.
            //
            // why? libbpf will take ownership of these values
            // and it will free them using the c allocator.
            if (allocator.vtable != std.heap.c_allocator.vtable) {
                @compileError("Expected a c allocator");
            }

            var self: *Self = try allocator.create(Self);

            // zero bpf_prog and bpf_link pointers
            // or else libbpf will get confused.
            @memset(std.mem.asBytes(&self.programs), 0);
            @memset(std.mem.asBytes(&self.links), 0);

            self.skeleton = try allocator.create(c.bpf_object_skeleton);
            self.skeleton.* = std.mem.zeroes(c.bpf_object_skeleton);

            errdefer c.bpf_object__destroy_skeleton(self.skeleton);

            self.skeleton.sz = @sizeOf(c.bpf_object_skeleton);
            self.skeleton.name = "prog_bpf";
            self.skeleton.obj = @ptrCast(&self.object);

            self.skeleton.prog_cnt = programs.len;
            self.skeleton.prog_skel_sz = @sizeOf(c.bpf_prog_skeleton);
            const progs = try allocator.alloc(c.bpf_prog_skeleton, programs.len);
            self.skeleton.progs = progs.ptr;

            inline for (programs, 0..) |prog_name, i| {
                self.skeleton.progs[i] = .{
                    .name = prog_name,
                    .prog = @ptrCast(&@field(self.programs, prog_name)),
                    .link = @ptrCast(&@field(self.links, prog_name)),
                };
            }

            self.skeleton.data = data;
            self.skeleton.data_sz = data.len;

            return self;
        }

        fn open(self: *Self) !void {
            const rc = c.bpf_object__open_skeleton(self.skeleton, null);
            switch (std.posix.errno(rc)) {
                .SUCCESS => {},
                .INVAL => return error.InvalidArgument,
                .NOENT => return error.NotFound,
                else => |e| return std.posix.unexpectedErrno(e),
            }
        }

        fn load(self: *Self) !void {
            const rc = c.bpf_object__load_skeleton(self.skeleton);
            switch (std.posix.errno(rc)) {
                .SUCCESS => {},
                .PERM => return error.PermissionDenied,
                else => |e| return std.posix.unexpectedErrno(e),
            }
        }

        fn _attach(self: *Self) !void {
            const rc = c.bpf_object__attach_skeleton(self.skeleton);
            switch (std.posix.errno(rc)) {
                .SUCCESS => {},
                .PERM => return error.PermissionDenied,
                else => |e| return std.posix.unexpectedErrno(e),
            }
        }

        pub fn attach(self: *Self) !void {
            try self.open();
            try self.load();
            try self._attach();
        }
        pub fn deinit(self: *Self, allocator: mem.Allocator) void {
            _ = c.bpf_object__destroy_skeleton(self.skeleton);
            allocator.destroy(self);
        }
    };
}
