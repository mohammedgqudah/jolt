const std = @import("std");
const c = @import("c");

const mem = std.mem;

pub fn Maps(comptime maps: []const []const u8) type {
    var names: [maps.len][:0]const u8 = undefined;
    var types: [maps.len]type = undefined;
    var attrs: [maps.len]std.builtin.Type.Struct.FieldAttributes = undefined;

    inline for (maps, 0..) |name, i| {
        names[i] = name ++ "";
        types[i] = *c.bpf_map;
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

pub fn Object(comptime path: []const u8, comptime programs: []const [:0]const u8, comptime maps: []const [:0]const u8) type {
    const data = @embedFile(path);
    return struct {
        const Self = @This();

        maps: Maps(maps),
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

            // initialize programs and links
            inline for (programs, 0..) |prog_name, i| {
                self.skeleton.progs[i] = .{
                    .name = prog_name,
                    .prog = @ptrCast(&@field(self.programs, prog_name)),
                    .link = @ptrCast(&@field(self.links, prog_name)),
                };
            }

            // ** initialize maps **
            //
            // TODO: parse ELF at comptime to autoamtically
            //  extract maps automatically on behalf of the user.
            //  a quick test with readelf shows that I just need
            //  to get ".maps" section index, and then find symbols
            //  with st_shndx equal to that index, need to confirm later
            //  with libbpf/bpftool.
            self.skeleton.map_cnt = maps.len;
            // TODO: see https://github.com/libbpf/bpftool/blob/3468e85806337c8308e1e7e8da30e343582e1aae/src/gen.c#L912
            self.skeleton.map_skel_sz = 24;

            const skeleton_maps = try allocator.alloc(c.bpf_map_skeleton, maps.len);
            @memset(skeleton_maps, std.mem.zeroes(c.bpf_map_skeleton));
            self.skeleton.maps = skeleton_maps.ptr;

            inline for (maps, 0..) |map_name, i| {
                self.skeleton.maps[i] = .{
                    .name = map_name,
                    .map = @ptrCast(&@field(self.maps, map_name)),
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

pub const RingBuffer = struct {
    const Self = @This();

    inner: *c.ring_buffer,

    pub fn init(
        map: *c.bpf_map,
        handler: *const fn (?*anyopaque, ?*anyopaque, usize) callconv(.c) c_int,
        context: ?*anyopaque,
    ) !Self {
        const rb = c.ring_buffer__new(
            c.bpf_map__fd(map),
            handler,
            context,
            null,
        );
        if (rb) |r| {
            return Self{ .inner = r };
        } else {
            return error.Failed;
        }
    }

    pub fn poll_once(self: *Self, timeout: std.Io.Duration) !void {
        const rc = c.ring_buffer__poll(self.inner, @intCast(timeout.toMilliseconds()));
        switch (std.posix.errno(rc)) {
            .SUCCESS => {},
            else => |e| return std.posix.unexpectedErrno(e),
        }
    }
};
