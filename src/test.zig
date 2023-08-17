const std = @import("std");

comptime {
    _ = @import("lib.zig");
}

test {
    std.testing.refAllDecls(@This());
}
