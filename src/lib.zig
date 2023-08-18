//! A library to check and extract values from integers based on a "bit string". Primarily intended for (my) emulator instruction decoding, but maybe someone else can find a use for it?
//!
//! ## Example
//! ```zig
//! const std = @import("std");
//!
//! test "doc test" {
//!     const value: u8 = 0b10001011;
//!
//!     try std.testing.expectEqual(true, match("10001011", value));
//!     try std.testing.expectEqual(false, match("11111011", value));
//!     try std.testing.expectEqual(true, match("1---1011", value));
//!
//!     {
//!         const ret = extract("1000aaaa", value);
//!         try std.testing.expectEqual(@as(u4, 0b1011), ret.a);
//!     }
//!     {
//!         const ret = extract("1aaa1aaa", value);
//!         try std.testing.expectEqual(@as(u6, 0b000011), ret.a);
//!     }
//!     {
//!         const ret = extract("1---abcd", value);
//!         try std.testing.expectEqual(@as(u3, 0b1), ret.a);
//!         try std.testing.expectEqual(@as(u3, 0b0), ret.b);
//!         try std.testing.expectEqual(@as(u3, 0b1), ret.c);
//!         try std.testing.expectEqual(@as(u3, 0b1), ret.d);
//!     }
//! }
//! ```
//! ## Syntax
//! |  Token  |  Meaning  | Description
//! | ------- | --------- | -----------
//! | `0`     | Unset bit | In the equivalent position, the value's bit must be set.
//! | `1`     | Set bit   | In the equivalent position, the value's bit must be set.
//! | `a..=z` | Variable  | Given the 4-bit bit string, `"1aa0"`, the value `0b1010` would produce the variable `a` with the value `0b01`
//! | `-`     | Ignored   | In the equivalent position, the value's bit does not matter.
//!
//! ## Notes
//! - This library does the majority of it's work at `comptime`. Due to this, you cannot create strings to match against at runtime.
//! - Variables do not have to be "sequential". This means the 5-bit bit string `"1aa0a"` with the value `0b10101` will produce the variable `a` with the value `0b011`.

const std = @import("std");
const Log2Int = std.math.Log2Int;

/// Test to see if a value matches the provided bit-string
///
/// ### Example
/// ```zig
/// match("1100", @as(u4, 0b1100)) // true
/// match("1100", @as(u4, 0b1110)) // false
/// match("1--0", @as(u4, 0b1010)) // true
/// match("1ab0", @as(u4, 0b1010)) // true
/// ```
pub fn match(comptime bit_string: []const u8, value: anytype) bool {
    const ValT = @TypeOf(value);
    comptime verify(ValT, bit_string);

    const masks: struct { ValT, ValT } = comptime blk: {
        const bit_count = @typeInfo(ValT).Int.bits;

        var set: ValT = 0;
        var clr: ValT = 0;

        // FIXME: I linear search bit_string 4 separate times. Consider doing a single search and compromizing on memory + stateless API? (imagine a "regex compile"-like API)
        for (bit_string, 0..) |char, i| {
            switch (char) {
                '0' => clr |= @as(ValT, 1) << @intCast(bit_count - 1 - i),
                '1' => set |= @as(ValT, 1) << @intCast(bit_count - 1 - i),
                'a'...'z', '-' => continue,
                else => @compileError("'" ++ [_]u8{char} ++ "' was unexpected when parsing bitstring"),
            }
        }

        break :blk .{ set, clr };
    };

    const set_mask = masks[0];
    const clr_mask = masks[1];

    return (value & set_mask) == set_mask and (~value & clr_mask) == clr_mask;
}

test "match" {
    // doc tests
    try std.testing.expectEqual(true, match("1100", @as(u4, 0b1100))); // true
    try std.testing.expectEqual(false, match("1100", @as(u4, 0b1110))); // false
    try std.testing.expectEqual(true, match("1--0", @as(u4, 0b1010))); // true
    try std.testing.expectEqual(true, match("1ab0", @as(u4, 0b1010))); // true

    // other tests
    try std.testing.expectEqual(true, match("11111111", @as(u8, 0b11111111)));
    try std.testing.expectEqual(true, match("10110011", @as(u8, 0b10110011)));
    try std.testing.expectEqual(true, match("101aaabb", @as(u8, 0b10110001)));
    try std.testing.expectEqual(true, match("abcdefgh", @as(u8, 0b10110101)));
    try std.testing.expectEqual(true, match("aaa---11", @as(u8, 0b01011111)));
    try std.testing.expectEqual(true, match("1a0b1c0d", @as(u8, 0b10011101)));
    try std.testing.expectEqual(false, match("aaa---11", @as(u8, 0b01011110)));
}

/// Extracts the variables (defined in the bit string) from a value.
///
/// ### Examples
/// ```
/// const ret = extract("aaaa", @as(u4, 0b1001)); // ret.a == 0b1001
/// const ret = extract("abcd", @as(u4, 0b1001)); // ret.a == 0b1, ret.b == 0b0, ret.c == 0b0, ret.d == 0b1
/// const ret = extract("a0ab", @as(u4, 0b1001)); // ret.a == 0b10, ret.b == 0b1
/// const ret = extract("-a-a", @as(u4, 0b1001)); // ret.a == 0b01
/// ```
///
/// Note: In Debug and ReleaseSafe builds, there's a runtime assert that
/// ensures that the value matches against the bit string.
pub fn extract(comptime bit_string: []const u8, value: anytype) Bitfield(bit_string) {
    const builtin = @import("builtin");

    const ValT = @TypeOf(value);
    const ReturnT = Bitfield(bit_string);
    const bmi2 = switch (builtin.target.cpu.arch) {
        .x86_64 => std.Target.x86.featureSetHas(builtin.cpu.features, .bmi2),
        else => false,
    };
    comptime verify(ValT, bit_string);

    var ret: ReturnT = undefined;

    inline for (@typeInfo(ReturnT).Struct.fields) |field| {
        @field(ret, field.name) = blk: {
            var masked_val: ValT = 0;

            for (bit_string, 0..) |char, i| {
                const rev = @typeInfo(ValT).Int.bits - 1 - i;
                if (char == field.name[0]) masked_val |= @as(ValT, 1) << @intCast(rev); // no penalty
            }

            // TODO: decide at compile time if we're calling the 32-bit or 64-bit version of `PEXT`

            // invariant: the bit count in the field we're writing to and the
            // # of bits we happened to find in this linear search are identical
            //
            // we're confident in this because it's guaranteed to be the same bit_string,
            // and it's the same linear search. If you're reading this double check that this is still the case lol
            break :blk @truncate(if (bmi2) pext.hardware(u32, value, masked_val) else pext.software(u32, value, masked_val));
        };
    }

    return ret;
}

pub fn matchExtract(comptime bit_string: []const u8, value: anytype) ?Bitfield(bit_string) {
    if (!match(bit_string, value)) return null;
    return extract(bit_string, value);
}

test "extract" {
    // doc tests
    {
        const ret = extract("aaaa", @as(u4, 0b1001));
        try std.testing.expectEqual(@as(u4, 0b1001), ret.a);
    }
    {
        const ret = extract("abcd", @as(u4, 0b1001));
        try std.testing.expectEqual(@as(u1, 0b1), ret.a);
        try std.testing.expectEqual(@as(u1, 0b0), ret.b);
        try std.testing.expectEqual(@as(u1, 0b0), ret.c);
        try std.testing.expectEqual(@as(u1, 0b1), ret.d);
    }
    {
        const ret = extract("a0ab", @as(u4, 0b1001));
        try std.testing.expectEqual(@as(u2, 0b10), ret.a);
        try std.testing.expectEqual(@as(u1, 0b01), ret.b);
    }
    {
        const ret = extract("-a-a", @as(u4, 0b1001));
        try std.testing.expectEqual(@as(u2, 0b01), ret.a);
    }

    // other tests
    {
        const ret = extract("10aaabbc", @as(u8, 0b10110011));
        try std.testing.expectEqual(@as(u3, 0b110), ret.a);
        try std.testing.expectEqual(@as(u2, 0b01), ret.b);
        try std.testing.expectEqual(@as(u1, 0b1), ret.c);
    }
    {
        const ret = extract("1111abababab1010", @as(u16, 0b1111_1110_1101_1010));
        try std.testing.expectEqual(@as(u4, 0b1110), ret.a);
        try std.testing.expectEqual(@as(u4, 0b1011), ret.b);
    }
    {
        const ret = extract("--------ddddrrrr", @as(u16, 0b0000_0010_1011_0110));
        try std.testing.expectEqual(@as(u4, 0b1011), ret.d);
        try std.testing.expectEqual(@as(u4, 0b0110), ret.r);
    }
    {
        const ret = extract("--------", @as(u8, 0b00000000));
        const T = @TypeOf(ret);

        try std.testing.expectEqual(@as(usize, 0), @typeInfo(T).Struct.fields.len);
    }
    {
        const ret = extract("00000000", @as(u8, 0b00000000));
        const T = @TypeOf(ret);

        try std.testing.expectEqual(@as(usize, 0), @typeInfo(T).Struct.fields.len);
    }
    {
        const ret = extract("0-0-0-0-", @as(u8, 0b01010101));
        const T = @TypeOf(ret);

        try std.testing.expectEqual(@as(usize, 0), @typeInfo(T).Struct.fields.len);
    }
}

/// Parses a bit string and reifies a struct that will contain fields that correspond to the variables present in the bit string.
///
///
/// Note: If it weren't for the return type of `extract()`, this type would be a private implementation detail
///
/// TODO: I will probably rename this type
pub fn Bitfield(comptime bit_string: []const u8) type {
    const StructField = std.builtin.Type.StructField;

    const alphabet_set: u26 = tmp: {
        var bit_set: u26 = 0;

        for (bit_string) |char| {
            switch (char) {
                'a'...'z' => |c| bit_set |= @as(u26, 1) << @intCast(c - 'a'),
                else => continue,
            }
        }

        break :tmp bit_set;
    };

    const field_len = @popCount(alphabet_set);

    const fields = blk: {
        var tmp: [field_len]StructField = undefined;

        const Tmp = struct { bits: u8 = 0, char: ?u8 = null };
        var things: [field_len]Tmp = [_]Tmp{.{}} ** field_len; // TODO: rename this lol

        for (bit_string) |char| {
            switch (char) {
                'a'...'z' => |c| {
                    const bit_in_set = @as(u26, 1) << @intCast(c - 'a');
                    const pos = @popCount(alphabet_set & ~(bit_in_set - 1)) - 1; // TODO: investigate this off-by-one

                    things[pos].bits += 1;
                    things[pos].char = c;
                },
                '1', '0', '-' => continue,
                else => @compileError("error when parsing bitset string"),
            }
        }

        for (things, &tmp) |th, *field| {
            const FieldInt = @Type(.{ .Int = .{ .signedness = .unsigned, .bits = th.bits } });

            field.* = .{
                .name = &.{th.char.?},
                .type = FieldInt,
                .default_value = null,
                .is_comptime = false,
                .alignment = @alignOf(FieldInt),
            };
        }

        break :blk tmp;
    };

    return @Type(.{ .Struct = .{
        .layout = .Auto,
        .fields = &fields,
        .decls = &.{},
        .is_tuple = false,
    } });
}

fn verify(comptime T: type, comptime bit_string: []const u8) void {
    const info = @typeInfo(T);

    // FIXME: remove the need for this
    if (info.Int.bits > 32) @compileError("TODO: 64-bit `PEXT` software implementation");

    std.debug.assert(info != .ComptimeInt);
    std.debug.assert(info.Int.signedness == .unsigned);
    std.debug.assert(info.Int.bits <= 64); // x86 PEXT u32 and u64 operands only
    std.debug.assert(bit_string.len == info.Int.bits); // TODO: Support Underscores?
}

const pext = struct {
    fn hardware(comptime T: type, value: T, mask: T) T {
        return switch (T) {
            u32 => asm ("pextl %[mask], %[value], %[ret]"
                : [ret] "=r" (-> T),
                : [value] "r" (value),
                  [mask] "r" (mask),
            ),
            u64 => asm ("pextq %[mask], %[value], %[ret]"
                : [ret] "=r" (-> T),
                : [value] "r" (value),
                  [mask] "r" (mask),
            ),
            else => @compileError("pext is sunsupported for " ++ @typeName(T) ++ "."),
        };
    }

    // why we need this: https://github.com/ziglang/zig/issues/14995 (ideally compiler-rt implements this for us)
    fn software(comptime T: type, value: T, mask: T) T {
        return switch (T) {
            u32 => {
                // TODO: Looks (and is) like C code :pensive:
                // code source: https://stackoverflow.com/questions/41720249/detecting-matching-bits-in-c

                var _value: T = value;
                var _mask: T = mask;

                _value &= _mask;
                var mk: T = ~_mask << 1;
                var mp: T = undefined;
                var mv: T = undefined;
                var t: T = undefined;

                inline for (0..@typeInfo(u5).Int.bits) |i| {
                    mp = mk ^ (mk << 1); // parallel suffix
                    mp = mp ^ (mp << 2);
                    mp = mp ^ (mp << 4);
                    mp = mp ^ (mp << 8);
                    mp = mp ^ (mp << 16);
                    mv = (mp & _mask); // bits to move
                    _mask = ((_mask ^ mv) | (mv >> (1 << i))); // compress _mask
                    t = (_value & mv);
                    _value = ((_value ^ t) | (t >> (1 << i))); // compress _value
                    mk &= ~mp;
                }

                return _value;
            },
            u64 => @compileError("TODO: find/write branchless software impl of `PEXT` for 64-bit values"),
            else => @compileError("pext is sunsupported for " ++ @typeName(T) ++ "."),
        };
    }

    test "pext" {
        const builtin = @import("builtin");

        switch (builtin.cpu.arch) {
            .x86_64 => if (std.Target.x86.featureSetHas(builtin.cpu.features, .bmi2)) {
                try std.testing.expectEqual(@as(u32, 0x0001_2567), pext.hardware(u32, 0x12345678, 0xFF00FFF0));
                try std.testing.expectEqual(@as(u64, 0x0001_2567), pext.hardware(u64, 0x12345678, 0xFF00FFF0));

                // random tests
                // TODO: when implemented, test 64-bit fallback `PEXT` as well
                var rand_impl = std.rand.DefaultPrng.init(0xBAADF00D_DEADCAFE);
                for (0..100) |_| {
                    const value = rand_impl.random().int(u32);
                    const mask = rand_impl.random().int(u32);

                    try std.testing.expectEqual(pext.hardware(u32, value, mask), pext.software(u32, value, mask));
                }
            },
            else => {},
        }

        // example values from: https://en.wikipedia.org/w/index.php?title=X86_Bit_manipulation_instruction_set&oldid=1170426748
        try std.testing.expectEqual(@as(u32, 0x0001_2567), pext.software(u32, 0x12345678, 0xFF00FFF0));
    }
};

test "doc test" {
    const value: u8 = 0b10001011;

    try std.testing.expectEqual(true, match("10001011", value));
    try std.testing.expectEqual(false, match("11111011", value));
    try std.testing.expectEqual(true, match("1---1011", value));

    {
        const ret = extract("1000aaaa", value);
        try std.testing.expectEqual(@as(u4, 0b1011), ret.a);
    }
    {
        const ret = extract("1aaa1aaa", value);
        try std.testing.expectEqual(@as(u6, 0b000011), ret.a);
    }
    {
        const ret = extract("1---abcd", value);
        try std.testing.expectEqual(@as(u3, 0b1), ret.a);
        try std.testing.expectEqual(@as(u3, 0b0), ret.b);
        try std.testing.expectEqual(@as(u3, 0b1), ret.c);
        try std.testing.expectEqual(@as(u3, 0b1), ret.d);
    }
}
