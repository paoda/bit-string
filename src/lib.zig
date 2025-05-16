//! A library to check and extract values from integers based on a "bit string". Primarily intended for (my) emulator instruction decoding, but maybe someone else can find a use for it?
//!
//! ## Example
//! ```zig
//! const std = @import("std");
//!
//! test "doc test" {
//!    const value: u8 = 0b10001011;
//!
//!    try std.testing.expectEqual(true, match("1000_1011", value));
//!    try std.testing.expectEqual(false, match("11111011", value));
//!    try std.testing.expectEqual(true, match("1---1011", value));
//!
//!    {
//!        const ret = extract("1000aaaa", value);
//!        try std.testing.expectEqual(@as(u4, 0b1011), ret.a);
//!    }
//!    {
//!        const ret = extract("1aaa1aaa", value);
//!        try std.testing.expectEqual(@as(u6, 0b000011), ret.a);
//!    }
//!    {
//!        const ret = extract("1---abcd", value);
//!        try std.testing.expectEqual(@as(u3, 0b1), ret.a);
//!        try std.testing.expectEqual(@as(u3, 0b0), ret.b);
//!        try std.testing.expectEqual(@as(u3, 0b1), ret.c);
//!        try std.testing.expectEqual(@as(u3, 0b1), ret.d);
//!    }
//! }
//! ```
//! ## Syntax
//! |  Token  |  Meaning  | Description                                                                                                   |
//! | :-----: | --------- | ------------------------------------------------------------------------------------------------------------- |
//! | `0`     | Clear bit | In the equivalent position, the value's bit must be cleared.                                                  |
//! | `1`     | Set bit   | In the equivalent position, the value's bit must be set.                                                      |
//! | `a..=z` | Variable  | Given the 4-bit bit string, `"1aa0"`, the value `0b1010` would produce the variable `a` with the value `0b01` |
//! | `-`     | Ignored   | In the equivalent position, the value's bit does not matter.                                                  |
//! | `_`     | Ignored*  | Underscores are completely ignored during parsing, use to make bit strings easier to read e.g. `1111_1111`    |
//!
//! ## Notes
//! - This library does the majority of it's work at `comptime`. Due to this, you cannot create strings to match against at runtime.
//! - Variables do not have to be "sequential". This means the 5-bit bit string `"1aa0a"` with the value `0b10101` will produce the variable `a` with the value `0b011`.

const std = @import("std");
const Log2Int = std.math.Log2Int;

/// Test to see if a value matches the provided bit-string
pub fn match(comptime bit_string: []const u8, value: anytype) bool {
    @setEvalBranchQuota(std.math.maxInt(u32)); // FIXME: bad practice

    const ValT = @TypeOf(value);
    comptime verify(ValT, bit_string);

    const masks: struct { ValT, ValT } = comptime blk: {
        const bit_count = @typeInfo(ValT).int.bits;

        var set: ValT = 0;
        var clr: ValT = 0;
        var offset = 0;

        // FIXME: I linear search like this 5 times across the entire lib. Consider structuring this like a regex lib (compiling a match)
        for (bit_string, 0..) |char, i| {
            switch (char) {
                '0' => clr |= @as(ValT, 1) << @intCast((bit_count - 1 - (i - offset))),
                '1' => set |= @as(ValT, 1) << @intCast((bit_count - 1 - (i - offset))),
                '_' => offset += 1,
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

test match {
    // doc tests
    try std.testing.expectEqual(true, match("1100", @as(u4, 0b1100)));
    try std.testing.expectEqual(false, match("1100", @as(u4, 0b1110)));

    try std.testing.expectEqual(true, match("1--0", @as(u4, 0b1010)));
    try std.testing.expectEqual(true, match("1ab0", @as(u4, 0b1010)));
    try std.testing.expectEqual(true, match("11_00", @as(u4, 0b1100)));

    // other tests
    try std.testing.expectEqual(true, match("11111111", @as(u8, 0b11111111)));
    try std.testing.expectEqual(true, match("10110011", @as(u8, 0b10110011)));
    try std.testing.expectEqual(true, match("101aaabb", @as(u8, 0b10110001)));
    try std.testing.expectEqual(true, match("abcdefgh", @as(u8, 0b10110101)));
    try std.testing.expectEqual(true, match("aaa---11", @as(u8, 0b01011111)));
    try std.testing.expectEqual(true, match("1a0b1c0d", @as(u8, 0b10011101)));
    try std.testing.expectEqual(false, match("aaa---11", @as(u8, 0b01011110)));

    try std.testing.expectEqual(true, match("1111_1111", @as(u8, 0b11111111)));
    try std.testing.expectEqual(true, match("________11111111", @as(u8, 0b11111111)));
    try std.testing.expectEqual(true, match("11111111________", @as(u8, 0b11111111)));

    try std.testing.expectEqual(true, match(
        "11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111",
        @as(u64, 0xFFFF_FFFF_FFFF_FFFF),
    ));
}

/// Extracts the variables (defined in the bit string) from a value.
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

    inline for (@typeInfo(ReturnT).@"struct".fields) |field| {
        @field(ret, field.name) = blk: {
            var masked_val: ValT = 0;
            var offset: usize = 0; // FIXME(URGENT): this whole block should be happening at comptime...

            for (bit_string, 0..) |char, i| {
                const rev = @typeInfo(ValT).int.bits - 1 - (i - offset);

                switch (char) {
                    '_' => offset += 1,
                    else => if (char == field.name[0]) {
                        masked_val |= @as(ValT, 1) << @intCast(rev); // no penalty
                    },
                }
            }

            const PextT = if (@typeInfo(ValT).int.bits > 32) u64 else u32;
            const use_hw = bmi2 and !@inComptime();

            break :blk @truncate(if (use_hw) pext.hw(PextT, value, masked_val) else pext.sw(PextT, value, masked_val));
        };
    }

    return ret;
}

test extract {
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
    {
        const ret = extract("aa_aa", @as(u4, 0b1001));
        try std.testing.expectEqual(@as(u4, 0b1001), ret.a);
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

        try std.testing.expectEqual(@as(usize, 0), @typeInfo(T).@"struct".fields.len);
    }
    {
        const ret = extract("00000000", @as(u8, 0b00000000));
        const T = @TypeOf(ret);

        try std.testing.expectEqual(@as(usize, 0), @typeInfo(T).@"struct".fields.len);
    }
    {
        const ret = extract("0-0-0-0-", @as(u8, 0b01010101));
        const T = @TypeOf(ret);

        try std.testing.expectEqual(@as(usize, 0), @typeInfo(T).@"struct".fields.len);
    }

    {
        const ret = extract(
            "11111111_ssssssss_11111111_dddddddd_11111111_vvvvvvvv_11111111_xxxxxxxx",
            @as(u64, 0xFF55_FF77_FF33_FF00),
        );

        try std.testing.expectEqual(@as(u8, 0x55), ret.s);
        try std.testing.expectEqual(@as(u8, 0x77), ret.d);
        try std.testing.expectEqual(@as(u8, 0x33), ret.v);
        try std.testing.expectEqual(@as(u8, 0x00), ret.x);
    }
}

pub fn matchExtract(comptime bit_string: []const u8, value: anytype) ?Bitfield(bit_string) {
    if (!match(bit_string, value)) return null;
    return extract(bit_string, value);
}

/// Parses a bit string and reifies a struct that will contain fields that correspond to the variables present in the bit string.
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
                '1', '0', '-', '_' => continue,
                else => @compileError("unexpected char '" ++ [_]u8{char} ++ "' when parsing bit string"),
            }
        }

        for (things, &tmp) |th, *field| {
            const FieldInt = @Type(.{ .int = .{ .signedness = .unsigned, .bits = th.bits } });

            field.* = .{
                .name = &.{th.char.?},
                .type = FieldInt,
                .default_value_ptr = null,
                .is_comptime = false,
                .alignment = @alignOf(FieldInt),
            };
        }

        break :blk tmp;
    };

    return @Type(.{ .@"struct" = .{
        .layout = .auto,
        .fields = &fields,
        .decls = &.{},
        .is_tuple = false,
    } });
}

fn verify(comptime T: type, comptime bit_string: []const u8) void {
    const info = @typeInfo(T);

    std.debug.assert(info != .comptime_int);
    std.debug.assert(info.int.signedness == .unsigned);
    std.debug.assert(info.int.bits <= 64); // x86 PEXT u32 and u64 operands only

    var underscore_count = 0;
    for (bit_string) |c| {
        if (c == '_') underscore_count += 1;
    }

    std.debug.assert((bit_string.len - underscore_count) == info.int.bits);
}

const pext = struct {
    fn hw(comptime T: type, value: T, mask: T) T {
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

    inline fn sw(comptime T: type, value: T, mask: T) T {
        // FIXME: will be replaced in the future by https://github.com/ziglang/zig/issues/14995 (hopefully?)

        return switch (T) {
            u32, u64 => {
                // code source: https://stackoverflow.com/questions/41720249/detecting-matching-bits-in-c
                // TODO: rewrite more in generic/idiomatic zig
                const log2_bits = @typeInfo(Log2Int(T)).int.bits;

                var val: T = value & mask; // immediately clear irrelevant bits
                var msk: T = mask;

                var mk: T = ~msk << 1; // count 0s to the right

                inline for (0..log2_bits) |i| {
                    var mp: T = mk ^ (mk << 1);
                    inline for (1..log2_bits) |j| {
                        mp = mp ^ (mp << (1 << j)); // parallel suffix
                    }

                    const mv = (mp & msk); // bits to move
                    msk = ((msk ^ mv) | (mv >> (1 << i))); // compress mask

                    const t = (val & mv);
                    val = ((val ^ t) | (t >> (1 << i))); // compress val

                    mk &= ~mp;
                }

                return val;
            },
            else => @compileError("pext is sunsupported for " ++ @typeName(T) ++ "."),
        };
    }

    test pext {
        const builtin = @import("builtin");

        try std.testing.expectEqual(@as(u32, 0x0001_2567), pext.sw(u32, 0x12345678, 0xFF00FFF0));
        try std.testing.expectEqual(@as(u64, 0x0001_2567), pext.sw(u64, 0x12345678, 0xFF00FFF0));

        switch (builtin.cpu.arch) {
            .x86_64 => if (std.Target.x86.featureSetHas(builtin.cpu.features, .bmi2)) {
                var rand_impl = std.Random.DefaultPrng.init(0xBAADF00D_DEADCAFE);

                for (0..100) |_| {
                    const value = rand_impl.random().int(u32);
                    const mask = rand_impl.random().int(u32);

                    try std.testing.expectEqual(pext.hw(u32, value, mask), pext.sw(u32, value, mask));
                }

                for (0..100) |_| {
                    const value = rand_impl.random().int(u64);
                    const mask = rand_impl.random().int(u64);

                    try std.testing.expectEqual(pext.hw(u64, value, mask), pext.sw(u64, value, mask));
                }
            },
            else => return error.SkipZigTest,
        }

        // example values from: https://en.wikipedia.org/w/index.php?title=X86_Bit_manipulation_instruction_set&oldid=1170426748
        try std.testing.expectEqual(@as(u32, 0x0001_2567), pext.sw(u32, 0x12345678, 0xFF00FFF0));
    }
};

test "doc test" {
    const value: u8 = 0b10001011;

    try std.testing.expectEqual(true, match("1000_1011", value));
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
