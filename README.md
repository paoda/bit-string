# Bit String

A library to check and extract values from integers based on a "bit string". Primarily intended for (my) emulator instruction decoding, but maybe someone else can find a use for it?

## Example

```zig
const std = @import("std");

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
```

## Syntax

|  Token  |  Meaning  | Description
| ------- | --------- | -----------
| `0`     | Unset bit | In the equivalent position, the value's bit must be set.
| `1`     | Set bit   | In the equivalent position, the value's bit must be set.
| `a..=z` | Variable  | Given the 4-bit bit string, `"1aa0"`, the value `0b1010` would produce the variable `a` with the value `0b01`
| `-`     | Ignored   | In the equivalent position, the value's bit does not matter.

## Notes

- This library does the majority of it's work at `comptime`. Due to this, you cannot create strings to match against at runtime.
- Variables do not have to be "sequential". This means the 5-bit bit string `"1aa0a"` with the value `0b10101` will produce the variable `a` with the value `0b011`.
