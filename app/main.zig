const std = @import("std");
const stdout = std.io.getStdOut().writer();
const allocator = std.heap.page_allocator;

const StringArrayList = std.ArrayList(u8);

pub fn main() !void {
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 3) {
        try stdout.print("Usage: your_bittorrent.zig <command> <args>\n", .{});
        std.process.exit(1);
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "decode")) {
        // Uncomment this block to pass the first stage
        const encodedStr = args[2];
        const decoded = decode(encodedStr) catch {
            try stdout.print("Couldn't decode value\n", .{});
            std.process.exit(1);
        };

        var string = StringArrayList.init(allocator);
        try writeDecoded(decoded, string.writer());
        const jsonStr = try string.toOwnedSlice();
        try stdout.print("{s}\n", .{jsonStr});
    }
}

const Value = union(enum) {
    string: []const u8,
    integer: []const u8,
    list: []Value,

    fn lenWithSpecifier(self: @This()) usize {
        return switch (self) {
            // 5:hello -> "hello".len + 5 + ':'
            .string => |str| str.len + countNumDigits(str.len) + 1,
            // i52e -> "52".len + 'i' + 'e'
            .integer => |int| int.len + 2,
            .list => |l| blk: {
                var count: usize = 2;
                for (l) |item| {
                    count += item.lenWithSpecifier();
                }
                break :blk count;
            },
        };
    }
};

fn decode(encodedValue: []const u8) !Value {
    switch (encodedValue[0]) {
        '0'...'9' => {
            const firstColon = std.mem.indexOf(u8, encodedValue, ":");
            if (firstColon == null) {
                return error.InvalidArgument;
            }
            const strLen = try std.fmt.parseInt(usize, encodedValue[0..firstColon.?], 10);
            const startPos = firstColon.? + 1;
            const endPos = startPos + strLen;
            return .{
                .string = encodedValue[startPos..endPos],
            };
        },
        'i' => {
            const endOfNum = std.mem.indexOf(u8, encodedValue, "e");
            if (endOfNum == null) {
                return error.InvalidArgument;
            }
            return .{
                .integer = encodedValue[1..endOfNum.?],
            };
        },
        'l' => {
            var cursor: usize = 1;
            var list = std.ArrayList(Value).init(allocator);
            while (cursor < encodedValue.len and encodedValue[cursor] != 'e') {
                const val = try decode(encodedValue[cursor..]);
                try list.append(val);
                cursor += val.lenWithSpecifier();
            }

            return .{
                .list = try list.toOwnedSlice(),
            };
        },
        else => {
            try stdout.print("Unknown case {c}", .{encodedValue[0]});
            std.process.exit(1);
        },
    }
}

fn writeDecoded(val: Value, writer: StringArrayList.Writer) !void {
    switch (val) {
        .string => |s| {
            try std.json.stringify(s, .{}, writer);
        },
        .integer => |int| {
            try writer.writeAll(int);
        },
        .list => |l| {
            try writer.writeByte('[');
            for (l, 0..) |item, i| {
                try writeDecoded(item, writer);
                if (i != l.len - 1) try writer.writeByte(',');
            }
            try writer.writeByte(']');
        },
    }
}

fn countNumDigits(n: usize) usize {
    var count: usize = 1;
    var num = n;
    while (num > 9) {
        num /= 10;
        count += 1;
    }
    return count;
}
