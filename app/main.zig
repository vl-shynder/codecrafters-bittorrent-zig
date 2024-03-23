const std = @import("std");
const stdout = std.io.getStdOut().writer();
const allocator = std.heap.page_allocator;

const StringArrayList = std.ArrayList(u8);
const Dictionary = std.StringArrayHashMap(Value);

pub fn main() !void {
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 3) {
        try stdout.print("Usage: your_bittorrent.zig <command> <args>\n", .{});
        std.process.exit(1);
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "decode")) {
        const encodedStr = args[2];
        const decoded = Value.decode(encodedStr) catch {
            try stdout.print("Couldn't decode value\n", .{});
            std.process.exit(1);
        };

        var string = StringArrayList.init(allocator);
        try decoded.dumpToWriter(string.writer());
        const jsonStr = try string.toOwnedSlice();
        try stdout.print("{s}\n", .{jsonStr});
    } else if (std.mem.eql(u8, command, "info")) {
        const filePath = args[2];

        var file = try std.fs.cwd().openFile(filePath, .{});
        var bufReader = std.io.bufferedReader(file.reader());
        var reader = bufReader.reader();

        var buf = try reader.readAllAlloc(allocator, 1024 * 1024);

        const decoded = Value.decode(buf[0..]) catch {
            try stdout.print("Couldn't decode value\n", .{});
            std.process.exit(1);
        };

        var string = StringArrayList.init(allocator);
        try writeDecodedInfo(decoded, string.writer());
        const jsonStr = try string.toOwnedSlice();
        try stdout.print("{s}\n", .{jsonStr});
    }
}

const Value = union(enum) {
    string: []const u8,
    integer: []const u8,
    list: []Value,
    dict: Dictionary,

    fn decode(encodedValue: []const u8) !@This() {
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
                while (cursor < encodedValue.len) {
                    if (encodedValue[cursor] == 'e') {
                        cursor += 1;
                        break;
                    }
                    const val = try decode(encodedValue[cursor..]);
                    try list.append(val);
                    cursor += val.lenWithSpecifier();
                }

                return .{
                    .list = try list.toOwnedSlice(),
                };
            },
            'd' => {
                var cursor: usize = 1;
                var dict = Dictionary.init(allocator);
                while (cursor < encodedValue.len and encodedValue[cursor] != 23) {
                    if (encodedValue[cursor] == 'e') {
                        cursor += 1;
                        break;
                    }

                    const key = try decode(encodedValue[cursor..]);
                    if (!key.isString()) {
                        try stdout.print("Dectionary value for key is not a string. key = {any},\n", .{key});
                    }
                    cursor += key.lenWithSpecifier();
                    const value = try decode(encodedValue[cursor..]);
                    cursor += value.lenWithSpecifier();
                    try dict.put(key.string, value);
                }

                return .{
                    .dict = dict,
                };
            },
            else => {
                try stdout.print("Unknown case\n", .{});
                std.process.exit(1);
            },
        }
    }

    fn dumpToWriter(self: @This(), writer: StringArrayList.Writer) !void {
        switch (self) {
            .string => |s| {
                try std.json.stringify(s, .{}, writer);
            },
            .integer => |int| {
                try writer.writeAll(int);
            },
            .list => |l| {
                try writer.writeByte('[');
                for (l, 0..) |item, i| {
                    try item.dumpToWriter(writer);
                    if (i != l.len - 1) try writer.writeByte(',');
                }
                try writer.writeByte(']');
            },
            .dict => |d| {
                try writer.writeByte('{');
                var it = d.iterator();
                var index: usize = 0;
                while (it.next()) |entry| {
                    index += 1;
                    try writer.writeByte('"');
                    try writer.writeAll(entry.key_ptr.*);
                    try writer.writeByte('"');
                    try writer.writeByte(':');
                    try entry.value_ptr.dumpToWriter(writer);
                    if (index != d.count()) {
                        try writer.writeByte(',');
                    }
                }
                try writer.writeByte('}');
            },
        }
    }

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
            .dict => |dict| blk: {
                var count: usize = 0;
                var it = dict.iterator();
                while (it.next()) |entry| {
                    const keyVal = Value{ .string = entry.key_ptr.* };
                    count += keyVal.lenWithSpecifier();
                    count += entry.value_ptr.lenWithSpecifier();
                }
                break :blk count;
            },
        };
    }

    fn isString(self: @This()) bool {
        return switch (self) {
            .string => true,
            else => false,
        };
    }
};

fn countNumDigits(n: usize) usize {
    var count: usize = 1;
    var num = n;
    while (num > 9) {
        num /= 10;
        count += 1;
    }
    return count;
}

fn printValue(val: Value) ![]const u8 {
    return switch (val) {
        .string => |s| s,
        .integer => |i| i,
        else => |v| {
            var buf = [_]u8{'.'} ** 1000;
            _ = try std.fmt.bufPrint(&buf, "{}", .{v});
            return buf[0..];
        },
    };
}

fn writeDecodedInfo(decoded: Value, writer: StringArrayList.Writer) !void {
    switch (decoded) {
        .dict => |d| {
            try writer.writeAll("Tracker URL: ");
            const trackerURL = d.get("announce");
            if (trackerURL) |urlValue| {
                const url = try printValue(urlValue);
                try writer.writeAll(url);
            } else {
                try stdout.print("Can't find announce in provided file\n", .{});
            }

            try writer.writeByte('\n');
            try writer.writeAll("Length: ");
            const infoMapVal = d.get("info");
            if (infoMapVal) |infoVal| {
                const lengthMapVal = infoVal.dict.get("length");
                if (lengthMapVal) |lengthVal| {
                    const length = try printValue(lengthVal);
                    try writer.writeAll(length);
                } else {
                    try stdout.print("Can't find length in provided file\n", .{});
                }
                try stdout.print("Can't find info in provided file\n", .{});
            }
        },
        else => {
            try stdout.print("Shouldn't be the case\n", .{});
            std.process.exit(1);
        },
    }
}
