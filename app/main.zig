const std = @import("std");
const stdout = std.io.getStdOut().writer();
const allocator = std.heap.page_allocator;

// pub const RED = "\x1b[31m";
// pub const GREEN = "\x1b[32m";
// pub const RESET = "\x1b[0m";

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

        var buf = try file.readToEndAlloc(allocator, 1024 * 1024);

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
                while (encodedValue[cursor] != 'e' and cursor < encodedValue.len) {
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
                try stdout.print("Unknown case {} \n", .{encodedValue[0]});
                std.process.exit(1);
            },
        }
    }

    fn encodeBencode(self: @This()) ![]const u8 {
        var encoded = StringArrayList.init(allocator);
        switch (self) {
            .string => |str| {
                const encStr = try std.fmt.allocPrint(allocator, "{}:{s}", .{ str.len, str });
                try encoded.appendSlice(encStr);
            },
            .integer => |int| {
                const encInt = try std.fmt.allocPrint(allocator, "i{s}e", .{int});
                try encoded.appendSlice(encInt);
            },
            .list => |list| {
                try encoded.append('l');
                for (list) |item| {
                    const encodedItem = try item.encodeBencode();
                    try encoded.appendSlice(encodedItem);
                }
                try encoded.append('e');
            },
            .dict => |dict| {
                try encoded.append('d');
                var it = dict.iterator();
                while (it.next()) |entry| {
                    const keyVal = Value{ .string = entry.key_ptr.* };
                    const encKey = try keyVal.encodeBencode();
                    const encEl = try entry.value_ptr.encodeBencode();
                    try encoded.appendSlice(encKey);
                    try encoded.appendSlice(encEl);
                }
                try encoded.append('e');
            },
        }

        return encoded.toOwnedSlice();
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

    fn print(self: @This()) ![]const u8 {
        return switch (self) {
            .string => |s| s,
            .integer => |i| i,
            else => |v| {
                var buf = [_]u8{'.'} ** 1000;
                _ = try std.fmt.bufPrint(&buf, "{}", .{v});
                return buf[0..];
            },
        };
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
                var count: usize = 2;
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

    fn len(self: @This()) !usize {
        return switch (self) {
            .string => |str| str.len,
            else => {
                try stdout.print("\x1b[31m .len() was called on a wrong value type \x1b[0m\n", .{});
                return 0;
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

fn writeDecodedInfo(decoded: Value, writer: StringArrayList.Writer) !void {
    switch (decoded) {
        .dict => |d| {
            try writer.writeAll("Tracker URL: ");
            const trackerURL = d.get("announce");
            if (trackerURL) |urlValue| {
                const url = try urlValue.print();
                try writer.writeAll(url);
            } else {
                try stdout.print("Can't find announce in provided file\n", .{});
            }

            const infoMapVal = d.get("info");
            if (infoMapVal) |infoVal| {
                const lengthMapVal = infoVal.dict.get("length");
                if (lengthMapVal) |lengthVal| {
                    const length = try lengthVal.print();
                    try writer.writeByte('\n');
                    try writer.writeAll("Length: ");
                    try writer.writeAll(length);
                } else {
                    try stdout.print("Can't find length in provided file\n", .{});
                }

                const encodedInfo = try infoVal.encodeBencode();
                var hash: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
                std.crypto.hash.Sha1.hash(encodedInfo, &hash, .{});

                try writer.writeByte('\n');
                try writer.writeAll("Info Hash: ");
                try writer.writeAll(&std.fmt.bytesToHex(&hash, .lower));

                const pieceLengthMapVal = infoVal.dict.get("piece length");
                if (pieceLengthMapVal) |pieceLengthVal| {
                    try writer.writeByte('\n');
                    try writer.writeAll("Piece Length: ");
                    try writer.writeAll(pieceLengthVal.integer);
                } else {
                    try stdout.print("Can't find piece length in provided file\n", .{});
                }

                const piecesMapVal = infoVal.dict.get("pieces");
                if (piecesMapVal) |piecesVal| {
                    try writer.writeByte('\n');
                    try writer.writeAll("Piece Hashes:");

                    var win = std.mem.window(u8, piecesVal.string, 20, 20);
                    while (win.next()) |piece| {
                        try writer.writeByte('\n');
                        const h = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(piece[0..20])});
                        try writer.writeAll(h);
                    }
                } else {
                    try stdout.print("Can't find pieces in provided file\n", .{});
                }
            } else {
                try stdout.print("Can't find info in provided file\n", .{});
            }
        },
        else => {
            try stdout.print("Shouldn't be the case\n", .{});
            std.process.exit(1);
        },
    }
}
