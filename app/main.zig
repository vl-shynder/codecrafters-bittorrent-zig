const std = @import("std");
const stdout = std.io.getStdOut().writer();
const allocator = std.heap.page_allocator;

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
        const decoder = BencodeDecoder{
            .encodedValue = encodedStr,
        };

        if (decoder.isString()) {
            const decodedStr = decoder.decodeString() catch {
                try stdout.print("Invalid encoded value\n", .{});
                std.process.exit(1);
            };
            var string = std.ArrayList(u8).init(allocator);
            try std.json.stringify(decodedStr.*, .{}, string.writer());
            const jsonStr = try string.toOwnedSlice();
            try stdout.print("{s}\n", .{jsonStr});
        }
        if (decoder.isNumber()) {
            const decodedNum = decoder.decodeNumber() catch {
                try stdout.print("Invalid encoded value\n", .{});
                std.process.exit(1);
            };
            try stdout.print("{}\n", .{decodedNum});
        }
    }
}

const BencodeDecoder = struct {
    encodedValue: []const u8,

    const Self = @This();

    fn isString(self: Self) bool {
        return self.encodedValue[0] >= '0' and self.encodedValue[0] <= '9';
    }

    fn isNumber(self: Self) bool {
        return self.encodedValue[0] == 'i';
    }

    fn decodeString(self: Self) !*const []const u8 {
        const firstColon = std.mem.indexOf(u8, self.encodedValue, ":");
        if (firstColon == null) {
            return error.InvalidArgument;
        }
        return &self.encodedValue[firstColon.? + 1 ..];
    }

    fn decodeNumber(self: Self) !i64 {
        const endOfNum = std.mem.indexOf(u8, self.encodedValue, "e");
        if (endOfNum == null) {
            return error.InvalidArgument;
        }
        return std.fmt.parseInt(i64, self.encodedValue[1..endOfNum.?], 10);
    }
};
