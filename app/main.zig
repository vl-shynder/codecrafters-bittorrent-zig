const std = @import("std");
const Commands = @import("commands.zig").Commands;
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
        const encodedStr = args[2];
        try Commands.decode(allocator, encodedStr);
    } else if (std.mem.eql(u8, command, "info")) {
        const filePath = args[2];
        try Commands.info(allocator, filePath);
    } else if (std.mem.eql(u8, command, "peers")) {
        const filePath = args[2];
        try Commands.peers(allocator, filePath);
    } else if (std.mem.eql(u8, command, "handshake")) {
        const filePath = args[2];
        try Commands.handshake(allocator, filePath, args[3]);
    } else if (std.mem.eql(u8, command, "download_piece")) {
        const outputFile = args[3];
        const filePath = args[4];
        const pieceIndex = try std.fmt.parseInt(u32, args[5], 10);
        try Commands.downloadPiece(allocator, outputFile, filePath, pieceIndex);
    } else if (std.mem.eql(u8, command, "download")) {
        const outputFile = args[3];
        const filePath = args[4];
        try Commands.download(allocator, outputFile, filePath);
    } else {
        try stdout.print("Unknown command {s}\n", .{command});
        std.process.exit(1);
    }
}

// fn dumpToWriter(bvalue: BencodeValue, writer: StringArrayList.Writer) !void {
//     switch (bvalue) {
//         .string => |s| {
//             try std.json.stringify(s, .{}, writer);
//         },
//         .integer => |int| {
//             try writer.writeAll(try numToString(i64, int));
//         },
//         .list => |l| {
//             try writer.writeByte('[');
//             for (l, 0..) |item, i| {
//                 try dumpToWriter(item, writer);
//                 if (i != l.len - 1) try writer.writeByte(',');
//             }
//             try writer.writeByte(']');
//         },
//         .dictionary => |d| {
//             try writer.writeByte('{');
//             var it = d.iterator();
//             var index: usize = 0;
//             while (it.next()) |entry| {
//                 index += 1;
//                 try writer.writeByte('"');
//                 try writer.writeAll(entry.key_ptr.*);
//                 try writer.writeByte('"');
//                 try writer.writeByte(':');
//                 try dumpToWriter(entry.value_ptr.*, writer);
//                 if (index != d.count()) {
//                     try writer.writeByte(',');
//                 }
//             }
//             try writer.writeByte('}');
//         },
//     }
// }
