const std = @import("std");
const stdout = std.io.getStdOut().writer();

const StringArrayList = std.ArrayList(u8);

const Handshake = extern struct {
    protocolLength: u8 = 19,
    ident: [19]u8 = "BitTorrent protocol".*,
    reserved: [8]u8 = std.mem.zeroes([8]u8),
    infoHash: [20]u8,
    peerId: [20]u8,
};

const BitTorrent = struct {
    decoded: Commands.BencodeValue,
    announce: []const u8,
    info: struct {
        length: i64,
        name: []const u8,
        pieceLength: i64,
        pieces: []const u8,
    },

    const TorrentError = error{
        InvalidTorrentFile,
        InvalidAnnounce,
        InvalidInfo,
        InvalidInfoLength,
        InvalidInfoName,
        InvalidInfoPieceLength,
        InvalidInfoPieces,
    };

    fn parseFile(allocator: std.mem.Allocator, path: []const u8) !@This() {
        var file = try std.fs.cwd().openFile(path, .{});
        var buf = try file.readToEndAlloc(allocator, 1024 * 1024);
        const decoded = try Commands.decodeBencode(allocator, buf);

        if (decoded != .dictionary) return TorrentError.InvalidTorrentFile;
        const announce = decoded.dictionary.get("announce");
        if (announce == null) return TorrentError.InvalidAnnounce;
        if (announce.? != .string) return TorrentError.InvalidAnnounce;

        const info = decoded.dictionary.get("info");
        if (info == null) return TorrentError.InvalidInfo;
        if (info.? != .dictionary) return TorrentError.InvalidInfo;

        const length = info.?.dictionary.get("length");
        if (length == null) return TorrentError.InvalidInfoLength;
        if (length.? != .integer) return TorrentError.InvalidInfoLength;

        const name = info.?.dictionary.get("name");
        if (name == null) return TorrentError.InvalidInfoName;
        if (name.? != .string) return TorrentError.InvalidInfoName;

        const pieceLength = info.?.dictionary.get("piece length");
        if (pieceLength == null) return TorrentError.InvalidInfoPieceLength;
        if (pieceLength.? != .integer) return TorrentError.InvalidInfoPieceLength;

        const pieces = info.?.dictionary.get("pieces");
        if (pieces == null) return TorrentError.InvalidInfoPieces;
        if (pieces.? != .string) return TorrentError.InvalidInfoPieces;

        return .{
            .decoded = decoded,
            .announce = announce.?.string,
            .info = .{
                .length = length.?.integer,
                .name = name.?.string,
                .pieceLength = pieceLength.?.integer,
                .pieces = pieces.?.string,
            },
        };
    }
};

pub const Commands = struct {
    allocator: std.mem.Allocator,

    const BencodeDict = std.StringArrayHashMap(BencodeValue);

    const BencodeValue = union(enum) {
        string: []const u8,
        integer: i64,
        list: []BencodeValue,
        dictionary: BencodeDict,

        fn lenEncoded(self: @This()) usize {
            return switch (self) {
                // 5:hello -> "hello".len + 5 + ':'
                .string => |str| str.len + countNumDigits(str.len) + 1,
                // i52e -> "52".len + 'i' + 'e'
                .integer => |int| blk: {
                    var buf: [1024]u8 = undefined;
                    const strInt = std.fmt.bufPrint(&buf, "{d}", .{int}) catch "";
                    break :blk strInt.len + 2;
                },
                .list => |l| blk: {
                    var count: usize = 2;
                    for (l) |item| {
                        count += item.lenEncoded();
                    }
                    break :blk count;
                },
                .dictionary => |dict| blk: {
                    var count: usize = 2;
                    var it = dict.iterator();
                    while (it.next()) |entry| {
                        const keyVal = BencodeValue{ .string = entry.key_ptr.* };
                        count += keyVal.lenEncoded();
                        count += entry.value_ptr.lenEncoded();
                    }
                    break :blk count;
                },
            };
        }
    };

    fn decodeBencode(allocator: std.mem.Allocator, encodedValue: []const u8) !BencodeValue {
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
                    .integer = try std.fmt.parseInt(i64, encodedValue[1..endOfNum.?], 10),
                };
            },
            'l' => {
                var cursor: usize = 1;
                var list = std.ArrayList(BencodeValue).init(allocator);
                while (cursor < encodedValue.len) {
                    if (encodedValue[cursor] == 'e') {
                        cursor += 1;
                        break;
                    }
                    const val = try decodeBencode(allocator, encodedValue[cursor..]);
                    try list.append(val);
                    cursor += val.lenEncoded();
                }

                return .{
                    .list = try list.toOwnedSlice(),
                };
            },
            'd' => {
                var cursor: usize = 1;
                var dict = BencodeDict.init(allocator);
                while (encodedValue[cursor] != 'e' and cursor < encodedValue.len) {
                    const key = try decodeBencode(allocator, encodedValue[cursor..]);
                    if (key != .string) {
                        return error.DictionaryKeyNotString;
                    }
                    cursor += key.lenEncoded();
                    const value = try decodeBencode(allocator, encodedValue[cursor..]);
                    cursor += value.lenEncoded();
                    try dict.put(key.string, value);
                }

                return .{
                    .dictionary = dict,
                };
            },
            else => {
                return error.UnknownCase;
            },
        }
    }

    fn encodeBencode(allocator: std.mem.Allocator, value: BencodeValue) ![]const u8 {
        var encoded = StringArrayList.init(allocator);
        switch (value) {
            .string => |str| {
                const encStr = try std.fmt.allocPrint(allocator, "{}:{s}", .{ str.len, str });
                try encoded.appendSlice(encStr);
            },
            .integer => |int| {
                const encInt = try std.fmt.allocPrint(allocator, "i{d}e", .{int});
                try encoded.appendSlice(encInt);
            },
            .list => |list| {
                try encoded.append('l');
                for (list) |item| {
                    const encodedItem = try encodeBencode(allocator, item);
                    try encoded.appendSlice(encodedItem);
                }
                try encoded.append('e');
            },
            .dictionary => |dict| {
                try encoded.append('d');
                var it = dict.iterator();
                while (it.next()) |entry| {
                    const keyVal = BencodeValue{ .string = entry.key_ptr.* };
                    const encKey = try encodeBencode(allocator, keyVal);
                    const encEl = try encodeBencode(allocator, entry.value_ptr.*);
                    try encoded.appendSlice(encKey);
                    try encoded.appendSlice(encEl);
                }
                try encoded.append('e');
            },
        }
        return encoded.toOwnedSlice();
    }

    pub fn decode(allocator: std.mem.Allocator, encodedStr: []const u8) !void {
        const decoded = decodeBencode(allocator, encodedStr) catch {
            try stdout.print("Couldn't decode value\n", .{});
            std.process.exit(1);
        };

        var string = StringArrayList.init(allocator);
        try writeEncoded(decoded, string.writer());
        const jsonStr = try string.toOwnedSlice();
        try stdout.print("{s}\n", .{jsonStr});
    }

    pub fn info(allocator: std.mem.Allocator, filePath: []const u8) !void {
        const torrent = try BitTorrent.parseFile(allocator, filePath);
        var string = StringArrayList.init(allocator);

        try string.appendSlice("Tracker URL: ");
        try string.appendSlice(torrent.announce);
        try string.append('\n');

        try string.appendSlice("Length: ");
        try string.appendSlice(try numToString(i64, allocator, torrent.info.length));
        try string.append('\n');

        try string.appendSlice("Info Hash: ");
        const encodedInfo = try encodeBencode(allocator, torrent.decoded.dictionary.get("info").?);
        var hash: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
        std.crypto.hash.Sha1.hash(encodedInfo, &hash, .{});
        try string.appendSlice(try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&hash)}));
        try string.append('\n');

        try string.appendSlice("Piece Length: ");
        try string.appendSlice(try numToString(i64, allocator, torrent.info.pieceLength));
        try string.append('\n');

        try string.appendSlice("Piece Hashes: ");
        var win = std.mem.window(u8, torrent.info.pieces, 20, 20);
        while (win.next()) |piece| {
            try string.append('\n');
            const h = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(piece[0..20])});
            try string.appendSlice(h);
        }
        try string.append('\n');

        const jsonStr = try string.toOwnedSlice();
        try stdout.print("{s}\n", .{jsonStr});
    }

    pub fn peers(allocator: std.mem.Allocator, filePath: []const u8) !void {
        const torrent = try BitTorrent.parseFile(allocator, filePath);

        var client = std.http.Client{ .allocator = allocator };

        var query = StringArrayList.init(allocator);
        try query.appendSlice("?info_hash=");

        const encodedInfo = try encodeBencode(allocator, torrent.decoded.dictionary.get("info").?);
        var hash: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
        std.crypto.hash.Sha1.hash(encodedInfo, &hash, .{});

        const escaped_hash = try std.Uri.escapeString(allocator, &hash);
        try query.appendSlice(escaped_hash);
        try query.appendSlice("&peer_id=00112233445566778899");
        try query.appendSlice("&port=6881");
        try query.appendSlice("&uploaded=0");
        try query.appendSlice("&downloaded=0");
        try query.appendSlice("&left=");
        try query.appendSlice(try numToString(i64, allocator, torrent.info.length));
        try query.appendSlice("&compact=1");

        const url = try std.mem.concat(allocator, u8, &.{ torrent.announce, query.items });
        const uri = try std.Uri.parse(url);

        var req = try client.request(.GET, uri, .{ .allocator = allocator }, .{});
        defer req.deinit();

        try req.start();
        try req.finish();
        try req.wait();

        var body: [8046]u8 = undefined;
        const len = try req.readAll(&body);
        const decodedBody = try decodeBencode(allocator, body[0..len]);

        if (decodedBody != .dictionary) return error.InvalidResponse;
        var peers_entry = decodedBody.dictionary.get("peers") orelse return error.InvalidResponse;
        if (peers_entry != .string) return error.InvalidResponse;

        var allPeers = std.mem.window(u8, peers_entry.string, 6, 6);
        while (allPeers.next()) |peer| {
            const ip = peer[0..4];
            const port = std.mem.bytesToValue(u16, peer[4..6]);
            try stdout.print("{d}.{d}.{d}.{d}:{d}\n", .{
                ip[0],
                ip[1],
                ip[2],
                ip[3],
                std.mem.bigToNative(u16, port),
            });
        }
    }

    pub fn handshake(allocator: std.mem.Allocator, filePath: []const u8, fullIp: []const u8) !void {
        const torrent = try BitTorrent.parseFile(allocator, filePath);

        var it = std.mem.splitScalar(u8, fullIp, ':');
        const ip = it.next() orelse return error.MissingIP;
        const port = it.next() orelse return error.MissingPort;

        const address = try std.net.Address.resolveIp(ip, try std.fmt.parseInt(u16, port, 10));
        var stream = try std.net.tcpConnectToAddress(address);
        const writer = stream.writer();
        const reader = stream.reader();

        const encodedInfo = try encodeBencode(allocator, torrent.decoded.dictionary.get("info").?);
        var hash: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
        std.crypto.hash.Sha1.hash(encodedInfo, &hash, .{});
        const hs = Handshake{
            .infoHash = hash,
            .peerId = "00112233445566778899".*,
        };
        try writer.writeStruct(hs);
        const serverHandshake = try reader.readStruct(Handshake);
        try stdout.print("Peer ID: {s}\n", .{std.fmt.bytesToHex(serverHandshake.peerId, .lower)});
    }
};

fn writeEncoded(value: Commands.BencodeValue, writer: StringArrayList.Writer) !void {
    switch (value) {
        .string => |s| {
            try std.json.stringify(s, .{}, writer);
        },
        .integer => |int| {
            try writer.print("{d}", .{int});
        },
        .list => |l| {
            try writer.writeByte('[');
            for (l, 0..) |item, i| {
                try writeEncoded(item, writer);
                if (i != l.len - 1) try writer.writeByte(',');
            }
            try writer.writeByte(']');
        },
        .dictionary => |d| {
            try writer.writeByte('{');
            var it = d.iterator();
            var index: usize = 0;
            while (it.next()) |entry| {
                index += 1;
                try writer.writeByte('"');
                try writer.writeAll(entry.key_ptr.*);
                try writer.writeByte('"');
                try writer.writeByte(':');
                try writeEncoded(entry.value_ptr.*, writer);
                if (index != d.count()) {
                    try writer.writeByte(',');
                }
            }
            try writer.writeByte('}');
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

fn numToString(comptime vt: type, allocator: std.mem.Allocator, val: vt) ![]const u8 {
    return try std.fmt.allocPrint(allocator, "{d}", .{val});
}
