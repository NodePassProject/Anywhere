//
//  InitialCrumbling.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

enum CrumbledFrame: Equatable {
    case crypto(offset: UInt64, length: Int)
    case ping
    case padding(Int)
}

enum InitialCrumbling {
    static let maxFrameCount = 256
    static let maxAddedFrames = 10
    static let maxRemovedLength = 30

    static func splitRandomly(_ frames: inout [CrumbledFrame], maxAdditions: Int, using random: inout PCG32) {
        var remaining = maxAdditions
        while remaining > 0 {
            remaining -= 1
            let index = Int(random.next(upperBound: UInt32(frames.count)))
            guard case .crypto(let offset, let length) = frames[index], length > 1 else {
                continue
            }
            let half = length / 2
            frames[index] = .crypto(offset: offset, length: half)
            frames.append(.crypto(offset: offset + UInt64(half), length: length - half))
        }
    }

    static func split(_ frames: inout [CrumbledFrame], at position: Int) {
        guard case .crypto(let offset, let length) = frames[0] else {
            preconditionFailure("expected CRYPTO data")
        }
        precondition(position < length)
        frames[0] = .crypto(offset: offset, length: position)
        frames.append(.crypto(offset: offset + UInt64(position), length: length - position))
    }

    static func findServerName(in bytes: UnsafeRawBufferPointer) -> Range<Int>? {
        precondition(!bytes.isEmpty)
        var cursor = HandshakeCursor(bytes)
        guard cursor.byteCount >= 4, cursor.readUInt8() == 1 else {
            return nil
        }
        let messageLength = cursor.readUInt24()
        cursor.truncate(to: messageLength)
        guard cursor.byteCount >= 2, cursor.readUInt16() == 0x0303 else {
            return nil
        }
        guard cursor.byteCount >= 32 else {
            return nil
        }
        cursor.skip(32)
        guard cursor.skipVector8(), cursor.skipVector16(), cursor.skipVector8(), cursor.byteCount >= 2 else {
            return nil
        }
        let extensionsLength = cursor.readUInt16()
        cursor.truncate(to: extensionsLength)
        while true {
            guard cursor.byteCount >= 4 else {
                return nil
            }
            if cursor.readUInt16() != 0 {
                guard cursor.skipVector16() else {
                    return nil
                }
                continue
            }
            let extensionLength = cursor.readUInt16()
            guard cursor.byteCount >= extensionLength, extensionLength >= 2 else {
                return nil
            }
            cursor.truncate(to: extensionLength)
            let listLength = cursor.readUInt16()
            guard cursor.byteCount >= listLength, listLength >= 3 else {
                return nil
            }
            cursor.truncate(to: listLength)
            guard cursor.readUInt8() == 0 else {
                return nil
            }
            let nameLength = cursor.readUInt16()
            guard cursor.byteCount >= nameLength else {
                return nil
            }
            return cursor.position..<cursor.position + nameLength
        }
    }

    static func appendPingAndPadding(to frames: inout [CrumbledFrame], budget: Int, using random: inout PCG32) {
        var budget = budget
        while budget > 0, frames.count < Self.maxFrameCount {
            let count = Int(random.next(upperBound: UInt32(clamping: budget + 1)))
            if count == 0 {
                frames.append(.ping)
                budget -= 1
            } else {
                frames.append(.padding(count))
                budget -= count
            }
        }
    }

    static func permute(_ frames: inout [CrumbledFrame], using random: inout PCG32) {
        guard frames.count >= 2 else {
            return
        }
        for index in stride(from: frames.count - 1, to: 0, by: -1) {
            let other = Int(random.next(upperBound: UInt32(index)))
            if other != index {
                frames.swapAt(index, other)
            }
        }
    }

    static func removePartially(
        _ part: Range<UInt64>,
        from frames: inout [CrumbledFrame],
        using random: inout PCG32
    ) -> Range<UInt64> {
        guard case .crypto(let offset, let length) = frames[0] else {
            preconditionFailure("expected CRYPTO data")
        }
        precondition(offset < part.lowerBound && part.upperBound <= offset + UInt64(length))
        let kept = Int(part.lowerBound - offset) + Int(part.upperBound - part.lowerBound) / 2
        precondition(kept < length)
        let removedOffset = offset + UInt64(kept)
        let removedLength = length - kept
        frames[0] = .crypto(offset: offset, length: kept)
        if removedLength == 1 {
            return removedOffset..<removedOffset + 1
        }
        let cut = 1 + Int(random.next(upperBound: UInt32(Swift.min(Self.maxRemovedLength, removedLength - 1))))
        frames.append(.crypto(offset: removedOffset + UInt64(cut), length: removedLength - cut))
        return removedOffset..<removedOffset + UInt64(cut)
    }
}

private struct HandshakeCursor {
    let bytes: UnsafeRawBufferPointer
    private(set) var position = 0
    private var end: Int

    init(_ bytes: UnsafeRawBufferPointer) {
        self.bytes = bytes
        self.end = bytes.count
    }

    var byteCount: Int { self.end - self.position }

    mutating func truncate(to length: Int) {
        if self.byteCount > length {
            self.end = self.position + length
        }
    }

    mutating func skip(_ count: Int) {
        self.position += count
    }

    mutating func readUInt8() -> Int {
        defer {
            self.position += 1
        }
        return Int(self.bytes[self.position])
    }

    mutating func readUInt16() -> Int {
        return self.readUInt8() << 8 | self.readUInt8()
    }

    mutating func readUInt24() -> Int {
        return self.readUInt8() << 16 | self.readUInt16()
    }

    mutating func skipVector8() -> Bool {
        guard self.byteCount >= 1 else {
            return false
        }
        let length = self.readUInt8()
        guard self.byteCount >= length else {
            return false
        }
        self.position += length
        return true
    }

    mutating func skipVector16() -> Bool {
        guard self.byteCount >= 2 else {
            return false
        }
        let length = self.readUInt16()
        guard self.byteCount >= length else {
            return false
        }
        self.position += length
        return true
    }
}
