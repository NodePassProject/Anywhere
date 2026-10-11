//
//  ReceiveBuffer.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/27/26.
//

import Foundation

struct ReceiveBuffer {
    private var chunks: [Data] = []
    private var offset = 0
    private var isTailSealed = false
    private(set) var unsealedSince: UInt32?

    var unreadByteCount: Int {
        chunks[offset...].reduce(0) { $0 + $1.count }
    }

    func hasReadableChunk(flushing: Bool) -> Bool {
        offset < chunks.count && (flushing || isTailSealed || offset < chunks.count - 1)
    }

    mutating func append(_ bytes: UnsafeRawBufferPointer, push: Bool, ticks: UInt32) {
        guard let base = bytes.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
        let limit = Constants.receiveChunkSize
        if offset < chunks.count, !isTailSealed, chunks[chunks.count - 1].count + bytes.count <= limit {
            chunks[chunks.count - 1].append(base, count: bytes.count)
        } else if push {
            chunks.append(Data(bytes: base, count: bytes.count))
            unsealedSince = nil
        } else {
            var chunk = Data(capacity: limit)
            chunk.append(base, count: bytes.count)
            chunks.append(chunk)
            unsealedSince = nil
        }
        if push || chunks[chunks.count - 1].count > limit - Int(Constants.maximumSegmentSize) {
            isTailSealed = true
            unsealedSince = nil
        } else {
            isTailSealed = false
            if unsealedSince == nil { unsealedSince = ticks }
        }
    }

    mutating func seal() {
        isTailSealed = offset < chunks.count
        unsealedSince = nil
    }

    mutating func next(flushing: Bool) -> Data? {
        guard hasReadableChunk(flushing: flushing) else { return nil }
        let chunk = chunks[offset]
        offset += 1
        if offset == chunks.count {
            removeAll(keepingCapacity: true)
        } else if offset >= 64 && offset >= chunks.count / 2 {
            chunks.removeFirst(offset)
            offset = 0
        }
        return chunk
    }

    mutating func removeAll(keepingCapacity: Bool = false) {
        chunks.removeAll(keepingCapacity: keepingCapacity)
        offset = 0
        isTailSealed = false
        unsealedSince = nil
    }
}
