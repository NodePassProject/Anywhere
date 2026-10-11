//
//  SegmentArena.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

final class SegmentArena {
    private static let chunkSlots = 4

    private var chunks: [UnsafeMutableRawPointer] = []
    private var free: UnsafeMutablePointer<Segment.Storage>?
    private var outstanding = 0

    var isReclaimable: Bool {
        outstanding == 0 && chunks.count > 1
    }

    deinit {
        for chunk in chunks {
            chunk.deallocate()
        }
    }

    func allocate(sequenceNumber: UInt32, flags: TCPHeader.Flags, options: TCPHeader.Options = TCPHeader.Options()) -> Segment {
        if free == nil {
            grow()
        }
        let storage = free.unsafelyUnwrapped
        free = storage.pointee.next
        outstanding += 1
        storage.pointee.next = nil
        storage.pointee.sequenceNumber = sequenceNumber
        storage.pointee.length = 0
        storage.pointee.flags = flags
        storage.pointee.options = options
        storage.pointee.payloadSum = 0
        storage.pointee.isQueued = false
        return Segment(storage: storage)
    }

    func recycle(_ segment: Segment) {
        segment.isQueued = false
        release(segment)
    }

    func release(_ segment: Segment) {
        outstanding -= 1
        segment.storage.pointee.next = free
        free = segment.storage
    }

    func reclaim() {
        guard isReclaimable else { return }
        for chunk in chunks[1...] {
            chunk.deallocate()
        }
        chunks.removeSubrange(1...)
        free = nil
        thread(chunks[0])
    }

    private func grow() {
        let chunk = UnsafeMutableRawPointer.allocate(byteCount: Self.chunkSlots * Segment.stride, alignment: 16)
        chunks.append(chunk)
        thread(chunk)
    }

    private func thread(_ chunk: UnsafeMutableRawPointer) {
        for index in stride(from: Self.chunkSlots - 1, through: 0, by: -1) {
            free = (chunk + index * Segment.stride).initializeMemory(
                as: Segment.Storage.self,
                to: Segment.Storage(
                    next: free, sequenceNumber: 0, length: 0,
                    flags: [], options: TCPHeader.Options(), payloadSum: 0, isQueued: false
                )
            )
        }
    }
}
