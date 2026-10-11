//
//  Segment.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

struct Segment: Equatable {
    struct Storage {
        var next: UnsafeMutablePointer<Storage>?
        var sequenceNumber: UInt32
        var length: Int
        var flags: TCPHeader.Flags
        var options: TCPHeader.Options
        var payloadSum: UInt16
        var isQueued: Bool
    }

    static let headroom = IPv6Header.length + TCPHeader.length + 8
    static let capacity = Int(Constants.maximumSegmentSize)

    static var bufferOffset: Int {
        (MemoryLayout<Storage>.stride + 15) & ~15
    }

    static var stride: Int {
        (bufferOffset + headroom + capacity + 15) & ~15
    }

    let storage: UnsafeMutablePointer<Storage>

    var sequenceNumber: UInt32 {
        storage.pointee.sequenceNumber
    }

    var length: Int {
        storage.pointee.length
    }

    var payloadSum: UInt16 {
        storage.pointee.payloadSum
    }

    func setPayload(_ bytes: UnsafeRawBufferPointer) {
        storage.pointee.length = bytes.count
        let payload = self.payload
        payload.copyMemory(from: bytes)
        storage.pointee.payloadSum = InternetChecksum.partialSum(of: UnsafeRawBufferPointer(payload))
    }

    func truncatePayload(to count: Int) {
        storage.pointee.length = count
        storage.pointee.payloadSum = InternetChecksum.partialSum(of: UnsafeRawBufferPointer(payload))
    }

    func appendPayload(_ bytes: UnsafeRawBufferPointer) {
        let end = payload.baseAddress.unsafelyUnwrapped + length
        UnsafeMutableRawBufferPointer(start: end, count: bytes.count).copyMemory(from: bytes)
        truncatePayload(to: length + bytes.count)
    }

    func dropPayloadPrefix(_ count: Int) {
        let payload = self.payload
        let start = payload.baseAddress.unsafelyUnwrapped
        start.copyMemory(from: start + count, byteCount: payload.count - count)
        storage.pointee.sequenceNumber &+= UInt32(count)
        truncatePayload(to: payload.count - count)
    }

    var flags: TCPHeader.Flags {
        get { storage.pointee.flags }
        nonmutating set { storage.pointee.flags = newValue }
    }

    var options: TCPHeader.Options {
        storage.pointee.options
    }

    var isQueued: Bool {
        get { storage.pointee.isQueued }
        nonmutating set { storage.pointee.isQueued = newValue }
    }

    var next: Segment? {
        get { storage.pointee.next.map(Segment.init) }
        nonmutating set { storage.pointee.next = newValue?.storage }
    }

    var buffer: UnsafeMutableRawBufferPointer {
        UnsafeMutableRawBufferPointer(start: UnsafeMutableRawPointer(storage) + Self.bufferOffset, count: Self.headroom + Self.capacity)
    }

    var payloadOffset: Int {
        IPv6Header.length + TCPHeader.length + options.encodedLength
    }

    var payload: UnsafeMutableRawBufferPointer {
        UnsafeMutableRawBufferPointer(rebasing: buffer[payloadOffset..<(payloadOffset + length)])
    }

    var tcpLength: UInt32 {
        UInt32(length) + (flags.contains(.syn) || flags.contains(.fin) ? 1 : 0)
    }
}
