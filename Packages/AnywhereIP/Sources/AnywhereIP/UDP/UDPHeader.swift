//
//  UDPHeader.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/25/26.
//

struct UDPHeader: Hashable, Sendable {
    static let length = 8

    var sourcePort: UInt16
    var destinationPort: UInt16
    var totalLength: Int
    var checksum: UInt16

    init(sourcePort: UInt16, destinationPort: UInt16, totalLength: Int, checksum: UInt16 = 0) {
        self.sourcePort = sourcePort
        self.destinationPort = destinationPort
        self.totalLength = totalLength
        self.checksum = checksum
    }

    init?(parsing bytes: UnsafeRawBufferPointer) {
        guard bytes.count >= Self.length, let base = bytes.baseAddress else { return nil }
        let totalLength = Int(UInt16(bigEndian: base.loadUnaligned(fromByteOffset: 4, as: UInt16.self)))
        guard totalLength >= Self.length, totalLength <= bytes.count else { return nil }
        sourcePort = UInt16(bigEndian: base.loadUnaligned(as: UInt16.self))
        destinationPort = UInt16(bigEndian: base.loadUnaligned(fromByteOffset: 2, as: UInt16.self))
        self.totalLength = totalLength
        checksum = UInt16(bigEndian: base.loadUnaligned(fromByteOffset: 6, as: UInt16.self))
    }

    func write(to bytes: UnsafeMutableRawBufferPointer) {
        precondition(bytes.count >= Self.length)
        let base = bytes.baseAddress!
        base.storeBytes(of: sourcePort.bigEndian, as: UInt16.self)
        base.storeBytes(of: destinationPort.bigEndian, toByteOffset: 2, as: UInt16.self)
        base.storeBytes(of: UInt16(totalLength).bigEndian, toByteOffset: 4, as: UInt16.self)
        base.storeBytes(of: checksum.bigEndian, toByteOffset: 6, as: UInt16.self)
    }
}
