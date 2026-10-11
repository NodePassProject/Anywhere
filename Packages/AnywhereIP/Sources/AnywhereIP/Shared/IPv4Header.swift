//
//  IPv4Header.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

struct IPv4Header: Hashable, Sendable {
    static let length = 20

    var headerLength: Int
    var typeOfService: UInt8
    var totalLength: Int
    var identification: UInt16
    var fragmentField: UInt16
    var timeToLive: UInt8
    var `protocol`: UInt8
    var source: IPAddress.V4
    var destination: IPAddress.V4
    
    var isFragment: Bool { fragmentField & 0x3FFF != 0 }
    var hasOptions: Bool { headerLength > Self.length }

    init(
        totalLength: Int,
        timeToLive: UInt8,
        protocol: UInt8,
        source: IPAddress.V4,
        destination: IPAddress.V4,
        identification: UInt16 = 0,
        typeOfService: UInt8 = 0,
        fragmentField: UInt16 = 0
    ) {
        headerLength = Self.length
        self.typeOfService = typeOfService
        self.totalLength = totalLength
        self.identification = identification
        self.fragmentField = fragmentField
        self.timeToLive = timeToLive
        self.protocol = `protocol`
        self.source = source
        self.destination = destination
    }

    init?(parsing bytes: UnsafeRawBufferPointer) {
        guard bytes.count >= Self.length, let base = bytes.baseAddress else { return nil }
        let versionAndLength = base.load(as: UInt8.self)
        guard versionAndLength >> 4 == 4 else { return nil }
        let headerLength = Int(versionAndLength & 0x0F) * 4
        let totalLength = Int(UInt16(bigEndian: base.loadUnaligned(fromByteOffset: 2, as: UInt16.self)))
        guard headerLength >= Self.length, totalLength >= headerLength, totalLength <= bytes.count else { return nil }
        self.headerLength = headerLength
        typeOfService = base.load(fromByteOffset: 1, as: UInt8.self)
        self.totalLength = totalLength
        identification = UInt16(bigEndian: base.loadUnaligned(fromByteOffset: 4, as: UInt16.self))
        fragmentField = UInt16(bigEndian: base.loadUnaligned(fromByteOffset: 6, as: UInt16.self))
        timeToLive = base.load(fromByteOffset: 8, as: UInt8.self)
        `protocol` = base.load(fromByteOffset: 9, as: UInt8.self)
        source = IPAddress.V4(bytes: base + 12)
        destination = IPAddress.V4(bytes: base + 16)
    }

    func write(to bytes: UnsafeMutableRawBufferPointer) {
        precondition(bytes.count >= Self.length)
        let base = bytes.baseAddress!
        base.storeBytes(of: 0x45, as: UInt8.self)
        base.storeBytes(of: typeOfService, toByteOffset: 1, as: UInt8.self)
        base.storeBytes(of: UInt16(totalLength).bigEndian, toByteOffset: 2, as: UInt16.self)
        base.storeBytes(of: identification.bigEndian, toByteOffset: 4, as: UInt16.self)
        base.storeBytes(of: fragmentField.bigEndian, toByteOffset: 6, as: UInt16.self)
        base.storeBytes(of: timeToLive, toByteOffset: 8, as: UInt8.self)
        base.storeBytes(of: `protocol`, toByteOffset: 9, as: UInt8.self)
        base.storeBytes(of: UInt16(0), toByteOffset: 10, as: UInt16.self)
        source.write(to: base + 12)
        destination.write(to: base + 16)
        var checksum = InternetChecksum()
        checksum.update(bufferPointer: UnsafeRawBufferPointer(start: base, count: Self.length))
        base.storeBytes(of: checksum.finalize(), toByteOffset: 10, as: UInt16.self)
    }
}
