//
//  OutboundPacket.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

import Foundation

public struct OutboundPacket: @unchecked Sendable {
    public let data: NSData
    public let isIPv6: Bool

    public init(data: NSData, isIPv6: Bool) {
        self.data = data
        self.isIPv6 = isIPv6
    }

    public init(byteCount: Int, isIPv6: Bool, _ fill: (UnsafeMutableRawBufferPointer) -> Void) {
        let bytes = calloc(1, max(byteCount, 1)).unsafelyUnwrapped
        fill(UnsafeMutableRawBufferPointer(start: bytes, count: byteCount))
        self.init(data: NSData(bytesNoCopy: bytes, length: byteCount, freeWhenDone: true), isIPv6: isIPv6)
    }

    init(copying bytes: UnsafeRawBufferPointer, isIPv6: Bool) {
        self.init(data: NSData(bytes: bytes.baseAddress, length: bytes.count), isIPv6: isIPv6)
    }

    var flags: TCPHeader.Flags {
        TCPHeader.Flags(rawValue: CFDataGetBytePtr(data)[(isIPv6 ? IPv6Header.length : IPv4Header.length) + 13])
    }
}
