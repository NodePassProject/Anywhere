//
//  PacketTemplate.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/27/26.
//

struct PacketTemplate {
    let isIPv6: Bool
    private let header: (UInt64, UInt64, UInt64, UInt64, UInt64)
    private let headerSum: UInt16
    private let pseudoSum: UInt16
    private let ports: UInt32

    var headerLength: Int {
        isIPv6 ? IPv6Header.length : IPv4Header.length
    }

    init(from local: IPEndpoint, to remote: IPEndpoint) {
        var header: (UInt64, UInt64, UInt64, UInt64, UInt64) = (0, 0, 0, 0, 0)
        var pseudo: (UInt64, UInt64, UInt64, UInt64, UInt64) = (0, 0, 0, 0, 0)
        var headerSum: UInt16 = 0
        var pseudoSum: UInt16 = 0
        withUnsafeMutableBytes(of: &header) { header in
            withUnsafeMutableBytes(of: &pseudo) { pseudo in
                let base = header.baseAddress.unsafelyUnwrapped
                let pseudoBase = pseudo.baseAddress.unsafelyUnwrapped
                local.address.write(to: pseudoBase)
                remote.address.write(to: pseudoBase + local.address.byteCount)
                switch (local.address, remote.address) {
                case (.v4(let source), .v4(let destination)):
                    base.storeBytes(of: 0x45, as: UInt8.self)
                    base.storeBytes(of: UInt16(0x4000).bigEndian, toByteOffset: 6, as: UInt16.self)
                    base.storeBytes(of: Constants.hopLimit, toByteOffset: 8, as: UInt8.self)
                    base.storeBytes(of: 6, toByteOffset: 9, as: UInt8.self)
                    source.write(to: base + 12)
                    destination.write(to: base + 16)
                    pseudoBase.storeBytes(of: UInt16(6).bigEndian, toByteOffset: 8, as: UInt16.self)
                    headerSum = InternetChecksum.partialSum(of: UnsafeRawBufferPointer(rebasing: header[..<IPv4Header.length]))
                    pseudoSum = InternetChecksum.partialSum(of: UnsafeRawBufferPointer(rebasing: pseudo[..<12]))
                case (.v6(let source), .v6(let destination)):
                    base.storeBytes(of: UInt32(6 << 28).bigEndian, as: UInt32.self)
                    base.storeBytes(of: 6, toByteOffset: 6, as: UInt8.self)
                    base.storeBytes(of: Constants.hopLimit, toByteOffset: 7, as: UInt8.self)
                    source.write(to: base + 8)
                    destination.write(to: base + 24)
                    pseudoBase.storeBytes(of: UInt32(6).bigEndian, toByteOffset: 36, as: UInt32.self)
                    pseudoSum = InternetChecksum.partialSum(of: UnsafeRawBufferPointer(pseudo))
                default:
                    break
                }
            }
        }
        isIPv6 = local.address.isIPv6
        self.header = header
        self.headerSum = headerSum
        self.pseudoSum = pseudoSum
        ports = UInt32(local.port.bigEndian) | UInt32(remote.port.bigEndian) << 16
    }

    func encode(
        into packet: UnsafeMutableRawBufferPointer,
        sequenceNumber: UInt32,
        acknowledgmentNumber: UInt32,
        flags: TCPHeader.Flags,
        options: TCPHeader.Options,
        window: UInt16,
        payloadLength: Int,
        payloadSum: UInt16
    ) {
        let base = packet.baseAddress.unsafelyUnwrapped
        let headerLength = headerLength
        let tcpHeaderLength = TCPHeader.length + options.encodedLength
        let tcpLength = UInt16(truncatingIfNeeded: tcpHeaderLength + payloadLength)
        withUnsafeBytes(of: header) { base.copyMemory(from: $0.baseAddress.unsafelyUnwrapped, byteCount: headerLength) }
        if isIPv6 {
            base.storeBytes(of: tcpLength.bigEndian, toByteOffset: 4, as: UInt16.self)
        } else {
            let totalLength = (tcpLength &+ UInt16(IPv4Header.length)).bigEndian
            base.storeBytes(of: totalLength, toByteOffset: 2, as: UInt16.self)
            base.storeBytes(of: ~Self.fold(UInt32(headerSum) &+ UInt32(totalLength)), toByteOffset: 10, as: UInt16.self)
        }
        let tcp = base + headerLength
        tcp.storeBytes(of: ports, as: UInt32.self)
        tcp.storeBytes(of: sequenceNumber.bigEndian, toByteOffset: 4, as: UInt32.self)
        tcp.storeBytes(of: acknowledgmentNumber.bigEndian, toByteOffset: 8, as: UInt32.self)
        tcp.storeBytes(of: (UInt16(tcpHeaderLength / 4) << 12 | UInt16(flags.rawValue)).bigEndian, toByteOffset: 12, as: UInt16.self)
        tcp.storeBytes(of: window.bigEndian, toByteOffset: 14, as: UInt16.self)
        tcp.storeBytes(of: UInt32(0), toByteOffset: 16, as: UInt32.self)
        if tcpHeaderLength > TCPHeader.length {
            options.write(to: UnsafeMutableRawBufferPointer(start: tcp + TCPHeader.length, count: tcpHeaderLength - TCPHeader.length))
        }
        let headerSum = InternetChecksum.partialSum(of: UnsafeRawBufferPointer(start: tcp, count: tcpHeaderLength))
        let sum = UInt32(pseudoSum) &+ UInt32(tcpLength.bigEndian) &+ UInt32(headerSum) &+ UInt32(payloadSum)
        tcp.storeBytes(of: ~Self.fold(sum), toByteOffset: 16, as: UInt16.self)
    }

    private static func fold(_ value: UInt32) -> UInt16 {
        let folded = (value & 0xFFFF) &+ (value >> 16)
        return UInt16(truncatingIfNeeded: (folded & 0xFFFF) &+ (folded >> 16))
    }
}
