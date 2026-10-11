//
//  OutboundPacket+TCP.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/26/26.
//

import Foundation

extension OutboundPacket {
    init?(resetFrom local: IPEndpoint, to remote: IPEndpoint, sequenceNumber: UInt32, acknowledgmentNumber: UInt32) {
        let isIPv6 = local.address.isIPv6
        var encoded = false
        self.init(byteCount: (isIPv6 ? IPv6Header.length : IPv4Header.length) + TCPHeader.length, isIPv6: isIPv6) { packet in
            encoded = Self.encodeTCP(
                into: packet,
                from: local,
                to: remote,
                sequenceNumber: sequenceNumber,
                acknowledgmentNumber: acknowledgmentNumber,
                flags: [.rst, .ack],
                window: Constants.resetWindow
            )
        }
        guard encoded else { return nil }
    }

    static func encodeTCP(
        into packet: UnsafeMutableRawBufferPointer,
        from local: IPEndpoint,
        to remote: IPEndpoint,
        sequenceNumber: UInt32,
        acknowledgmentNumber: UInt32,
        flags: TCPHeader.Flags,
        options: TCPHeader.Options = TCPHeader.Options(),
        window: UInt16,
        payloadLength: Int = 0,
        payloadSum: UInt16 = 0
    ) -> Bool {
        let tcpLength = TCPHeader.length + options.encodedLength + payloadLength
        let ipLength: Int
        switch (local.address, remote.address) {
        case (.v4(let source), .v4(let destination)):
            ipLength = IPv4Header.length
            IPv4Header(
                totalLength: ipLength + tcpLength,
                timeToLive: Constants.hopLimit,
                protocol: 6,
                source: source,
                destination: destination,
                identification: PacketIdentification.next()
            ).write(to: packet)
        case (.v6(let source), .v6(let destination)):
            ipLength = IPv6Header.length
            IPv6Header(
                payloadLength: tcpLength,
                nextHeader: 6,
                hopLimit: Constants.hopLimit,
                source: source,
                destination: destination
            ).write(to: packet)
        default:
            return false
        }
        let tcp = UnsafeMutableRawBufferPointer(rebasing: packet[ipLength...])
        TCPHeader(
            sourcePort: local.port,
            destinationPort: remote.port,
            sequenceNumber: sequenceNumber,
            acknowledgmentNumber: acknowledgmentNumber,
            dataOffset: TCPHeader.length + options.encodedLength,
            flags: flags,
            window: window
        ).write(to: tcp)
        options.write(to: UnsafeMutableRawBufferPointer(rebasing: tcp[TCPHeader.length...]))
        var checksum = InternetChecksum()
        checksum.update(pseudoHeaderFor: local.address, destination: remote.address, protocol: 6, length: tcpLength)
        checksum.update(bufferPointer: UnsafeRawBufferPointer(rebasing: UnsafeRawBufferPointer(tcp)[..<(tcpLength - payloadLength)]))
        checksum.update(partialSum: payloadSum, byteCount: payloadLength)
        tcp.storeBytes(of: checksum.finalize(), toByteOffset: 16, as: UInt16.self)
        return true
    }
}
