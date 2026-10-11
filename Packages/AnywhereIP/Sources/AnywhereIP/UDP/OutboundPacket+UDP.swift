//
//  OutboundPacket+UDP.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/25/26.
//

import Foundation

extension OutboundPacket {
    public init?(datagram payload: Data, from source: IPEndpoint, to destination: IPEndpoint) {
        let udpLength = UDPHeader.length + payload.count
        let ipLength: Int
        switch (source.address, destination.address) {
        case (.v4, .v4):
            ipLength = IPv4Header.length
            guard ipLength + udpLength <= 0xFFFF else { return nil }
        case (.v6, .v6):
            ipLength = IPv6Header.length
            guard udpLength <= 0xFFFF else { return nil }
        default:
            return nil
        }
        self.init(byteCount: ipLength + udpLength, isIPv6: source.address.isIPv6) { packet in
            switch (source.address, destination.address) {
            case (.v4(let sourceAddress), .v4(let destinationAddress)):
                IPv4Header(
                    totalLength: ipLength + udpLength,
                    timeToLive: Constants.hopLimit,
                    protocol: 17,
                    source: sourceAddress,
                    destination: destinationAddress,
                    identification: PacketIdentification.next()
                ).write(to: packet)
            case (.v6(let sourceAddress), .v6(let destinationAddress)):
                IPv6Header(
                    payloadLength: udpLength,
                    nextHeader: 17,
                    hopLimit: Constants.hopLimit,
                    source: sourceAddress,
                    destination: destinationAddress
                ).write(to: packet)
            default:
                return
            }
            let udp = UnsafeMutableRawBufferPointer(rebasing: packet[ipLength...])
            UDPHeader(sourcePort: source.port, destinationPort: destination.port, totalLength: udpLength).write(to: udp)
            payload.withUnsafeBytes { UnsafeMutableRawBufferPointer(rebasing: udp[UDPHeader.length...]).copyMemory(from: $0) }
            guard ipLength == IPv6Header.length else { return }
            var checksum = InternetChecksum()
            checksum.update(pseudoHeaderFor: source.address, destination: destination.address, protocol: 17, length: udpLength)
            checksum.update(bufferPointer: UnsafeRawBufferPointer(udp))
            let value = checksum.finalize()
            udp.storeBytes(of: value == 0 ? .max : value, toByteOffset: 6, as: UInt16.self)
        }
    }

    public init?(portUnreachable datagram: InboundDatagram) {
        let packet: OutboundPacket? = datagram.packet.withUnsafeBytes { quoted in
            switch (datagram.source.address, datagram.destination.address) {
            case (.v4(let source), .v4(let destination)):
                ICMPMessage.error(type: 3, code: 3, quoting: quoted, from: destination, to: source)
            case (.v6(let source), .v6(let destination)):
                ICMPMessage.error(type: 1, code: 4, quoting: quoted, from: destination, to: source)
            default:
                nil
            }
        }
        guard let packet else { return nil }
        self = packet
    }
}
