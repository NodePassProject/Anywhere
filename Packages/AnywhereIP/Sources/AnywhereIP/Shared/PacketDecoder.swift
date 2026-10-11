//
//  PacketDecoder.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

import Foundation

struct PacketDecoder {
    var tcp: InboundTCP?
    var udp: InboundDatagram?
    var output: [OutboundPacket] = []
    private let decodesUDP: Bool

    init(decodesUDP: Bool) {
        self.decodesUDP = decodesUDP
    }

    mutating func deliverTCP(_ segment: UnsafeRawBufferPointer, source: IPAddress, destination: IPAddress) {
        guard let header = TCPHeader(parsing: segment) else { return }
        tcp = InboundTCP(
            key: ConnectionKey(remote: IPEndpoint(address: source, port: header.sourcePort), local: IPEndpoint(address: destination, port: header.destinationPort)),
            header: header,
            options: UnsafeRawBufferPointer(rebasing: segment[TCPHeader.length..<header.dataOffset]),
            payload: UnsafeRawBufferPointer(rebasing: segment[header.dataOffset...])
        )
    }

    mutating func deliverUDP(_ segment: UnsafeRawBufferPointer, in datagram: UnsafeRawBufferPointer, source: IPAddress, destination: IPAddress) {
        guard let header = UDPHeader(parsing: segment), let base = segment.baseAddress, let datagramBase = datagram.baseAddress else { return }
        let packet = Data(datagram)
        let start = datagramBase.distance(to: base) + UDPHeader.length
        udp = InboundDatagram(
            source: IPEndpoint(address: source, port: header.sourcePort),
            destination: IPEndpoint(address: destination, port: header.destinationPort),
            payload: packet[start..<(start + header.totalLength - UDPHeader.length)],
            packet: packet
        )
    }

    mutating func decode(_ packet: UnsafeRawBufferPointer) {
        guard let first = packet.first else { return }
        switch first >> 4 {
        case 4: receiveIPv4(packet)
        case 6: receiveIPv6(packet)
        default: break
        }
    }

    private mutating func receiveIPv4(_ packet: UnsafeRawBufferPointer) {
        guard let header = IPv4Header(parsing: packet), !header.hasOptions, !header.isFragment,
              isRoutable(header.source), isRoutable(header.destination) else { return }
        let datagram = UnsafeRawBufferPointer(rebasing: packet[..<header.totalLength])
        let payload = UnsafeRawBufferPointer(rebasing: datagram[IPv4Header.length...])
        switch header.protocol {
        case 6: deliverTCP(payload, source: .v4(header.source), destination: .v4(header.destination))
        case 17 where decodesUDP: deliverUDP(payload, in: datagram, source: .v4(header.source), destination: .v4(header.destination))
        case 1: replyToEchoRequest(in: datagram, header: header, payload: payload)
        default: sendProtocolUnreachable(for: datagram, header: header)
        }
    }

    private func isRoutable(_ address: IPAddress.V4) -> Bool {
        !address.isUnspecified && !address.isBroadcast && !address.isMulticast && !address.isLoopback
    }

    private mutating func receiveIPv6(_ packet: UnsafeRawBufferPointer) {
        guard let header = IPv6Header(parsing: packet),
              !header.source.isUnspecified, !header.source.isMulticast, !header.source.isIPv4Mapped,
              !header.destination.isMulticast, !header.destination.isIPv4Mapped else { return }
        let datagram = UnsafeRawBufferPointer(rebasing: packet[..<header.totalLength])
        switch header.locatePayload(in: datagram) {
        case .dropped:
            return
        case .parameterProblem(let code, let pointer):
            sendParameterProblem(for: datagram, header: header, code: code, pointer: pointer)
        case .found(let payload):
            let bytes = UnsafeRawBufferPointer(rebasing: datagram[payload.offset...])
            switch payload.nextHeader {
            case 6: deliverTCP(bytes, source: .v6(header.source), destination: .v6(header.destination))
            case 17 where decodesUDP: deliverUDP(bytes, in: datagram, source: .v6(header.source), destination: .v6(header.destination))
            case 58: replyToEchoRequest(in: datagram, header: header, payload: bytes)
            case 59: return
            default: sendParameterProblem(for: datagram, header: header, code: 1, pointer: UInt32(payload.nextHeaderFieldOffset))
            }
        }
    }

    private mutating func replyToEchoRequest(in datagram: UnsafeRawBufferPointer, header: IPv4Header, payload: UnsafeRawBufferPointer) {
        guard payload.count >= 8, payload[0] == 8 else { return }
        send(byteCount: datagram.count, isIPv6: false) { reply in
            reply.copyMemory(from: datagram)
            var replyHeader = header
            replyHeader.source = header.destination
            replyHeader.destination = header.source
            replyHeader.timeToLive = 255
            replyHeader.write(to: reply)
            reply[IPv4Header.length] = 0
            ICMPMessage.storeChecksum(in: reply, from: IPv4Header.length, at: IPv4Header.length + 2)
        }
    }

    private mutating func sendProtocolUnreachable(for datagram: UnsafeRawBufferPointer, header: IPv4Header) {
        output.append(ICMPMessage.error(type: 3, code: 2, quoting: datagram, from: header.destination, to: header.source))
    }

    private mutating func replyToEchoRequest(in datagram: UnsafeRawBufferPointer, header: IPv6Header, payload: UnsafeRawBufferPointer) {
        guard payload.count >= 8, payload[0] == 128 else { return }
        send(byteCount: IPv6Header.length + payload.count, isIPv6: true) { reply in
            IPv6Header(
                payloadLength: payload.count,
                nextHeader: 58,
                hopLimit: 255,
                source: header.destination,
                destination: header.source
            ).write(to: reply)
            UnsafeMutableRawBufferPointer(rebasing: reply[IPv6Header.length...]).copyMemory(from: payload)
            reply[IPv6Header.length] = 129
            ICMPMessage.storeChecksum(
                in: reply, from: IPv6Header.length, at: IPv6Header.length + 2,
                pseudoHeaderFor: .v6(header.destination), destination: .v6(header.source), protocol: 58
            )
        }
    }

    private mutating func sendParameterProblem(for datagram: UnsafeRawBufferPointer, header: IPv6Header, code: UInt8, pointer: UInt32) {
        output.append(ICMPMessage.error(type: 4, code: code, parameter: pointer, quoting: datagram, from: header.destination, to: header.source))
    }

    private mutating func send(byteCount: Int, isIPv6: Bool, _ fill: (UnsafeMutableRawBufferPointer) -> Void) {
        output.append(OutboundPacket(byteCount: byteCount, isIPv6: isIPv6, fill))
    }
}
