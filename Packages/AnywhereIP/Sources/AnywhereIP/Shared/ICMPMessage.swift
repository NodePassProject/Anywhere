//
//  ICMPMessage.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/25/26.
//

enum ICMPMessage {
    static func error(
        type: UInt8,
        code: UInt8,
        parameter: UInt32 = 0,
        quoting datagram: UnsafeRawBufferPointer,
        from source: IPAddress.V4,
        to destination: IPAddress.V4
    ) -> OutboundPacket {
        let quoted = min(datagram.count, IPv4Header.length + 8)
        let length = IPv4Header.length + 8 + quoted
        return OutboundPacket(byteCount: length, isIPv6: false) { packet in
            IPv4Header(
                totalLength: length,
                timeToLive: 255,
                protocol: 1,
                source: source,
                destination: destination,
                identification: PacketIdentification.next()
            ).write(to: packet)
            let message = UnsafeMutableRawBufferPointer(rebasing: packet[IPv4Header.length...])
            message[0] = type
            message[1] = code
            message.storeBytes(of: parameter.bigEndian, toByteOffset: 4, as: UInt32.self)
            UnsafeMutableRawBufferPointer(rebasing: message[8...]).copyMemory(from: UnsafeRawBufferPointer(rebasing: datagram[..<quoted]))
            storeChecksum(in: packet, from: IPv4Header.length, at: IPv4Header.length + 2)
        }
    }

    static func error(
        type: UInt8,
        code: UInt8,
        parameter: UInt32 = 0,
        quoting datagram: UnsafeRawBufferPointer,
        from source: IPAddress.V6,
        to destination: IPAddress.V6
    ) -> OutboundPacket {
        let quoted = min(datagram.count, 1280 - IPv6Header.length - 8)
        return OutboundPacket(byteCount: IPv6Header.length + 8 + quoted, isIPv6: true) { packet in
            IPv6Header(
                payloadLength: 8 + quoted,
                nextHeader: 58,
                hopLimit: 255,
                source: source,
                destination: destination
            ).write(to: packet)
            let message = UnsafeMutableRawBufferPointer(rebasing: packet[IPv6Header.length...])
            message[0] = type
            message[1] = code
            message.storeBytes(of: parameter.bigEndian, toByteOffset: 4, as: UInt32.self)
            UnsafeMutableRawBufferPointer(rebasing: message[8...]).copyMemory(from: UnsafeRawBufferPointer(rebasing: datagram[..<quoted]))
            storeChecksum(
                in: packet, from: IPv6Header.length, at: IPv6Header.length + 2,
                pseudoHeaderFor: .v6(source), destination: .v6(destination), protocol: 58
            )
        }
    }

    static func storeChecksum(
        in buffer: UnsafeMutableRawBufferPointer,
        from start: Int,
        at offset: Int,
        pseudoHeaderFor source: IPAddress? = nil,
        destination: IPAddress? = nil,
        protocol: UInt8 = 0
    ) {
        buffer.storeBytes(of: UInt16(0), toByteOffset: offset, as: UInt16.self)
        var checksum = InternetChecksum()
        if let source, let destination {
            checksum.update(pseudoHeaderFor: source, destination: destination, protocol: `protocol`, length: buffer.count - start)
        }
        checksum.update(bufferPointer: UnsafeRawBufferPointer(rebasing: UnsafeRawBufferPointer(buffer)[start...]))
        buffer.storeBytes(of: checksum.finalize(), toByteOffset: offset, as: UInt16.self)
    }
}
