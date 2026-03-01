//
//  UDPFraming.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

/// Protocol providing UDP packet framing capabilities
/// UDP packets are length-prefixed with 2 bytes (big-endian)
protocol UDPFramingCapable: AnyObject {
    var udpBuffer: Data { get set }
    var udpBufferOffset: Int { get set }
    var udpLock: UnfairLock { get }
}

extension UDPFramingCapable {
    /// Frame a UDP packet with 2-byte length prefix
    func frameUDPPacket(_ data: Data) -> Data {
        var framedData = Data(capacity: 2 + data.count)
        let length = UInt16(data.count)
        framedData.append(UInt8(length >> 8))
        framedData.append(UInt8(length & 0xFF))
        framedData.append(data)
        return framedData
    }

    /// Extract a complete UDP packet from the buffer
    /// Returns nil if not enough data is available
    func extractUDPPacket() -> Data? {
        let available = udpBuffer.count - udpBufferOffset
        guard available >= 2 else { return nil }

        let length = Int(UInt16(udpBuffer[udpBufferOffset]) << 8 | UInt16(udpBuffer[udpBufferOffset + 1]))
        guard available >= 2 + length else { return nil }

        let packetStart = udpBufferOffset + 2
        let packetEnd = packetStart + length
        let packet = Data(udpBuffer[packetStart..<packetEnd])

        udpBufferOffset = packetEnd

        // Compact buffer periodically to avoid unbounded growth
        if udpBufferOffset > 8192 {
            udpBuffer.removeSubrange(0..<udpBufferOffset)
            udpBufferOffset = 0
        }

        return packet
    }

    /// Clear UDP buffer state
    func clearUDPBuffer() {
        udpBuffer = Data()
        udpBufferOffset = 0
    }
}
