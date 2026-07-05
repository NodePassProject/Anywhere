//
//  UDPFraming.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import Synchronization

/// Buffered incoming bytes for UDP framing; wrapped in `UDPFramingCapable.udpState`.
struct UDPFramingState {
    var buffer = Data()
    var bufferOffset = 0
}

/// UDP packets are length-prefixed with 2 bytes (big-endian)
protocol UDPFramingCapable: AnyObject {
    var udpState: Mutex<UDPFramingState> { get }
}

extension UDPFramingCapable {
    func frameUDPPacket(_ data: Data) -> Data {
        var framedData = Data(capacity: 2 + data.count)
        let length = UInt16(data.count)
        framedData.append(UInt8(length >> 8))
        framedData.append(UInt8(length & 0xFF))
        framedData.append(data)
        return framedData
    }

    /// Extracts one length-prefixed packet; call inside `udpState.withLock`.
    func extractUDPPacket(from state: inout UDPFramingState) -> Data? {
        let available = state.buffer.count - state.bufferOffset
        guard available >= 2 else { return nil }

        let length = Int(UInt16(state.buffer[state.bufferOffset]) << 8 | UInt16(state.buffer[state.bufferOffset + 1]))
        guard available >= 2 + length else { return nil }

        let packetStart = state.bufferOffset + 2
        let packetEnd = packetStart + length
        let packet = Data(state.buffer[packetStart..<packetEnd])

        state.bufferOffset = packetEnd

        // Compact buffer periodically to avoid unbounded growth
        if state.bufferOffset > 8192 {
            state.buffer.removeSubrange(0..<state.bufferOffset)
            state.bufferOffset = 0
        }

        return packet
    }

    /// Drops all buffered bytes; call inside `udpState.withLock`.
    func clearUDPBuffer(_ state: inout UDPFramingState) {
        state.buffer = Data()
        state.bufferOffset = 0
    }
}
