//
//  Context.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

import Foundation
import Synchronization

final class Context {
    enum CoreEffect {
        case packet(OutboundPacket)
        case received(UnsafeRawBufferPointer, push: Bool)
        case acknowledged(Int)
        case ready, fin, ended, removed, timeWait
        case failed(ConnectionError)
    }
    
    let arena = SegmentArena()
    let initialSequenceNumber: UInt32
    private let template: PacketTemplate
    var ticks: UInt32
    var batching = false
    var effects: [CoreEffect] = []

    init(key: ConnectionKey, initialSequenceNumber: UInt32, ticks: UInt32) {
        template = PacketTemplate(from: key.local, to: key.remote)
        self.initialSequenceNumber = initialSequenceNumber
        self.ticks = ticks
    }

    func advance(to ticks: UInt32) {
        if Sequence.lessThan(self.ticks, ticks) { self.ticks = ticks }
    }

    func receive(_ bytes: UnsafeRawBufferPointer, push: Bool) {
        guard !bytes.isEmpty else { return }
        effects.append(.received(bytes, push: push))
    }

    func sendReset(from local: IPEndpoint, to remote: IPEndpoint, sequenceNumber: UInt32, acknowledgmentNumber: UInt32) {
        guard let packet = OutboundPacket(resetFrom: local, to: remote, sequenceNumber: sequenceNumber, acknowledgmentNumber: acknowledgmentNumber) else { return }
        effects.append(.packet(packet))
    }

    func transmit(_ segment: Segment, acknowledgmentNumber: UInt32, window: UInt16) {
        defer { if !segment.isQueued { arena.recycle(segment) } }
        let start = IPv6Header.length - template.headerLength
        let end = IPv6Header.length + TCPHeader.length + segment.options.encodedLength + segment.length
        let packet = UnsafeMutableRawBufferPointer(rebasing: segment.buffer[start..<end])
        template.encode(
            into: packet,
            sequenceNumber: segment.sequenceNumber,
            acknowledgmentNumber: acknowledgmentNumber,
            flags: segment.flags,
            options: segment.options,
            window: window,
            payloadLength: segment.length,
            payloadSum: segment.payloadSum
        )
        effects.append(.packet(OutboundPacket(copying: UnsafeRawBufferPointer(packet), isIPv6: template.isIPv6)))
    }
}
