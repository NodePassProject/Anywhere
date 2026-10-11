//
//  InboundBatch.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/27/26.
//

import Foundation

struct InboundBatch {
    private static let linearGroupLimit = 8

    private let decodesUDP: Bool
    private(set) var control: [OutboundPacket] = []
    private(set) var datagrams: [InboundDatagram] = []
    private(set) var groups: [[InboundTCP]] = []
    private(set) var segmentCount = 0
    private var index: [ConnectionKey: Int] = [:]

    init(decodesUDP: Bool) {
        self.decodesUDP = decodesUDP
    }

    mutating func decode(_ packet: UnsafeRawBufferPointer) {
        var decoder = PacketDecoder(decodesUDP: decodesUDP)
        decoder.decode(packet)
        if !decoder.output.isEmpty { control.append(contentsOf: decoder.output) }
        if let udp = decoder.udp { datagrams.append(udp) }
        if let tcp = decoder.tcp { add(tcp) }
    }

    private mutating func add(_ packet: InboundTCP) {
        segmentCount += 1
        if let last = groups.indices.last, groups[last][0].key == packet.key {
            groups[last].append(packet)
        } else if let existing = group(for: packet.key) {
            groups[existing].append(packet)
        } else {
            if groups.count >= Self.linearGroupLimit {
                if index.isEmpty {
                    for (position, group) in groups.enumerated() { index[group[0].key] = position }
                }
                index[packet.key] = groups.count
            }
            groups.append([packet])
        }
    }

    private func group(for key: ConnectionKey) -> Int? {
        groups.count > Self.linearGroupLimit ? index[key] : groups.firstIndex { $0[0].key == key }
    }
}
