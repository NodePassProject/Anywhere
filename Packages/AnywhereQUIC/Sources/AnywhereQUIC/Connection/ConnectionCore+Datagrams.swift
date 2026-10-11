//
//  ConnectionCore+Datagrams.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

import Foundation

extension ConnectionCore {
    static let maximumPendingDatagrams = 256

    var maxDatagramPayloadSize: Int {
        guard self.peerMaxDatagramFrameSize > 0 else {
            return 0
        }
        let packetOverhead = 1 + self.active.connectionID.id.count + 4 + AEADAlgorithm.tagLength
        let frameLimit = Swift.min(
            UInt64(Swift.max(0, self.pathMaxSendUDPPayloadSize - packetOverhead)),
            self.peerMaxDatagramFrameSize
        )
        guard frameLimit >= 2 else {
            return 0
        }
        var payload = Int(frameLimit) - 2
        while 1 + VarInt.encodedLength(UInt64(payload)) + payload > Int(frameLimit) {
            payload -= 1
        }
        return payload
    }

    func sendDatagram(_ data: Data) throws(QUICError) {
        try self.sendDatagrams([data])
    }

    var pendingDatagramCount: Int { self.pendingDatagrams.count }

    func sendDatagrams(_ datagrams: [Data]) throws(QUICError) {
        guard !datagrams.isEmpty else {
            return
        }
        guard self.state == .established else {
            throw QUICError.invalidState
        }
        guard self.peerMaxDatagramFrameSize > 0 else {
            throw QUICError.datagramUnsupported
        }
        let limit = self.maxDatagramPayloadSize
        for data in datagrams {
            guard data.count <= limit,
                  UInt64(1 + VarInt.encodedLength(UInt64(data.count)) + data.count) <= self.peerMaxDatagramFrameSize else {
                throw QUICError.datagramTooLarge
            }
        }
        guard datagrams.count <= Swift.max(0, self.settings.maxPendingDatagrams - self.pendingDatagrams.count) else {
            throw QUICError.sendBufferFull
        }
        self.pendingDatagrams.append(contentsOf: datagrams)
    }

    func writeDatagramFrames(builder: inout PacketBuilder, flags: inout PacketFlags) {
        let limit = self.maxDatagramPayloadSize
        while let data = self.pendingDatagrams.first {
            guard data.count <= limit else {
                self.pendingDatagrams.removeFirst()
                continue
            }
            guard data.withUnsafeBytes({ bytes in builder.withWriter { $0.writeDatagram(bytes) } }) else {
                break
            }
            self.pendingDatagrams.removeFirst()
            flags.isACKEliciting = true
            flags.isPTOEliciting = true
        }
    }
}
