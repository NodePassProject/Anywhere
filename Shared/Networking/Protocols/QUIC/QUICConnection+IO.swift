//
//  QUICConnection+IO.swift
//  Anywhere
//
//  Created by NodePassProject on 7/18/26.
//

import Foundation
import Network
import AnywhereQUIC

extension QUICConnectionCore {

    // MARK: Path-aware carrier I/O

    func armReceive(
        _ carrier: QUICDatagramCarrier,
        localAddr: sockaddr_storage,
        onError: @escaping @Sendable (Int32) -> Void
    ) {
        carrier.startReceiving(
            onPacket: { [weak owner, weak carrier] packets in
                guard let carrier else { return }
                owner?.update { core in
                    guard core.isReceiving(from: carrier) else { return }
                    core.handleReceivedPackets(packets, localAddr: localAddr)
                }
            },
            onError: onError
        )
    }

    func armActiveCarrier(_ carrier: QUICDatagramCarrier, localAddr: sockaddr_storage) {
        armReceive(carrier, localAddr: localAddr) { [weak owner, weak carrier] errno in
            guard let carrier else { return }
            owner?.update { core in
                guard core.carrier === carrier else { return }
                core.close(error: AnywhereError.quic(.connectionFailed(detail: "recv errno=\(errno)")))
            }
        }
        installMigrationTriggers(on: carrier)
    }

    func installMigrationTriggers(on carrier: QUICDatagramCarrier) {
        guard migrationEnabled else { return }
        carrier.onPathDown = { [weak owner, weak carrier] in
            guard let carrier else { return }
            owner?.update { core in
                guard core.carrier === carrier else { return }
                core.attemptReactiveMigration()
            }
        }
        carrier.onBetterPath = { [weak owner, weak carrier] in
            guard let carrier else { return }
            owner?.update { core in
                guard core.carrier === carrier else { return }
                core.attemptProactiveMigration()
            }
        }
    }

    private func isReceiving(from source: QUICDatagramCarrier) -> Bool {
        guard phase != .closed else { return false }
        if carrier === source { return true }
        switch migration {
        case .proactiveProbing(let target, _), .proactiveValidating(let target, _): return target === source
        case .none, .reactiveValidating: return false
        }
    }

    // MARK: Packet processing

    func handleReceivedPacket(_ packet: Data, localAddr: sockaddr_storage) {
        handleReceivedPackets(CollectionOfOne(packet), localAddr: localAddr)
    }

    func handleReceivedPackets(_ packets: some Sequence<Data>, localAddr: sockaddr_storage) {
        guard let engine else { return }
        if let dialAttempt {
            self.dialAttempt = nil
            dialAttempt.noteServerResponse()
        }
        let path = quicPath(local: localAddr)
        for packet in packets where !packet.isEmpty {
            engine.receive(packet, from: path, now: currentTimestamp())
        }
        drainEngineEvents(engine)
        if phase != .closed { scheduleFlush() }
    }

    func pumpDatagrams(_ engine: AnywhereQUIC.QUICConnection) {
        guard !pendingDatagrams.isEmpty, engine.state == .established else { return }
        var consumed = 0
        defer { pendingDatagrams.removeFirst(consumed) }
        while consumed < pendingDatagrams.count {
            let head = pendingDatagrams[consumed]
            do {
                try engine.sendDatagram(head.data)
            } catch QUICError.sendBufferFull {
                return
            } catch {
                consumed += 1
                let failure: Error
                switch error {
                case .datagramTooLarge:
                    failure = AnywhereError.quic(.datagramTooLarge(limit: engine.maxDatagramPayloadSize))
                case .invalidState:
                    failure = AnywhereError.quic(.closed(graceful: false))
                default:
                    failure = AnywhereError.quic(.connectionFailed(detail: String(describing: error)))
                }
                head.latch?.settle(failure)
                continue
            }
            consumed += 1
            head.latch?.settle(nil)
        }
    }

    func writeToUDP() {
        guard let engine, phase != .closed else { return }
        let now = currentTimestamp()
        pumpStreamQueues(engine)
        pumpDatagrams(engine)
        while let outgoing = txBuffer.withUnsafeMutableBufferPointer({ engine.write(into: $0, now: now) }) {
            sendTxBuf(length: outgoing.count, to: carrierForOutPath(local: outgoing.path.local))
            pumpDatagrams(engine)
        }
        engine.finishWriting(now: now)
        drainEngineEvents(engine)
        rescheduleTimer()
    }

    // MARK: Timer

    func makeRetransmitTimer() -> BridgeDeadlineTimer {
        BridgeDeadlineTimer(queue: .global(qos: .userInitiated)) { [weak owner] in
            owner?.update { core in
                guard core.phase != .closed, let engine = core.engine else { return }
                core.lastScheduledExpiry = 0
                engine.handleTimeout(now: core.currentTimestamp())
                core.drainEngineEvents(engine)
                core.writeToUDP()
            }
        }
    }

    func rescheduleTimer() {
        guard let engine, let retransmitTimer, phase != .closed else { return }
        let expiry = engine.nextTimeout?.nanoseconds ?? UInt64.max
        if expiry == lastScheduledExpiry { return }
        lastScheduledExpiry = expiry
        guard expiry != UInt64.max else {
            retransmitTimer.parkUntilRearmed()
            return
        }
        let now = currentTimestamp().nanoseconds
        retransmitTimer.schedule(afterNanoseconds: expiry > now ? expiry - now : 0)
    }
}
