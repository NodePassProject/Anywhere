//
//  QUICConnection+IO.swift
//  Anywhere
//
//  Created by NodePassProject on 7/18/26.
//

import Foundation
import Network
import AnywhereQUIC

extension QUICConnection {

    // MARK: Path-aware carrier I/O

    func armReceive(
        _ carrier: QUICDatagramCarrier,
        localAddr: sockaddr_storage,
        onError: @escaping @Sendable (Int32) -> Void
    ) {
        carrier.assumeIsolated {
            $0.startReceiving(
                onPacket: { [weak self] data in self?.assumeIsolated { $0.handleReceivedPacket(data, localAddr: localAddr) } },
                onError: onError
            )
        }
    }

    func armActiveCarrier(_ carrier: QUICDatagramCarrier, localAddr: sockaddr_storage) {
        armReceive(carrier, localAddr: localAddr) { [weak self] errno in
            self?.close(error: AnywhereError.quic(.connectionFailed(detail: "recv errno=\(errno)")))
        }
        installMigrationTriggers(on: carrier)
    }

    func installMigrationTriggers(on carrier: QUICDatagramCarrier) {
        guard migrationEnabled else { return }
        carrier.assumeIsolated {
            $0.onPathDown = { [weak self] in self?.assumeIsolated { $0.attemptReactiveMigration() } }
            $0.onBetterPath = { [weak self] in self?.assumeIsolated { $0.attemptProactiveMigration() } }
        }
    }

    // MARK: Packet processing

    func handleReceivedPacket(_ packet: Data, localAddr: sockaddr_storage) {
        guard !packet.isEmpty, let engine else { return }
        if let dialAttempt {
            self.dialAttempt = nil
            dialAttempt.noteServerResponse()
        }
        inReadPkt = true
        let previous = enterConnHeld()
        defer {
            exitConnHeld(previous)
            inReadPkt = false
        }
        engine.receive(packet, from: quicPath(local: localAddr), now: currentTimestamp())
        drainEngineEvents(engine)
        if phase != .closed { scheduleFlush() }
    }

    func pumpDatagrams(_ engine: AnywhereQUIC.QUICConnection) {
        guard engine.state == .established else { return }
        while let head = pendingDatagrams.first {
            do {
                try engine.sendDatagram(head.data)
            } catch QUICError.sendBufferFull {
                return
            } catch {
                pendingDatagrams.removeFirst()
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
            pendingDatagrams.removeFirst()
            head.latch?.settle(nil)
        }
    }

    func writeToUDP() {
        guard let engine, phase != .closed else { return }
        guard !connHeld, !inReadPkt else {
            scheduleFlush()
            return
        }
        let previous = enterConnHeld()
        defer { exitConnHeld(previous) }
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

    func rescheduleTimer() {
        guard let engine, phase != .closed else { return }
        let expiry = engine.nextTimeout?.nanoseconds ?? UInt64.max
        if expiry == lastScheduledExpiry && retransmitTimer != nil { return }
        lastScheduledExpiry = expiry

        let timer: BridgeDeadlineTimer
        if let existing = retransmitTimer {
            timer = existing
        } else {
            timer = bridge.makeDeadlineTimer { [weak self] in
                self?.assumeIsolated { me in
                    guard let engine = me.engine else { return }
                    me.lastScheduledExpiry = 0
                    let previous = me.enterConnHeld()
                    engine.handleTimeout(now: me.currentTimestamp())
                    me.drainEngineEvents(engine)
                    me.exitConnHeld(previous)
                    me.writeToUDP()
                }
            }
            retransmitTimer = timer
        }

        if expiry == UInt64.max {
            timer.parkUntilRearmed()
        } else {
            let now = currentTimestamp().nanoseconds
            timer.schedule(afterNanoseconds: expiry > now ? expiry - now : 0)
        }
    }
}
