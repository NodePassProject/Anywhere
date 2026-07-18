//
//  QUICConnection+IO.swift
//  Anywhere
//
//  Created by NodePassProject on 7/18/26.
//

import Foundation
import Network
import CryptoKit
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "QUICConnection")

extension QUICConnection {

    // MARK: Path-aware carrier I/O

    /// Arms a carrier's receive loop, tagging inbound packets with `localAddr` so
    /// ngtcp2 attributes them to the right path. Migration triggers are set elsewhere.
    func armReceive(_ carrier: QUICDatagramCarrier, localAddr: sockaddr_storage,
                            onError: @escaping @Sendable (Int32) -> Void) {
        carrier.assumeIsolated {
            $0.startReceiving(
                onPacket: { [weak self] data in self?.assumeIsolated { $0.handleReceivedPacket(data, localAddr: localAddr) } },
                onError: onError
            )
        }
    }

    /// Arms the active carrier's receive loop (close on hard error) and migration triggers.
    func armActiveCarrier(_ carrier: QUICDatagramCarrier, localAddr: sockaddr_storage) {
        armReceive(carrier, localAddr: localAddr) { [weak self] errno in
            self?.close(error: QUICError.connectionFailed("recv errno=\(errno)"))
        }
        installMigrationTriggers(on: carrier)
    }

    /// Sets the reactive (path-down) and proactive (better-path) triggers; no-op when migration is off.
    func installMigrationTriggers(on carrier: QUICDatagramCarrier) {
        guard migrationEnabled else { return }
        carrier.assumeIsolated {
            $0.onPathDown = { [weak self] in self?.assumeIsolated { $0.attemptReactiveMigration() } }
            $0.onBetterPath = { [weak self] in self?.assumeIsolated { $0.attemptProactiveMigration() } }
        }
    }


    // MARK: Packet Processing

    /// A peer CONNECTION_CLOSE is benign (graceful) when it carries transport NO_ERROR (0)
    /// or an application code of 0 / 0x100 (HTTP/3 H3_NO_ERROR).
    func isBenignConnectionClose(_ ccerr: ngtcp2_ccerr) -> Bool {
        if ccerr.type == NGTCP2_CCERR_TYPE_TRANSPORT {
            return ccerr.error_code == 0
        }
        if ccerr.type == NGTCP2_CCERR_TYPE_APPLICATION {
            return ccerr.error_code == 0 || ccerr.error_code == 0x100
        }
        return false
    }

    func handleReceivedPacket(_ data: Data, localAddr: sockaddr_storage) {
        guard let connectionOpaquePointer else { return }

        // Deobfuscate first; a `nil` result is an incomplete fragment or malformed packet — nothing
        // to feed ngtcp2 yet.
        let packet: Data
        if let obfuscator {
            guard let opened = obfuscator.open(data) else { return }
            packet = opened
        } else {
            packet = data
        }

        let ts = currentTimestamp()
        var pi = ngtcp2_pkt_info()

        inReadPkt = true
        defer { inReadPkt = false }

        // Guard close() from freeing `conn` while ngtcp2 is still on the stack.
        let prevBusy = bridge.enterConnHeld()
        let rv: Int32 = packet.withUnsafeBytes { raw -> Int32 in
            guard let pointer = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return -1 }
            return bridge.readPacket(connectionOpaquePointer, localAddr: localAddr, remoteAddr: remoteAddr,
                                     addrLen: addrLen, pktInfo: &pi, data: pointer, count: packet.count, ts: ts)
        }
        bridge.exitConnHeld(prevBusy)

        if rv != 0 {
            // Any non-zero read_pkt return is terminal. Close now: a UDP-only workload
            // has no read pressure and would otherwise sit on a dead connection for the keep-alive window.
            let error: Error
            switch rv {
            case NGTCP2_ERR_DRAINING:
                // Peer sent CONNECTION_CLOSE. A benign code (NO_ERROR / H3_NO_ERROR 0x100)
                // is a graceful end-of-connection.
                if let ccerr = bridge.closeError(connectionOpaquePointer), isBenignConnectionClose(ccerr.pointee) {
                    error = QUICError.closedOK
                } else {
                    error = QUICError.closed
                }
            case NGTCP2_ERR_CLOSING:
                error = QUICError.closed
            case NGTCP2_ERR_CALLBACK_FAILURE, NGTCP2_ERR_CRYPTO:
                error = tlsHandler?.handshakeError
                    ?? QUICError.handshakeFailed("ngtcp2 error: \(rv) (\(bridge.errorString(rv)))")
            default:
                error = QUICError.connectionFailed("ngtcp2 read_pkt: \(rv) (\(bridge.errorString(rv)))")
            }
            if let callback = connectCompletion {
                connectCompletion = nil
                callback(error)
            }
            close(error: error)
            return
        }
        scheduleFlush()
    }

    func writeToUDP() {
        guard let connectionOpaquePointer else { return }
        // Defer close() until we return; tail completions may re-enter ngtcp2.
        let prevBusy = bridge.enterConnHeld()
        defer { bridge.exitConnHeld(prevBusy) }
        let ts = currentTimestamp()
        var pi = ngtcp2_pkt_info()

        // Fire completions only after all ngtcp2 work: ngtcp2.h forbids other calls
        // between WRITE_MORE and the next write_datagram, and a completion could re-enter.
        var pendingCompletions: [(((Error?) -> Void)?, Error?)] = []

        // Drain datagrams first; WRITE_MORE packs multiple into one UDP packet.
        while !pendingDatagrams.isEmpty {
            var accepted: Int32 = 0
            let head = pendingDatagrams[0]
            let datagram = head.data
            let flags: UInt32 = pendingDatagrams.count > 1
                ? UInt32(NGTCP2_WRITE_DATAGRAM_FLAG_MORE)
                : 0

            var chosenLocal = sockaddr_storage()
            let nwrite = datagram.withUnsafeBytes { rawBuf -> ngtcp2_ssize in
                guard let srcPtr = rawBuf.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                    return 0
                }
                return txBuffer.withUnsafeMutableBufferPointer { destination -> ngtcp2_ssize in
                    bridge.writeDatagram(
                        connectionOpaquePointer, chosenLocalAddr: &chosenLocal, pktInfo: &pi,
                        dest: destination.baseAddress, destCapacity: destination.count,
                        accepted: &accepted, flags: flags, datagramId: 0,
                        data: srcPtr, dataLength: datagram.count, ts: ts
                    )
                }
            }
            let outCarrier = carrierForOutPath(local: chosenLocal)

            // WRITE_MORE: datagram committed to the in-progress packet (per ngtcp2.h).
            if nwrite == ngtcp2_ssize(NGTCP2_ERR_WRITE_MORE) {
                let popped = pendingDatagrams.removeFirst()
                pendingCompletions.append((popped.completion, nil))
                continue
            }
            if nwrite < 0 {
                // Fatal error (e.g. exceeds max_datagram_frame_size) — drop.
                logger.warning("[QUIC] Dropping \(datagram.count)-byte datagram: ngtcp2 err \(nwrite)")
                let popped = pendingDatagrams.removeFirst()
                pendingCompletions.append((popped.completion, QUICError.connectionFailed("ngtcp2 write_datagram err \(nwrite)")))
                continue
            }
            if nwrite > 0 {
                sendTxBuf(length: Int(nwrite), to: outCarrier)
            }
            if accepted != 0 {
                let popped = pendingDatagrams.removeFirst()
                pendingCompletions.append((popped.completion, nil))
                continue
            }
            if nwrite > 0 {
                // Packet flushed but head didn't fit; retry with a fresh packet.
                continue
            }
            // nwrite == 0, accepted == 0: CW full or head too large — use the
            // path-MTU bound to distinguish, dropping rather than wedging the queue.
            let bound = maxDatagramPayloadSize
            if datagram.count > bound {
                logger.warning("[QUIC] Dropping \(datagram.count)-byte datagram: exceeds path-MTU bound (\(bound) B)")
                let popped = pendingDatagrams.removeFirst()
                pendingCompletions.append((popped.completion, QUICError.datagramTooLarge(maxBound: bound)))
                continue
            }
            // Congestion window full; retry on the next writeToUDP.
            break
        }

        while true {
            var chosenLocal = sockaddr_storage()
            let nwrite = txBuffer.withUnsafeMutableBufferPointer { destination -> ngtcp2_ssize in
                bridge.writePacket(connectionOpaquePointer, chosenLocalAddr: &chosenLocal, pktInfo: &pi,
                                   dest: destination.baseAddress, destCapacity: destination.count, ts: ts)
            }
            if nwrite <= 0 { break }
            sendTxBuf(length: Int(nwrite), to: carrierForOutPath(local: chosenLocal))
        }

        // Updates conn->tx.pacing.next_ts; without it the pacer is disabled and sends burst cwnd-wide.
        bridge.updatePacketTxTime(connectionOpaquePointer, ts: ts)

        rescheduleTimer()

        // Fire completions after all ngtcp2 work; safe to re-enter ngtcp2 here.
        for (callback, error) in pendingCompletions { callback?(error) }
    }


    // MARK: Timer

    func rescheduleTimer() {
        guard let connectionOpaquePointer else { return }
        let expiry = bridge.expiry(connectionOpaquePointer)

        if expiry == lastScheduledExpiry && retransmitTimer != nil { return }
        lastScheduledExpiry = expiry

        let timer: BridgeDeadlineTimer
        if let existing = retransmitTimer {
            timer = existing
        } else {
            // Fires on the bridge queue (this actor's executor), so `assumeIsolated` is valid.
            timer = bridge.makeDeadlineTimer { [weak self] in
                guard let self else { return }
                self.assumeIsolated { me in
                    guard let connectionOpaquePointer = me.connectionOpaquePointer else { return }
                    me.lastScheduledExpiry = 0
                    let ts = me.currentTimestamp()
                    // handle_expiry may fire CC callbacks; bracket so a close inside is deferred.
                    let prevBusy = me.bridge.enterConnHeld()
                    let rv = me.bridge.handleExpiry(connectionOpaquePointer, ts: ts)
                    me.bridge.exitConnHeld(prevBusy)
                    if rv != 0 {
                        let error = QUICError.connectionFailed("expiry error: \(rv) (\(me.bridge.errorString(rv)))")
                        if let callback = me.connectCompletion {
                            me.connectCompletion = nil
                            callback(error)
                        }
                        me.close(error: error)
                        return
                    }
                    me.writeToUDP()
                }
            }
            retransmitTimer = timer
        }

        if expiry == UInt64.max {
            timer.parkUntilRearmed()
        } else {
            let now = currentTimestamp()
            let delay = expiry > now ? expiry - now : 0
            timer.schedule(afterNanoseconds: delay)
        }
    }

}
