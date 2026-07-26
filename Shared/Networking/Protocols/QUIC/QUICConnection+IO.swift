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


    // MARK: Packet Processing
    
    func isBenignConnectionClose(_ ccerr: ngtcp2_ccerr) -> Bool {
        if ccerr.type == NGTCP2_CCERR_TYPE_TRANSPORT {
            return ccerr.error_code == 0
        }
        if ccerr.type == NGTCP2_CCERR_TYPE_APPLICATION {
            return ccerr.error_code == 0 || ccerr.error_code == 0x100
        }
        return false
    }
    
    func handleReceivedPacket(_ packet: Data, localAddr: sockaddr_storage) {
        if let dialAttempt {
            self.dialAttempt = nil
            dialAttempt.noteServerResponse()
        }

        guard let connectionOpaquePointer else { return }

        let ts = currentTimestamp()
        var pi = ngtcp2_pkt_info()

        inReadPkt = true
        defer { inReadPkt = false }

        let prevBusy = enterConnHeld()
        let rv: Int32 = packet.withUnsafeBytes { raw -> Int32 in
            guard let pointer = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return -1 }
            return readPacket(
                connectionOpaquePointer,
                localAddr: localAddr,
                remoteAddr: remoteAddr,
                addrLen: addrLen,
                pktInfo: &pi,
                data: pointer,
                count: packet.count,
                ts: ts
            )
        }
        exitConnHeld(prevBusy)

        if rv != 0 {
            let error: Error
            switch rv {
            case NGTCP2_ERR_DRAINING:
                if let ccerr = closeError(connectionOpaquePointer), isBenignConnectionClose(ccerr.pointee) {
                    error = AnywhereError.quic(.closed(graceful: true))
                } else {
                    error = AnywhereError.quic(.closed(graceful: false))
                }
            case NGTCP2_ERR_CLOSING:
                error = AnywhereError.quic(.closed(graceful: false))
            case NGTCP2_ERR_CALLBACK_FAILURE, NGTCP2_ERR_CRYPTO:
                error = tlsHandler?.handshakeError
                    ?? AnywhereError.quic(.handshakeFailed(detail: "ngtcp2 error: \(rv) (\(errorString(rv)))"))
            default:
                error = AnywhereError.quic(.connectionFailed(detail: "ngtcp2 read_pkt: \(rv) (\(errorString(rv)))"))
            }
            finishConnect(error)
            close(error: error)
            return
        }
        scheduleFlush()
    }

    func writeToUDP() {
        guard let connectionOpaquePointer else { return }

        let prevBusy = enterConnHeld()
        defer { exitConnHeld(prevBusy) }
        let ts = currentTimestamp()
        var pi = ngtcp2_pkt_info()

        var settlements: [(DatagramBatchLatch?, Error?)] = []

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
                    writeDatagram(
                        connectionOpaquePointer,
                        chosenLocalAddr: &chosenLocal,
                        pktInfo: &pi,
                        dest: destination.baseAddress,
                        destCapacity: destination.count,
                        accepted: &accepted,
                        flags: flags,
                        datagramId: 0,
                        data: srcPtr,
                        dataLength: datagram.count,
                        ts: ts
                    )
                }
            }
            let outCarrier = carrierForOutPath(local: chosenLocal)
            
            if nwrite == ngtcp2_ssize(NGTCP2_ERR_WRITE_MORE) {
                let popped = pendingDatagrams.removeFirst()
                settlements.append((popped.latch, nil))
                continue
            }
            if nwrite < 0 {
                logger.warning("[QUIC] Dropping \(datagram.count)-byte datagram: ngtcp2 err \(nwrite)")
                let popped = pendingDatagrams.removeFirst()
                settlements.append((popped.latch, AnywhereError.quic(.connectionFailed(detail: "ngtcp2 write_datagram err \(nwrite)"))))
                continue
            }
            if nwrite > 0 {
                sendTxBuf(length: Int(nwrite), to: outCarrier)
            }
            if accepted != 0 {
                let popped = pendingDatagrams.removeFirst()
                settlements.append((popped.latch, nil))
                continue
            }
            if nwrite > 0 {
                continue
            }
            
            let bound = maxDatagramPayloadSize
            if datagram.count > bound {
                logger.warning("[QUIC] Dropping \(datagram.count)-byte datagram: exceeds path-MTU bound (\(bound) B)")
                let popped = pendingDatagrams.removeFirst()
                settlements.append((popped.latch, AnywhereError.quic(.datagramTooLarge(limit: bound))))
                continue
            }
            
            break
        }

        pumpStreamQueues(connectionOpaquePointer, ts: ts)

        while true {
            var chosenLocal = sockaddr_storage()
            let nwrite = txBuffer.withUnsafeMutableBufferPointer { destination -> ngtcp2_ssize in
                writePacket(
                    connectionOpaquePointer,
                    chosenLocalAddr: &chosenLocal,
                    pktInfo: &pi,
                    dest: destination.baseAddress,
                    destCapacity: destination.count,
                    ts: ts
                )
            }
            if nwrite <= 0 { break }
            sendTxBuf(length: Int(nwrite), to: carrierForOutPath(local: chosenLocal))
        }

        updatePacketTxTime(connectionOpaquePointer, ts: ts)

        rescheduleTimer()

        for (latch, error) in settlements { latch?.settle(error) }
    }


    // MARK: Timer

    func rescheduleTimer() {
        guard let connectionOpaquePointer else { return }
        var expiry = self.expiry(connectionOpaquePointer)
        
        if !pendingDatagrams.isEmpty || streamSendQueues.contains(where: { $0.value.hasUnsent }) {
            expiry = min(expiry, currentTimestamp() &+ 2_000_000)
        }

        if expiry == lastScheduledExpiry && retransmitTimer != nil { return }
        lastScheduledExpiry = expiry

        let timer: BridgeDeadlineTimer
        if let existing = retransmitTimer {
            timer = existing
        } else {
            timer = bridge.makeDeadlineTimer { [weak self] in
                guard let self else { return }
                self.assumeIsolated { me in
                    guard let connectionOpaquePointer = me.connectionOpaquePointer else { return }
                    me.lastScheduledExpiry = 0
                    let ts = me.currentTimestamp()
                    let prevBusy = me.enterConnHeld()
                    let rv = me.handleExpiry(connectionOpaquePointer, ts: ts)
                    me.exitConnHeld(prevBusy)
                    if rv != 0 {
                        let error = AnywhereError.quic(.connectionFailed(detail: "expiry error: \(rv) (\(me.errorString(rv)))"))
                        me.finishConnect(error)
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
