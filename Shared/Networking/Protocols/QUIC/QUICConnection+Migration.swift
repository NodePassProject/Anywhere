//
//  QUICConnection+Migration.swift
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

    // MARK: Migration

    /// Migration applies only to the direct carrier, and only if we advertised support.
    var migrationEnabled: Bool {
        transport == nil && !tuning.disableActiveMigration
    }

    /// A distinct cosmetic local addr for the next migration path, matching the remote's
    /// family. Never hits the wire (ngtcp2 uses it only as path identity), but it must
    /// differ from the current local or ngtcp2 won't see a path change.
    func makeMigrationLocalAddr() -> sockaddr_storage {
        migrationCounter = migrationCounter &+ 1
        let tag = migrationCounter == 0 ? 1 : migrationCounter
        var storage = sockaddr_storage()
        withUnsafeMutablePointer(to: &storage) { sp in
            if Int32(remoteAddr.ss_family) == AF_INET6 {
                sp.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                    sin6.pointee = sockaddr_in6()
                    sin6.pointee.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
                    sin6.pointee.sin6_family = sa_family_t(AF_INET6)
                    var a = in6addr_any
                    withUnsafeMutableBytes(of: &a) { bytes in
                        bytes[0] = 0xfd          // unique-local prefix
                        bytes[15] = tag
                    }
                    sin6.pointee.sin6_addr = a
                }
            } else {
                sp.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                    sin.pointee = sockaddr_in()
                    sin.pointee.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                    sin.pointee.sin_family = sa_family_t(AF_INET)
                    sin.pointee.sin_addr.s_addr = UInt32(tag).bigEndian  // 0.0.0.tag
                }
            }
        }
        return storage
    }

    /// The active path died. Move the live session onto a fresh carrier (picking the new
    /// OS-preferred path) via immediate migration, rather than tearing down every stream.
    /// Any failure falls back to `close()` and the pool reconnects. Runs on `queue`.
    func attemptReactiveMigration() {
        // A proactive migration is moot now the path is dead; abandon it (not a failure).
        if migrationKind == .proactive {
            migratingCarrier?.assumeIsolated { $0.close() }
            clearMigrationState()
        }

        guard migrationEnabled, state == .connected, migrationKind == nil,
              migrationFailures < Self.maxMigrationFailures,
              let conn = connectionOpaquePointer else {
            close(error: QUICError.connectionFailed("network path lost"))
            return
        }

        let newCarrier = QUICDatagramCarrier(bridge: bridge)
        var placeholder = sockaddr_storage()
        let remote = remoteAddr
        do {
            try newCarrier.assumeIsolated { try $0.connect(remoteAddr: remote, localAddr: &placeholder) }
        } catch {
            close(error: error)
            return
        }

        let newLocal = makeMigrationLocalAddr()
        let ts = currentTimestamp()
        // Bracket the ngtcp2 call so a synchronously-closing callback can't free `conn`.
        let prevBusy = bridge.enterConnHeld()
        let rv = bridge.initiateImmediateMigration(conn, localAddr: newLocal, remoteAddr: remoteAddr,
                                                   addrLen: addrLen, ts: ts)
        bridge.exitConnHeld(prevBusy)
        guard rv == 0 else {
            logger.warning("[QUIC] Reactive migration rejected (ngtcp2 \(rv)); reconnecting")
            newCarrier.assumeIsolated { $0.close() }
            migrationFailures += 1
            close(error: QUICError.connectionFailed("migration rejected: \(rv)"))
            return
        }

        // Immediate migration switched the active path: one carrier now (no per-path
        // routing), so route all I/O to it, retire the old one, validate in background.
        migrationKind = .reactive
        let oldCarrier = carrier
        carrier = newCarrier
        localAddr = newLocal
        armActiveCarrier(newCarrier, localAddr: newLocal)
        oldCarrier?.assumeIsolated { $0.close() }
        logger.info("[QUIC] Reactive migration initiated; validating new path")
        writeToUDP()
        rescheduleTimer()
    }

    /// A better path appeared while the current one still works. Validate it on a parallel
    /// carrier and switch only once it passes, keeping the working path until then.
    /// Best-effort: any hitch leaves the current path untouched. Runs on `queue`.
    func attemptProactiveMigration() {
        guard migrationEnabled, state == .connected, migrationKind == nil,
              migrationFailures < Self.maxMigrationFailures,
              connectionOpaquePointer != nil,
              let oldType = carrier?.assumeIsolated({ $0.currentInterfaceType }) else { return }

        let target = QUICDatagramCarrier(bridge: bridge)
        var placeholder = sockaddr_storage()
        let remote = remoteAddr
        do {
            try target.assumeIsolated { try $0.connect(remoteAddr: remote, localAddr: &placeholder) }
        } catch {
            target.assumeIsolated { $0.close() }
            return
        }

        let newLocal = makeMigrationLocalAddr()
        migrationKind = .proactive
        migratingCarrier = target
        migratingLocalAddr = newLocal

        // Before validation, a target failure aborts cleanly; once validating, it's left
        // for path_validation to time out so the in-flight probe isn't misrouted.
        armReceive(target, localAddr: newLocal) { [weak self] _ in
            self?.assumeIsolated { $0.abortProactiveIfNotValidating() }
        }
        target.assumeIsolated { $0.onPathDown = { [weak self] in self?.assumeIsolated { $0.abortProactiveIfNotValidating() } } }

        // If the target never reaches `.ready`, give up rather than wedge `migrationKind`.
        // Fires on `queue` (hopped back onto the ngtcp2 home queue) to touch migration state.
        proactiveDeadlineTask?.cancel()
        proactiveDeadlineTask = Task { [weak self, weak target] in
            try? await Task.sleep(for: .seconds(Self.proactiveReadyTimeout))
            guard !Task.isCancelled, let self, let target else { return }
            self.bridge.enqueue {
                self.assumeIsolated { me in
                    guard me.migratingCarrier === target, !me.proactiveValidating else { return }
                    logger.warning("[QUIC] Proactive migration target not ready in \(Int(Self.proactiveReadyTimeout))s; staying put")
                    me.abortProactiveMigration(countAsFailure: false)
                }
            }
        }

        // Once the target is up and confirmed a *different* interface, start validation.
        // NWConnection buffers the probe until ready.
        target.assumeIsolated { $0.onReady = { [weak self, weak target] in
            guard let self else { return }
            self.assumeIsolated { me in
                guard let target, me.migratingCarrier === target,
                      let conn = me.connectionOpaquePointer,
                      let newType = target.assumeIsolated({ $0.currentInterfaceType }), newType != oldType else {
                    me.abortProactiveMigration(countAsFailure: false)
                    return
                }
                let ts = me.currentTimestamp()
                let prevBusy = me.bridge.enterConnHeld()
                let rv = me.bridge.initiateMigration(conn, localAddr: newLocal, remoteAddr: me.remoteAddr,
                                                     addrLen: me.addrLen, ts: ts)
                me.bridge.exitConnHeld(prevBusy)
                guard rv == 0 else {
                    logger.warning("[QUIC] Proactive migration rejected (ngtcp2 \(rv)); staying put")
                    me.abortProactiveMigration(countAsFailure: true)
                    return
                }
                // Committed: ngtcp2 owns the validation now. Cancel the readiness deadline;
                // path_validation success/failure drives the rest.
                me.proactiveValidating = true
                me.proactiveDeadlineTask?.cancel()
                me.proactiveDeadlineTask = nil
                logger.info("[QUIC] Proactive migration: validating better path")
                me.writeToUDP()
                me.rescheduleTimer()
            }
        } }
    }

    /// Drops a proactive-migration target and stays on the current path. `countAsFailure`
    /// is true only when migration genuinely failed (ngtcp2 rejected, or validation
    /// failed); benign aborts pass false. Runs on `queue`.
    func abortProactiveMigration(countAsFailure: Bool) {
        guard migrationKind == .proactive else { return }
        migratingCarrier?.assumeIsolated { $0.close() }
        clearMigrationState()
        if countAsFailure { migrationFailures += 1 }
    }

    /// Aborts a proactive migration only while still safe — before `initiate_migration`
    /// hands ngtcp2 an active validation. Used by the target's error hooks.
    func abortProactiveIfNotValidating() {
        guard migrationKind == .proactive, !proactiveValidating else { return }
        abortProactiveMigration(countAsFailure: false)
    }

    /// Clears migration tracking and the readiness deadline; leaves `migrationFailures`. Runs on `queue`.
    func clearMigrationState() {
        proactiveDeadlineTask?.cancel()
        proactiveDeadlineTask = nil
        proactiveValidating = false
        migratingCarrier = nil
        migrationKind = nil
    }

    /// ngtcp2 finished (or abandoned) validating a migration path. The bridge trampoline defers
    /// it off the ngtcp2 batch, so `close()` and re-entrant ngtcp2 calls are safe here.
    func handlePathValidation(result: NGTCP2PathValidationResult) {
        // ABORTED ≠ failure: ngtcp2 abandons a validation (superseded by a newer
        // migration, or its CID retired) — not a dead path. A reactive switch during
        // proactive validation aborts the proactive pv; that stale ABORTED must not undo
        // it. Retire the target only if a proactive migration is still live.
        if result == .aborted {
            if migrationKind == .proactive { abortProactiveMigration(countAsFailure: false) }
            return
        }
        guard let kind = migrationKind else { return }
        if result == .success {
            if kind == .proactive, let target = migratingCarrier {
                let old = carrier
                carrier = target
                localAddr = migratingLocalAddr
                migratingCarrier = nil       // cleared first so routing settles on `carrier`
                armActiveCarrier(target, localAddr: localAddr)
                old?.assumeIsolated { $0.close() }
            }
            clearMigrationState()
            migrationFailures = 0
            logger.info("[QUIC] Migration validated; new path active")
        } else {
            logger.warning("[QUIC] Migration path validation failed")
            if kind == .proactive {
                abortProactiveMigration(countAsFailure: true)
            } else {
                clearMigrationState()
                close(error: QUICError.connectionFailed("migration path validation failed"))
            }
        }
    }

    /// The carrier for a just-written packet, per the local address ngtcp2 reported. Two carriers
    /// exist only during a proactive migration; otherwise this is always `carrier`.
    func carrierForOutPath(local: sockaddr_storage) -> QUICDatagramCarrier? {
        if migratingCarrier != nil, sockaddrMatches(local, migratingLocalAddr, length: addrLen) {
            return migratingCarrier
        }
        return carrier
    }

    /// Byte-compares the first `length` octets of two `sockaddr_storage` values — enough to tell
    /// the active local addr from a migration target's distinct cosmetic one.
    func sockaddrMatches(_ lhs: sockaddr_storage, _ rhs: sockaddr_storage, length: Int) -> Bool {
        var lhs = lhs
        var rhs = rhs
        return withUnsafeBytes(of: &lhs) { lb in
            withUnsafeBytes(of: &rhs) { rb in
                let n = min(length, lb.count, rb.count)
                return memcmp(lb.baseAddress!, rb.baseAddress!, n) == 0
            }
        }
    }

    /// Sends `length` bytes from `txBuffer` to the given `carrier`. Drop-on-error; ngtcp2 retransmits.
    func sendTxBuf(length: Int, to carrier: QUICDatagramCarrier?) {
        guard length > 0 else { return }
        if let obfuscator {
            let datagrams = txBuffer.withUnsafeBytes { raw in
                obfuscator.seal(UnsafeRawBufferPointer(rebasing: raw[0..<length]))
            }
            for datagram in datagrams { sendDatagram(datagram, to: carrier) }
            return
        }
        // Copy out before the next ngtcp2 write reuses txBuffer.
        let datagram = txBuffer.withUnsafeBufferPointer { Data(bytes: $0.baseAddress!, count: length) }
        sendDatagram(datagram, to: carrier)
    }

    /// Routes one wire datagram to the chained transport or the given direct carrier.
    func sendDatagram(_ datagram: Data, to carrier: QUICDatagramCarrier?) {
        if let transport {
            transport.sendDatagram(datagram)
            return
        }
        guard let carrier else { return }
        carrier.assumeIsolated { $0.send(datagram) }
    }

}
