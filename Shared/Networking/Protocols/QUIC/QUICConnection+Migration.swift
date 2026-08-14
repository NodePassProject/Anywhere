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

    var migrationEnabled: Bool {
        transport == nil && !tuning.disableActiveMigration
    }

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

    func setMigration(_ new: Migration) {
        guard Migration.canTransition(from: migration, to: new) else {
            logger.error("[QUIC] Invalid migration transition \(migration.label) → \(new.label); ignored")
            return
        }
        if case .proactiveProbing = new {} else {
            proactiveDeadlineTask?.cancel()
            proactiveDeadlineTask = nil
        }
        migration = new
    }

    func attemptReactiveMigration() {
        switch migration {
        case .proactiveProbing(let target, _), .proactiveValidating(let target, _):
            target.assumeIsolated { $0.close() }
            setMigration(.none)
        case .none, .reactiveValidating:
            break
        }

        guard migrationEnabled, phase == .connected, case .none = migration,
              migrationFailures < Self.maxMigrationFailures,
              let conn = connectionOpaquePointer else {
            close(error: AnywhereError.quic(.connectionFailed(detail: "network path lost")))
            return
        }

        let newCarrier = QUICDatagramCarrier(bridge: bridge, obfuscator: obfuscator)
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
        let prevBusy = enterConnHeld()
        let rv = initiateImmediateMigration(conn, localAddr: newLocal, remoteAddr: remoteAddr,
                                            addrLen: addrLen, ts: ts)
        exitConnHeld(prevBusy)
        guard rv == 0 else {
            logger.warning("[QUIC] Reactive migration rejected (ngtcp2 \(rv)); reconnecting")
            newCarrier.assumeIsolated { $0.close() }
            migrationFailures += 1
            close(error: AnywhereError.quic(.connectionFailed(detail: "migration rejected: \(rv)")))
            return
        }

        setMigration(.reactiveValidating(localAddr: newLocal))
        let oldCarrier = carrier
        carrier = newCarrier
        localAddr = newLocal
        armActiveCarrier(newCarrier, localAddr: newLocal)
        oldCarrier?.assumeIsolated { $0.close() }
        logger.info("[QUIC] Reactive migration initiated; validating new path")
        writeToUDP()
        rescheduleTimer()
    }

    func attemptProactiveMigration() {
        guard migrationEnabled, phase == .connected, case .none = migration,
              migrationFailures < Self.maxMigrationFailures,
              connectionOpaquePointer != nil,
              let oldType = carrier?.assumeIsolated({ $0.currentInterfaceType }) else { return }

        let target = QUICDatagramCarrier(bridge: bridge, obfuscator: obfuscator)
        var placeholder = sockaddr_storage()
        let remote = remoteAddr
        do {
            try target.assumeIsolated { try $0.connect(remoteAddr: remote, localAddr: &placeholder) }
        } catch {
            target.assumeIsolated { $0.close() }
            return
        }

        let newLocal = makeMigrationLocalAddr()
        setMigration(.proactiveProbing(target: target, localAddr: newLocal))

        armReceive(target, localAddr: newLocal) { [weak self] _ in
            self?.assumeIsolated { $0.abortProactiveIfNotValidating() }
        }
        target.assumeIsolated {
            $0.onPathDown = { [weak self] in
                self?.assumeIsolated { $0.abortProactiveIfNotValidating() }
            }
        }

        proactiveDeadlineTask = Task { [weak self, weak target] in
            try? await Task.sleep(for: .seconds(Self.proactiveReadyTimeout))
            guard !Task.isCancelled, let self, let target else { return }
            self.bridge.enqueue {
                self.assumeIsolated { me in
                    guard case .proactiveProbing(let current, _) = me.migration, current === target else { return }
                    logger.warning("[QUIC] Proactive migration target not ready in \(Int(Self.proactiveReadyTimeout))s; staying put")
                    me.abortProactiveMigration(countAsFailure: false)
                }
            }
        }

        target.assumeIsolated { $0.onReady = { [weak self, weak target] in
            guard let self else { return }
            self.assumeIsolated { me in
                guard let target,
                      case .proactiveProbing(let current, let migratingLocal) = me.migration, current === target,
                      let conn = me.connectionOpaquePointer,
                      let newType = target.assumeIsolated({ $0.currentInterfaceType }), newType != oldType else {
                    me.abortProactiveIfNotValidating()
                    return
                }
                let ts = me.currentTimestamp()
                let prevBusy = me.enterConnHeld()
                let rv = me.initiateMigration(conn, localAddr: migratingLocal, remoteAddr: me.remoteAddr,
                                              addrLen: me.addrLen, ts: ts)
                me.exitConnHeld(prevBusy)
                guard rv == 0 else {
                    logger.warning("[QUIC] Proactive migration rejected (ngtcp2 \(rv)); staying put")
                    me.abortProactiveMigration(countAsFailure: true)
                    return
                }
                me.setMigration(.proactiveValidating(target: target, localAddr: migratingLocal))
                me.proactiveDeadlineTask = Task { [weak self, weak target] in
                    try? await Task.sleep(for: .seconds(Self.proactiveReadyTimeout))
                    guard !Task.isCancelled, let self, let target else { return }
                    self.bridge.enqueue {
                        self.assumeIsolated { me in
                            guard case .proactiveValidating(let current, _) = me.migration, current === target else { return }
                            logger.warning("[QUIC] Proactive migration path validation timed out; staying put")
                            me.abortProactiveMigration(countAsFailure: true)
                        }
                    }
                }
                logger.info("[QUIC] Proactive migration: validating better path")
                me.writeToUDP()
                me.rescheduleTimer()
            }
        } }
    }

    func abortProactiveMigration(countAsFailure: Bool) {
        switch migration {
        case .proactiveProbing(let target, _), .proactiveValidating(let target, _):
            target.assumeIsolated { $0.close() }
            setMigration(.none)
            if countAsFailure { migrationFailures += 1 }
        case .none, .reactiveValidating:
            break
        }
    }

    func abortProactiveIfNotValidating() {
        guard case .proactiveProbing = migration else { return }
        abortProactiveMigration(countAsFailure: false)
    }

    func handlePathValidation(result: NGTCP2PathValidationResult, pathLocal: sockaddr_storage?) {
        switch migration {
        case .none:
            return
        case .proactiveProbing:
            return
        case .proactiveValidating(let target, let migratingLocal):
            guard pathBelongsToMigration(pathLocal, expected: migratingLocal) else { return }
            switch result {
            case .success:
                if !target.assumeIsolated({ $0.isUsable }) {
                    logger.warning("[QUIC] Migration target died during validation; adopting committed path, expecting path-down")
                }
                let old = carrier
                carrier = target
                localAddr = migratingLocal
                armActiveCarrier(target, localAddr: migratingLocal)
                old?.assumeIsolated { $0.close() }
                setMigration(.none)
                migrationFailures = 0
                logger.info("[QUIC] Migration validated; new path active")
            case .failure:
                logger.warning("[QUIC] Migration path validation failed")
                abortProactiveMigration(countAsFailure: true)
            case .aborted:
                abortProactiveMigration(countAsFailure: false)
            }
        case .reactiveValidating(let migratingLocal):
            guard pathBelongsToMigration(pathLocal, expected: migratingLocal) else { return }
            switch result {
            case .success:
                setMigration(.none)
                migrationFailures = 0
                logger.info("[QUIC] Migration validated; new path active")
            case .failure:
                logger.warning("[QUIC] Migration path validation failed")
                setMigration(.none)
                close(error: AnywhereError.quic(.connectionFailed(detail: "migration path validation failed")))
            case .aborted:
                logger.warning("[QUIC] Reactive migration validation aborted; releasing migration state")
                setMigration(.none)
            }
        }
    }

    private func pathBelongsToMigration(_ pathLocal: sockaddr_storage?, expected: sockaddr_storage) -> Bool {
        guard let pathLocal else { return true }
        return sockaddrMatches(pathLocal, expected, length: addrLen)
    }

    func carrierForOutPath(local: sockaddr_storage) -> QUICDatagramCarrier? {
        switch migration {
        case .proactiveProbing(let target, let migratingLocal),
             .proactiveValidating(let target, let migratingLocal):
            if sockaddrMatches(local, migratingLocal, length: addrLen) { return target }
            return carrier
        case .none, .reactiveValidating:
            return carrier
        }
    }

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

    func sendTxBuf(length: Int, to carrier: QUICDatagramCarrier?) {
        guard length > 0 else { return }
        let datagram = txBuffer.withUnsafeBufferPointer { Data(bytes: $0.baseAddress!, count: length) }
        sendDatagram(datagram, to: carrier)
    }

    func sendDatagram(_ datagram: Data, to carrier: QUICDatagramCarrier?) {
        if let transport {
            if let transportSealContinuation {
                transportSealContinuation.yield(datagram)
            } else {
                transport.sendDatagram(datagram)
            }
            return
        }
        guard let carrier else { return }
        carrier.assumeIsolated { $0.send(datagram) }
    }
}
