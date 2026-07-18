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
    
    func attemptReactiveMigration() {
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
    
    func attemptProactiveMigration() {
        guard migrationEnabled, state == .connected, migrationKind == nil,
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
        migrationKind = .proactive
        migratingCarrier = target
        migratingLocalAddr = newLocal
        
        armReceive(target, localAddr: newLocal) { [weak self] _ in
            self?.assumeIsolated { $0.abortProactiveIfNotValidating() }
        }
        target.assumeIsolated {
            $0.onPathDown = { [weak self] in
                self?.assumeIsolated { $0.abortProactiveIfNotValidating() }
            }
        }
        
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
                me.proactiveValidating = true
                me.proactiveDeadlineTask?.cancel()
                me.proactiveDeadlineTask = nil
                logger.info("[QUIC] Proactive migration: validating better path")
                me.writeToUDP()
                me.rescheduleTimer()
            }
        } }
    }
    
    func abortProactiveMigration(countAsFailure: Bool) {
        guard migrationKind == .proactive else { return }
        migratingCarrier?.assumeIsolated { $0.close() }
        clearMigrationState()
        if countAsFailure { migrationFailures += 1 }
    }
    
    func abortProactiveIfNotValidating() {
        guard migrationKind == .proactive, !proactiveValidating else { return }
        abortProactiveMigration(countAsFailure: false)
    }
    
    func clearMigrationState() {
        proactiveDeadlineTask?.cancel()
        proactiveDeadlineTask = nil
        proactiveValidating = false
        migratingCarrier = nil
        migrationKind = nil
    }
    
    func handlePathValidation(result: NGTCP2PathValidationResult) {
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
                migratingCarrier = nil
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
    
    func carrierForOutPath(local: sockaddr_storage) -> QUICDatagramCarrier? {
        if migratingCarrier != nil, sockaddrMatches(local, migratingLocalAddr, length: addrLen) {
            return migratingCarrier
        }
        return carrier
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
