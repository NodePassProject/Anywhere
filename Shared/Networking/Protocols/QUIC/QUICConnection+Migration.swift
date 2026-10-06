//
//  QUICConnection+Migration.swift
//  Anywhere
//
//  Created by NodePassProject on 7/18/26.
//

import Foundation
import Synchronization
import Network
import AnywhereQUIC

nonisolated private let logger = AnywhereLogger(category: "QUICConnection")

extension QUICConnectionCore {

    enum PathValidationResult {
        case success, failure, aborted
    }

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
        case .proactiveProbing, .proactiveValidating:
            abortProactiveMigration(countAsFailure: false)
        case .none, .reactiveValidating:
            break
        }

        guard migrationEnabled, phase == .connected, case .none = migration,
              migrationFailures < Self.maxMigrationFailures,
              let engine else {
            close(error: AnywhereError.quic(.connectionFailed(detail: "network path lost")))
            return
        }

        let newCarrier = QUICDatagramCarrier(obfuscator: obfuscator)
        var placeholder = sockaddr_storage()
        let remote = remoteAddr
        do {
            try newCarrier.connect(remoteAddr: remote, localAddr: &placeholder)
        } catch {
            close(error: error)
            return
        }

        let newLocal = makeMigrationLocalAddr()
        do {
            try engine.migrate(to: quicPath(local: newLocal), immediately: true, now: currentTimestamp())
        } catch {
            logger.warning("[QUIC] Reactive migration rejected (\(error)); reconnecting")
            newCarrier.close()
            migrationFailures += 1
            close(error: AnywhereError.quic(.connectionFailed(detail: "migration rejected: \(error)")))
            return
        }

        setMigration(.reactiveValidating(localAddr: newLocal))
        let oldCarrier = carrier
        carrier = newCarrier
        localAddr = newLocal
        armActiveCarrier(newCarrier, localAddr: newLocal)
        oldCarrier?.close()
        logger.info("[QUIC] Reactive migration initiated; validating new path")
        writeToUDP()
        rescheduleTimer()
    }

    func attemptProactiveMigration() {
        guard migrationEnabled, phase == .connected, case .none = migration,
              migrationFailures < Self.maxMigrationFailures,
              engine != nil,
              let oldType = carrier?.currentInterfaceType else { return }

        let target = QUICDatagramCarrier(obfuscator: obfuscator)
        var placeholder = sockaddr_storage()
        let remote = remoteAddr
        do {
            try target.connect(remoteAddr: remote, localAddr: &placeholder)
        } catch {
            target.close()
            return
        }

        let newLocal = makeMigrationLocalAddr()
        setMigration(.proactiveProbing(target: target, localAddr: newLocal))

        armReceive(target, localAddr: newLocal) { [weak owner, weak target] _ in
            guard let target else { return }
            owner?.update { $0.abortProactiveIfNotValidating(target: target) }
        }
        target.onPathDown = { [weak owner, weak target] in
            guard let target else { return }
            owner?.update { $0.abortProactiveIfNotValidating(target: target) }
        }
        scheduleProactiveDeadline(target: target, validating: false)
        target.onReady = { [weak owner, weak target] in
            guard let target else { return }
            owner?.update { $0.beginProactiveValidation(target: target, oldType: oldType) }
        }
    }

    private func scheduleProactiveDeadline(target: QUICDatagramCarrier, validating: Bool) {
        proactiveDeadlineTask?.cancel()
        proactiveDeadlineTask = Task { [weak owner, weak target] in
            do { try await Task.sleep(for: .seconds(Self.proactiveReadyTimeout)) }
            catch { return }
            guard !Task.isCancelled, let target else { return }
            owner?.update { core in
                switch core.migration {
                case .proactiveProbing(let current, _) where !validating && current === target:
                    logger.warning("[QUIC] Proactive migration target not ready; staying put")
                    core.abortProactiveMigration(countAsFailure: false)
                case .proactiveValidating(let current, _) where validating && current === target:
                    logger.warning("[QUIC] Proactive migration path validation timed out; staying put")
                    core.abortProactiveMigration(countAsFailure: true)
                default: break
                }
            }
        }
    }

    private func beginProactiveValidation(target: QUICDatagramCarrier, oldType: NWInterface.InterfaceType) {
        guard case .proactiveProbing(let current, let migratingLocal) = migration, current === target else { return }
        guard let engine, let newType = target.currentInterfaceType, newType != oldType else {
            abortProactiveIfNotValidating()
            return
        }
        do {
            try engine.migrate(to: quicPath(local: migratingLocal), immediately: false, now: currentTimestamp())
        } catch {
            logger.warning("[QUIC] Proactive migration rejected (\(error)); staying put")
            abortProactiveMigration(countAsFailure: true)
            return
        }
        setMigration(.proactiveValidating(target: target, localAddr: migratingLocal))
        scheduleProactiveDeadline(target: target, validating: true)
        logger.info("[QUIC] Proactive migration: validating better path")
        writeToUDP()
        rescheduleTimer()
    }

    func abortProactiveMigration(countAsFailure: Bool) {
        if case .proactiveValidating = migration {
            engine?.cancelPendingMigration(now: currentTimestamp())
        }
        switch migration {
        case .proactiveProbing(let target, _), .proactiveValidating(let target, _):
            target.close()
            setMigration(.none)
            if countAsFailure { migrationFailures += 1 }
        case .none, .reactiveValidating:
            break
        }
    }

    func abortProactiveIfNotValidating(target: QUICDatagramCarrier? = nil) {
        guard case .proactiveProbing(let current, _) = migration, target == nil || current === target else { return }
        abortProactiveMigration(countAsFailure: false)
    }

    func handlePathValidation(result: PathValidationResult, pathLocal: QUICSocketAddress) {
        switch migration {
        case .none:
            return
        case .proactiveProbing:
            return
        case .proactiveValidating(let target, let migratingLocal):
            guard pathBelongsToMigration(pathLocal, expected: migratingLocal) else { return }
            switch result {
            case .success:
                if !target.isUsable {
                    logger.warning("[QUIC] Migration target died during validation; adopting committed path, expecting path-down")
                }
                let old = carrier
                carrier = target
                localAddr = migratingLocal
                armActiveCarrier(target, localAddr: migratingLocal)
                old?.close()
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

    private func pathBelongsToMigration(_ pathLocal: QUICSocketAddress, expected: sockaddr_storage) -> Bool {
        pathLocal == QUICSocketAddress(expected, length: addrLen)
    }

    func carrierForOutPath(local: QUICSocketAddress) -> QUICDatagramCarrier? {
        switch migration {
        case .proactiveProbing(let target, let migratingLocal),
             .proactiveValidating(let target, let migratingLocal):
            if local == QUICSocketAddress(migratingLocal, length: addrLen) { return target }
            return carrier
        case .none, .reactiveValidating:
            return carrier
        }
    }

    func sendDatagrams(_ datagrams: [Data], to carrier: QUICDatagramCarrier?) {
        if let transport {
            if let transportSealContinuation {
                for datagram in datagrams { transportSealContinuation.yield(datagram) }
            } else {
                publish { for datagram in datagrams { transport.sendDatagram(datagram) } }
            }
            return
        }
        guard let carrier else { return }
        carrier.send(datagrams)
    }
}
