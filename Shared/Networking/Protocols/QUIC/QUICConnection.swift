//
//  QUICConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 4/11/26.
//

import Foundation
import Synchronization
import AnywhereQUIC

nonisolated final class QUICConnection: Sendable {
    enum StreamTerminationCause: Sendable { case closed, reset }
    struct Handlers: Sendable {
        var streamData: (@Sendable (Int64, Data, Bool) -> Void)?
        var streamTermination: (@Sendable (Int64, Error?, StreamTerminationCause) -> Void)?
        var datagram: (@Sendable (Data) -> Void)?
        var connectionClosed: (@Sendable (Error) -> Void)?
        var bidiCredit: (@Sendable (UInt64) -> Void)?
    }

    let handlers: QUICHandlerStore
    private let state: QUICState<QUICConnectionCore>
    private let host: String
    private let usesTransport: Bool
    static let maxUDPPayload = QUICConnectionCore.maxUDPPayload
    static let maxPendingDatagrams = QUICConnectionCore.maxPendingDatagrams

    init(
        host: String,
        port: UInt16,
        serverName: String? = nil,
        alpn: [String],
        datagramsEnabled: Bool = false,
        tuning: QUICTuning,
        obfuscator: QUICPacketObfuscator? = nil,
        directMaxUDPPayload: Int = QUICConnection.maxUDPPayload,
        transport: QUICDatagramTransport? = nil
    ) {
        self.host = host
        usesTransport = transport != nil
        let handlers = QUICHandlerStore()
        self.handlers = handlers
        let executor = BridgeExecutor(label: "com.argsment.Anywhere.QUICConnection")
        state = QUICState(
            QUICConnectionCore(
                host: host,
                port: port,
                serverName: serverName,
                alpn: alpn,
                datagramsEnabled: datagramsEnabled,
                tuning: tuning,
                obfuscator: obfuscator,
                directMaxUDPPayload: directMaxUDPPayload,
                transport: transport,
                handlers: handlers,
                executor: executor
            ),
            queue: executor.queue
        )
        state.update { $0.owner = self }
    }

    func update<T: Sendable>(_ body: (QUICConnectionCore) -> T) -> T { state.update(body) }

    func connect() async throws {
        let attempt = ConnectionMetrics.currentAttempt
        let resolved = usesTransport ? [] : await DNSResolver.shared.resolveAll(host)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            update { core in
                guard core.phase == .idle else {
                    continuation.resume(throwing: AnywhereError.quic(.connectionFailed(detail: "Invalid state")))
                    return
                }
                core.transition(to: .connecting)
                core.dialAttempt = attempt
                core.connectContinuation = continuation
                core.setupUDP(resolvedIPs: resolved)
            }
        }
    }

    func exportKeyingMaterial(label: String, context: Data, length: Int) async throws -> Data {
        try state.read { core in
            guard core.phase == .connected, let engine = core.engine else {
                throw AnywhereError.quic(.closed(graceful: false))
            }
            return try engine.exportKeyingMaterial(label: label, context: context, length: length)
        }
    }

    func close(error: Error? = nil) { update { $0.performTeardown(error: error) } }

    func openBidiStream() -> Int64? { update { $0.openStream(bidirectional: true) } }
    func openUniStream() -> Int64? { update { $0.openStream(bidirectional: false) } }
    var availableBidiStreams: UInt64 { state.read { $0.engine?.availableBidirectionalStreams ?? 0 } }
    var maxDatagramPayloadSize: Int { state.read { $0.engine?.maxDatagramPayloadSize ?? 0 } }
    func currentMaxDatagramPayloadSize() async -> Int { maxDatagramPayloadSize }

    func extendStreamOffset(_ streamID: Int64, count: Int) {
        guard count > 0 else { return }
        update { $0.extendStreamOffset(streamID, count: count) }
    }
    func shutdownStream(_ streamID: Int64, appErrorCode: UInt64) {
        update { core in
            guard let engine = core.engine, streamID >= 0 else { return }
            engine.shutdownStream(QUICStreamID(rawValue: UInt64(streamID)), errorCode: appErrorCode)
            core.failStreamSendQueue(streamId: streamID, error: AnywhereError.quic(.closed(graceful: false)))
            core.scheduleFlush()
        }
    }
    func writeStream(_ streamID: Int64, data: Data, fin: Bool = false) async throws {
        if let immediate = update({ $0.writeStreamImmediately(streamID, data: data, fin: fin) }) {
            return try immediate.get()
        }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            update { core in
                guard core.phase == .connected, core.engine != nil else {
                    continuation.resume(throwing: AnywhereError.quic(.closed(graceful: false)))
                    return
                }
                core.appendStreamWrite(streamID, data: data, fin: fin, continuation: continuation)
            }
        }
    }
    func submitStreamWrite(_ streamID: Int64, data: Data, fin: Bool = false) {
        update { core in
            guard core.phase == .connected, core.engine != nil else { return }
            core.appendStreamWrite(streamID, data: data, fin: fin, continuation: nil)
        }
    }
    func writeDatagrams(_ datagrams: [Data]) async throws {
        try await writeDatagrams(datagrams, atomically: false)
    }
    func writeDatagramsAtomically(_ datagrams: [Data]) async throws {
        try await writeDatagrams(datagrams, atomically: true)
    }
    private func writeDatagrams(_ datagrams: [Data], atomically: Bool) async throws {
        let immediate: Result<Void, Error>? = update { core in
            guard core.phase == .connected, core.engine != nil else {
                return .failure(AnywhereError.quic(.closed(graceful: false)))
            }
            if datagrams.isEmpty { return .success(()) }
            guard core.enqueueDatagramsInEngine(datagrams) else { return nil }
            core.scheduleFlush()
            return .success(())
        }
        if let immediate { return try immediate.get() }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            update { core in
                guard core.phase == .connected, core.engine != nil else {
                    continuation.resume(throwing: AnywhereError.quic(.closed(graceful: false)))
                    return
                }
                if datagrams.isEmpty { continuation.resume(); return }
                if core.enqueueDatagramsInEngine(datagrams) {
                    continuation.resume()
                    core.scheduleFlush()
                    return
                }
                if atomically, !Self.canEnqueueDatagramBatch(
                    pendingCount: core.pendingDatagrams.count + (core.engine?.pendingDatagramCount ?? 0),
                    batchCount: datagrams.count
                ) {
                    continuation.resume(throwing: AnywhereError.quic(.datagramQueueFull))
                    return
                }
                let latch = QUICConnectionCore.DatagramBatchLatch(count: datagrams.count, continuation: continuation)
                let pending = datagrams.map { QUICConnectionCore.PendingDatagram(data: $0, latch: latch) }
                if atomically { core.pendingDatagrams.append(contentsOf: pending) }
                else { core.enqueueDatagrams(pending) }
                core.scheduleFlush()
            }
        }
    }
    static func canEnqueueDatagramBatch(pendingCount: Int, batchCount: Int) -> Bool {
        guard pendingCount >= 0, batchCount >= 0, pendingCount <= maxPendingDatagrams else { return false }
        return batchCount <= maxPendingDatagrams - pendingCount
    }
    func setBrutalBandwidth(_ bytesPerSecond: UInt64) {
        _ = update { $0.engine?.setBrutalBandwidth(bytesPerSecond) }
    }
    func uninstallBrutalCC() {
        update { core in
            guard core.usesBrutalCC, let engine = core.engine else { return }
            core.usesBrutalCC = false
            engine.setCongestionController(QUICCubicCongestionController(), now: core.currentTimestamp())
            core.scheduleFlush()
        }
    }
}

nonisolated final class QUICHandlerStore: Sendable {
    private let storage = Mutex(QUICConnection.Handlers())
    func withLock<T: Sendable>(_ body: (inout QUICConnection.Handlers) -> T) -> T {
        storage.withLock { body(&$0) }
    }
}
