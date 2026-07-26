//
//  ConnectionMetrics.swift
//  Anywhere
//
//  Created by NodePassProject on 6/7/26.
//

import Foundation
import Synchronization

nonisolated final class ConnectionMetrics: Sendable {
    static let shared = ConnectionMetrics()
    
    @TaskLocal static var currentAttempt: Attempt?
    
    // MARK: - Attempt
    
    final class Attempt: Sendable {
        private let metrics: ConnectionMetrics
        private let generation: UInt64
        private let startedAt: ContinuousClock.Instant
        private let dialRecorded = Atomic<Bool>(false)
        private let handshakeRecorded = Atomic<Bool>(false)
        
        fileprivate init(metrics: ConnectionMetrics, generation: UInt64) {
            self.metrics = metrics
            self.generation = generation
            self.startedAt = ContinuousClock().now
        }
        
        func noteServerResponse() {
            guard !dialRecorded.load(ordering: .relaxed) else { return }
            guard !dialRecorded.exchange(true, ordering: .relaxed) else { return }
            metrics.commit(.dial, elapsed, generation: generation)
        }
        
        func notePayload() {
            guard !handshakeRecorded.load(ordering: .relaxed) else { return }
            guard !handshakeRecorded.exchange(true, ordering: .relaxed) else { return }
            metrics.commit(.handshake, elapsed, generation: generation)
        }
        
        private var elapsed: Duration { ContinuousClock().now - startedAt }
    }
    
    private enum Milestone {
        case dial
        case handshake
    }
    
    // MARK: - State
    
    private struct State {
        var defaultServerID: UUID?
        var generation: UInt64 = 0
        var dialMs: Int?
        var handshakeMs: Int?
        var dialTotalMs = 0
        var dialSampleCount = 0
        var handshakeTotalMs = 0
        var handshakeSampleCount = 0
        var suspendDepth = 0
    }
    
    private let state = Mutex(State())
    
    struct Snapshot {
        let dialMs: Int?
        let handshakeMs: Int?
        let avgDialMs: Int?
        let avgHandshakeMs: Int?
    }
    
    // MARK: - Default server
    
    func setDefaultServer(_ id: UUID?) {
        state.withLock { state in
            guard state.defaultServerID != id else { return }
            state.defaultServerID = id
            Self.clear(&state)
        }
    }
    
    // MARK: - Attempts
    
    func beginAttempt() -> Attempt? {
        let generation: UInt64? = state.withLock { state in
            guard state.suspendDepth == 0, state.defaultServerID != nil else { return nil }
            return state.generation
        }
        return generation.map { Attempt(metrics: self, generation: $0) }
    }
    
    private func commit(_ milestone: Milestone, _ duration: Duration, generation: UInt64) {
        let ms = max(0, duration.milliseconds)
        state.withLock { state in
            guard state.generation == generation else { return }
            switch milestone {
            case .dial:
                state.dialMs = ms
                state.dialTotalMs += ms
                state.dialSampleCount += 1
            case .handshake:
                state.handshakeMs = ms
                state.handshakeTotalMs += ms
                state.handshakeSampleCount += 1
            }
        }
    }
    
    // MARK: - Suspension
    
    func suspendRecording() {
        state.withLock { $0.suspendDepth += 1 }
    }
    
    func resumeRecording() {
        state.withLock { state in
            if state.suspendDepth > 0 { state.suspendDepth -= 1 }
        }
    }
    
    // MARK: - Readout
    
    func snapshot() -> Snapshot {
        state.withLock { state in
            Snapshot(
                dialMs: state.dialMs,
                handshakeMs: state.handshakeMs,
                avgDialMs: state.dialSampleCount > 0 ? state.dialTotalMs / state.dialSampleCount : nil,
                avgHandshakeMs: state.handshakeSampleCount > 0 ? state.handshakeTotalMs / state.handshakeSampleCount : nil
            )
        }
    }
    
    func reset() {
        state.withLock { Self.clear(&$0) }
    }
    
    private static func clear(_ state: inout State) {
        state.generation &+= 1
        state.dialMs = nil
        state.handshakeMs = nil
        state.dialTotalMs = 0
        state.dialSampleCount = 0
        state.handshakeTotalMs = 0
        state.handshakeSampleCount = 0
    }
}

// MARK: - Metered connection

nonisolated final class MeteredProxyConnection: ProxyConnection {
    private let inner: ProxyConnection
    private let attempt: ConnectionMetrics.Attempt
    
    init(_ inner: ProxyConnection, attempt: ConnectionMetrics.Attempt) {
        self.inner = inner
        self.attempt = attempt
    }
    
    var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }
    var deliversDatagrams: Bool { inner.deliversDatagrams }
    var isConnected: Bool { inner.isConnected }
    
    func send(_ data: Data) async throws { try await inner.send(data) }
    func sendRaw(_ data: Data) async throws { try await inner.sendRaw(data) }
    func sendDirectRaw(_ data: Data) async throws { try await inner.sendDirectRaw(data) }
    
    func receive() async throws -> Data? { note(try await inner.receive()) }
    func receiveRaw() async throws -> Data? { note(try await inner.receiveRaw()) }
    func receiveDirectRaw() async throws -> Data? { note(try await inner.receiveDirectRaw()) }
    
    func cancel() { inner.cancel() }
    func abort() { inner.abort() }
    
    private func note(_ data: Data?) -> Data? {
        if let data, !data.isEmpty { attempt.notePayload() }
        return data
    }
}

private extension Duration {
    nonisolated var milliseconds: Int {
        let components = self.components
        return Int(components.seconds * 1_000 + components.attoseconds / 1_000_000_000_000_000)
    }
}
