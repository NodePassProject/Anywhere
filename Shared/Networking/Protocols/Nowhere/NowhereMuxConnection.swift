//
//  NowhereMuxConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 8/24/26.
//

import Foundation
import Synchronization

/// Applies the ordinary Nowhere FlowRequest/FlowResult handshake inside one Mux stream.
nonisolated final class NowhereMuxFlowConnection: ProxyConnection, NowhereTerminationObservable {
    private enum Phase: PhaseTransitionable {
        case opening
        case ready
        case closed

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.opening, .ready):
                return true
            case (_, .closed):
                return old != .closed
            default:
                return false
            }
        }
    }

    private struct State: PhaseHolding {
        var phase: Phase = .opening
        var pending = Data()
        var terminalError: Error?
    }

    private let stream: NowhereMuxStream
    /// Non-nil only when this flow owns a non-pooled carrier supplied by a parent chain.
    private let ownedCarrier: NowhereMuxCarrier?
    private let state = Mutex(State())
    private let termination = TerminationLatch()

    init(stream: NowhereMuxStream, ownedCarrier: NowhereMuxCarrier? = nil) {
        self.stream = stream
        self.ownedCarrier = ownedCarrier
        stream.setNowhereTerminationHandler { [weak self] error in
            self?.handleTermination(error)
        }
    }

    var outerTLSVersion: TLSVersion? { stream.outerTLSVersion }

    var isConnected: Bool {
        state.withLock { $0.phase == .ready } && stream.isConnected
    }

    func setNowhereTerminationHandler(_ handler: (@Sendable (Error?) -> Void)?) {
        termination.install(handler)
    }

    func open(
        destination: NowhereProtocol.Target,
        flowHeader: NowhereProtocol.FlowHeader,
        initialData: Data?,
        attempt: NowhereFlowOpenAttempt?
    ) async throws {
        let request = try NowhereProtocol.encodeFlowRequest(
            header: flowHeader,
            target: flowHeader.carriesTarget ? destination : nil,
            initialData: flowHeader.role == .attach ? nil : initialData
        )
        if initialData?.isEmpty == false { attempt?.markEarlyDataWriteStarted() }

        do {
            try await stream.sendRaw(request)
            if flowHeader.role == .open {
                guard becomeReady(pending: Data()) else {
                    throw AnywhereError.proxy(.nowhere, .streamClosed)
                }
                return
            }

            var buffer = Data()
            while buffer.count < NowhereProtocol.flowResultSize {
                guard let chunk = try await stream.receiveRaw() else {
                    throw AnywhereError.proxy(
                        .nowhere,
                        .connectionClosed(detail: "Mux stream closed before complete READY")
                    )
                }
                buffer.append(chunk)
            }
            guard let result = NowhereProtocol.decodeFlowResult(buffer) else {
                throw AnywhereError.proxy(
                    .nowhere,
                    .connectionClosed(detail: "Invalid flow result")
                )
            }
            switch result {
            case .ready:
                let remainder = Data(buffer.dropFirst(NowhereProtocol.flowResultSize))
                guard becomeReady(pending: remainder) else {
                    throw AnywhereError.proxy(.nowhere, .streamClosed)
                }
            case .reject(let code):
                throw AnywhereError.proxy(.nowhere, .flowRejected(code: code.rawValue))
            }
        } catch {
            fail(error)
            throw error
        }
    }

    func sendRaw(_ data: Data) async throws {
        guard state.withLock({ $0.phase == .ready }) else {
            throw AnywhereError.proxy(.nowhere, .streamClosed)
        }
        do {
            try await stream.sendRaw(data)
        } catch {
            fail(error)
            throw error
        }
    }

    func receiveRaw() async throws -> Data? {
        let pending: Data? = state.withLock { state in
            guard state.phase == .ready, !state.pending.isEmpty else { return nil }
            let result = state.pending
            state.pending.removeAll(keepingCapacity: false)
            return result
        }
        if let pending { return pending }

        let terminalError: Error? = state.withLock { state in
            state.phase == .ready
                ? nil
                : state.terminalError ?? AnywhereError.proxy(.nowhere, .streamClosed)
        }
        if let terminalError { throw terminalError }

        do {
            let data = try await stream.receiveRaw()
            if data == nil { finishNormally() }
            return data
        } catch {
            fail(error)
            throw error
        }
    }

    func cancel() {
        guard closeState(error: nil) else { return }
        stream.setNowhereTerminationHandler(nil)
        closeStreamGracefully()
        termination.fire(nil)
    }

    func abort() {
        let error = AnywhereError.proxy(.nowhere, .streamClosed)
        guard closeState(error: error) else { return }
        stream.setNowhereTerminationHandler(nil)
        stream.abort()
        ownedCarrier?.abort()
        termination.fire(error)
    }

    private func becomeReady(pending: Data) -> Bool {
        state.withLock { state in
            guard state.phase == .opening else { return false }
            state.pending = pending
            return state.transition(to: .ready)
        }
    }

    private func finishNormally() {
        guard closeState(error: nil) else { return }
        stream.setNowhereTerminationHandler(nil)
        closeStreamGracefully()
        termination.fire(nil)
    }

    private func closeStreamGracefully() {
        guard let ownedCarrier else {
            stream.cancel()
            return
        }
        stream.closeGracefully {
            ownedCarrier.close()
        }
    }

    private func fail(_ error: Error) {
        guard closeState(error: error) else { return }
        stream.setNowhereTerminationHandler(nil)
        stream.abort()
        ownedCarrier?.abort()
        termination.fire(error)
    }

    private func handleTermination(_ error: Error?) {
        // A clean FIN may follow a final DATA frame already queued for the reader.
        // Notify paired UoT users immediately, but let ordinary readers drain it.
        guard let error else {
            termination.fire(nil)
            return
        }
        guard closeState(error: error) else { return }
        ownedCarrier?.abort()
        termination.fire(error)
    }

    private func closeState(error: Error?) -> Bool {
        state.withLock { state in
            guard state.transition(to: .closed) else { return false }
            state.terminalError = error
            state.pending.removeAll(keepingCapacity: false)
            return true
        }
    }
}
