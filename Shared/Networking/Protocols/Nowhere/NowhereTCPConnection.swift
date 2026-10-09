//
//  NowhereTCPConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 8/24/26.
//

import Foundation
import Synchronization

actor NowhereTCPConnection: ProxyConnection, NowhereTerminationObservable {
    private enum Phase: PhaseTransitionable {
        case idle
        case opening
        case ready
        case closed

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.idle, .opening),
                 (.opening, .ready):
                return true
            case (_, .closed):
                return old != .closed
            default:
                return false
            }
        }
    }

    private struct Lifecycle: PhaseHolding {
        var phase: Phase = .idle
        var tlsClient: TLSClient?
        var transport: (any ByteTransport)?
        var tlsVersion: TLSVersion?
        var terminalError: Error?
        var monitorTask: Task<Void, Never>?
        var bootstrapTask: Task<TLSRecordConnection, Error>?
        var flowKind: NowhereProtocol.FlowKind?
        var flowRole: NowhereProtocol.FlowRole?
    }

    private let configuration: NowhereRuntimeConfiguration
    private let connectHost: String
    private let tunnel: ProxyConnection?

    private nonisolated let lifecycle = Mutex(Lifecycle())
    private nonisolated let termination = TerminationLatch()

    private var pendingData = Data()
    private var receiveInProgress = false

    init(
        configuration: NowhereRuntimeConfiguration,
        connectHost: String,
        tunnel: ProxyConnection?
    ) {
        self.configuration = configuration
        self.connectHost = connectHost
        self.tunnel = tunnel
    }

    deinit {
        cancel()
    }

    nonisolated var isConnected: Bool {
        lifecycle.withLock {
            $0.phase == .ready && $0.transport?.isReady == true
        }
    }

    nonisolated var outerTLSVersion: TLSVersion? {
        lifecycle.withLock { $0.tlsVersion }
    }

    nonisolated func setNowhereTerminationHandler(
        _ handler: (@Sendable (Error?) -> Void)?
    ) {
        guard termination.install(handler), handler != nil else { return }
        startUplinkMonitorIfNeeded()
    }

    func openFresh(
        destination: NowhereProtocol.Target,
        flowHeader: NowhereProtocol.FlowHeader,
        initialData: Data? = nil,
        attempt: NowhereFlowOpenAttempt? = nil
    ) async throws {
        let request = try NowhereProtocol.encodeFlowRequest(
            header: flowHeader,
            target: flowHeader.carriesTarget ? destination : nil,
            initialData: flowHeader.role == .attach ? nil : initialData
        )
        guard lifecycle.withLock({ $0.transition(to: .opening) }) else {
            throw AnywhereError.proxy(.nowhere, .notReady)
        }

        let client = TLSClient(configuration: configuration.tlsConfiguration)
        let adoptedClient = lifecycle.withLock { state -> Bool in
            guard state.phase == .opening else { return false }
            state.tlsClient = client
            state.flowKind = flowHeader.kind
            state.flowRole = flowHeader.role
            return true
        }
        guard adoptedClient else {
            client.cancel()
            throw terminalError()
        }

        do {
            let record: TLSRecordConnection
            if configuration.morph {
                let base: any ByteTransport
                let directTCP: TCPTransport?
                if let tunnel {
                    base = TunneledTransport(tunnel: tunnel)
                    directTCP = nil
                } else {
                    let tcp = TCPTransport(
                        host: connectHost,
                        port: try configuration.proxyPort(for: .tcp),
                        resolution: .proxies
                    )
                    base = tcp
                    directTCP = tcp
                }
                guard let keys = configuration.morphKeys else {
                    base.cancel()
                    throw AnywhereError.proxy(.nowhere, .protocolViolation(detail: "Missing Morph keys"))
                }
                let adoptedBase = lifecycle.withLock { state -> Bool in
                    guard state.phase == .opening else { return false }
                    state.transport = base
                    return true
                }
                guard adoptedBase else {
                    base.cancel()
                    throw terminalError()
                }
                let task = Task {
                    try Task.checkCancellation()
                    if let directTCP { try await directTCP.connect() }
                    return try await NowhereMorph.connectTLS(
                        client: client,
                        base: base,
                        keys: keys,
                        prelude: configuration.morphPrelude
                    )
                }
                let adoptedTask = lifecycle.withLock { state -> Bool in
                    guard state.phase == .opening else { return false }
                    state.bootstrapTask = task
                    return true
                }
                if !adoptedTask { task.cancel() }
                defer { lifecycle.withLock { $0.bootstrapTask = nil } }
                record = try await withTaskCancellationHandler {
                    let result = try await task.value
                    guard !Task.isCancelled, lifecycle.withLock({ $0.phase == .opening }) else {
                        result.cancel()
                        throw terminalError(fallback: CancellationError())
                    }
                    return result
                } onCancel: {
                    task.cancel()
                    base.cancel()
                    client.cancel()
                }
            } else if let tunnel {
                record = try await client.connect(overTunnel: tunnel)
            } else {
                record = try await client.connect(
                    host: connectHost,
                    port: try configuration.proxyPort(for: .tcp)
                )
            }

            guard record.negotiatedALPN == NowhereProtocol.applicationProtocol else {
                record.cancel()
                throw AnywhereError.tls(.handshakeFailed(
                    detail: "Portal did not negotiate the Nowhere application protocol"
                ))
            }
            let exporter = try record.exportKeyingMaterial(
                label: "EXPORTER-Nowhere-Auth",
                context: Data(),
                length: 32
            )
            let auth = try NowhereProtocol.makeAuthFrame(
                authKey: configuration.authKey,
                transport: .tlsTCP,
                exporter: exporter,
                sessionID: configuration.sessionID
            )

            let transport = TLSByteTransport(record)
            let adoptedTransport = lifecycle.withLock { state -> Bool in
                guard state.phase == .opening else { return false }
                state.tlsClient = nil
                state.transport = transport
                state.tlsVersion = TLSVersion(rawValue: record.tlsVersion)
                return true
            }
            guard adoptedTransport else {
                transport.cancel()
                throw terminalError()
            }

            var bootstrap = auth
            bootstrap.append(request)
            if initialData?.isEmpty == false { attempt?.markEarlyDataWriteStarted() }
            try await transport.send(bootstrap)

            if flowHeader.role != .open {
                pendingData = try await receiveFlowResult(from: transport)
            }

            guard lifecycle.withLock({ $0.transition(to: .ready) }) else {
                throw terminalError()
            }
            startUplinkMonitorIfNeeded()
        } catch {
            let resolved = terminalError(fallback: error)
            fail(resolved)
            throw resolved
        }
    }

    private func receiveFlowResult(
        from transport: any ByteTransport
    ) async throws -> Data {
        var buffer = Data()
        while buffer.count < NowhereProtocol.flowResultSize {
            switch try await transport.receive() {
            case .bytes(let data):
                buffer.append(data)
            case .end:
                throw AnywhereError.proxy(
                    .nowhere,
                    .connectionClosed(detail: "TLS carrier closed before complete READY")
                )
            }
        }

        guard let result = NowhereProtocol.decodeFlowResult(buffer) else {
            throw AnywhereError.proxy(
                .nowhere,
                .connectionClosed(detail: "Invalid flow result")
            )
        }
        switch result {
        case .ready:
            return Data(buffer.dropFirst(NowhereProtocol.flowResultSize))
        case .reject(let code):
            throw AnywhereError.proxy(.nowhere, .flowRejected(code: code.rawValue))
        }
    }

    func sendRaw(_ data: Data) async throws {
        let transport = try readyTransport()
        do {
            try await transport.send(data)
        } catch {
            let resolved = terminalError(fallback: error)
            fail(resolved)
            throw resolved
        }
    }

    func receiveRaw() async throws -> Data? {
        if !pendingData.isEmpty {
            let data = pendingData
            pendingData.removeAll(keepingCapacity: false)
            return data
        }
        guard !receiveInProgress else {
            throw AnywhereError.proxy(
                .nowhere,
                .protocolViolation(detail: "Overlapping receive on Nowhere TLS carrier")
            )
        }
        receiveInProgress = true
        defer { receiveInProgress = false }

        let transport = try readyTransport()
        do {
            switch try await transport.receive() {
            case .bytes(let data):
                return data
            case .end:
                finish(error: nil)
                return nil
            }
        } catch {
            let resolved = terminalError(fallback: error)
            fail(resolved)
            throw resolved
        }
    }

    private func readyTransport() throws -> any ByteTransport {
        try lifecycle.withLock { state in
            guard state.phase == .ready, let transport = state.transport else {
                throw state.terminalError ?? AnywhereError.proxy(.nowhere, .streamClosed)
            }
            return transport
        }
    }

    private nonisolated func startUplinkMonitorIfNeeded() {
        guard termination.hasHandler else { return }
        lifecycle.withLock { state in
            guard state.phase == .ready,
                  state.flowKind == .udp,
                  state.flowRole == .open,
                  state.monitorTask == nil,
                  let transport = state.transport else {
                return
            }
            state.monitorTask = Task { [weak self] in
                do {
                    switch try await transport.receive() {
                    case .bytes:
                        throw AnywhereError.proxy(
                            .nowhere,
                            .connectionClosed(detail: "Unexpected reverse UoT payload")
                        )
                    case .end:
                        self?.finish(error: nil)
                    }
                } catch is CancellationError {
                    guard let self, self.isConnected else { return }
                    self.fail(AnywhereError.proxy(.nowhere, .streamClosed))
                } catch {
                    guard let self else { return }
                    self.fail(self.terminalError(fallback: error))
                }
            }
        }
    }

    private nonisolated func terminalError(
        fallback: Error = AnywhereError.proxy(.nowhere, .streamClosed)
    ) -> Error {
        lifecycle.withLock { $0.terminalError ?? fallback }
    }

    private nonisolated func fail(_ error: Error) {
        finish(error: error)
    }

    private nonisolated func finish(error: Error?) {
        let resources: (TLSClient?, (any ByteTransport)?, Task<Void, Never>?, Task<TLSRecordConnection, Error>?)? = lifecycle.withLock { state in
            guard state.transition(to: .closed) else { return nil }
            state.terminalError = error
            let resources = (state.tlsClient, state.transport, state.monitorTask, state.bootstrapTask)
            state.tlsClient = nil
            state.transport = nil
            state.monitorTask = nil
            state.bootstrapTask = nil
            return resources
        }
        guard let resources else { return }
        resources.2?.cancel()
        resources.3?.cancel()
        resources.0?.cancel()
        resources.1?.cancel()
        tunnel?.cancel()
        termination.fire(error)
    }

    nonisolated func cancel() {
        finish(error: nil)
    }

    nonisolated func abort() {
        finish(error: AnywhereError.proxy(.nowhere, .streamClosed))
    }
}
