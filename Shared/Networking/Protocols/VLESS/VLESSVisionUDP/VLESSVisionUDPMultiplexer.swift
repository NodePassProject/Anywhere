//
//  VLESSVisionUDPMultiplexer.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "VLESSVisionUDPMultiplexer")

nonisolated final class VLESSVisionUDPMultiplexer: Multiplexer, Sendable {

    // MARK: - Properties

    let configuration: ProxyConfiguration

    private enum Phase: PhaseTransitionable {
        case idle
        case connecting
        case ready
        case closed

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.idle, .connecting), (.connecting, .ready):
                return true
            case (_, .closed):
                return old != .closed
            default:
                return false
            }
        }
    }

    private struct State: PhaseHolding {
        var phase: Phase = .idle
        var proxyClient: ProxyClient?
        var proxyConnection: ProxyConnection?
        var streams: [UInt16: VLESSVisionUDPStream] = [:]
        var nextSessionID: UInt16 = 1
        var isXUDP = false
        var readyTask: Task<Void, Error>?
        var frameParser = VLESSVisionUDPFrameParser()
        var idleSince: ContinuousClock.Instant?
        var runTask: Task<Void, Never>?
    }

    private let state = Mutex(State())

    private let sendChain = SerialSender()

    private static let idleTimeout: TimeInterval = 16

    private let onClose: (@Sendable (VLESSVisionUDPMultiplexer) -> Void)?

    // MARK: - Init

    init(configuration: ProxyConfiguration,
         onClose: (@Sendable (VLESSVisionUDPMultiplexer) -> Void)? = nil) {
        self.configuration = configuration
        self.onClose = onClose
    }

    // MARK: - Capacity

    var activeStreamCount: Int { state.withLock { $0.streams.count } }
    var isClosed: Bool { state.withLock { $0.phase == .closed } }
    var isFull: Bool { state.withLock { $0.phase == .closed || $0.isXUDP } }

    // MARK: - Lifecycle

    private func ensureReady() async throws {
        let task: Task<Void, Error> = try state.withLock { state in
            if state.phase == .closed { throw AnywhereError.proxy(.vless, .connectionClosed(detail: "Mux client closed")) }
            if let existing = state.readyTask { return existing }
            let task = Task<Void, Error> { [weak self] in
                guard let self else { throw AnywhereError.proxy(.vless, .connectionClosed(detail: "Mux client released")) }
                try await self.performConnect()
            }
            state.readyTask = task
            state.transition(to: .connecting)
            return task
        }
        try await task.value
    }

    private func performConnect() async throws {
        let client = ProxyClient(configuration: configuration, isDefaultProxy: true)
        let live = state.withLock { state -> Bool in
            guard state.phase != .closed else { return false }
            state.proxyClient = client
            return true
        }
        guard live else { throw AnywhereError.proxy(.vless, .connectionClosed(detail: "Mux client closed")) }

        let connection: ProxyConnection
        do {
            connection = try await client.connectMultiplexer()
        } catch {
            close(error: error)
            throw error
        }

        let published = state.withLock { state -> Bool in
            guard state.phase != .closed else { return false }
            state.proxyConnection = connection
            state.transition(to: .ready)
            markIdlenessLocked(&state)
            return true
        }
        guard published else {
            connection.cancel()
            throw AnywhereError.proxy(.vless, .connectionClosed(detail: "Mux client closed"))
        }
        startSession(connection)
    }

    private func startSession(_ connection: ProxyConnection) {
        let task = Task {
            await withTaskGroup(of: Void.self) { group in
                group.addTask { await self.runReadLoop(connection) }
                group.addTask { await self.runIdleSweep() }
            }
        }
        state.withLock { state in
            if state.phase == .closed {
                task.cancel()
            } else {
                state.runTask = task
            }
        }
    }

    private func markIdlenessLocked(_ state: inout State) {
        state.idleSince = state.streams.isEmpty ? ContinuousClock.now : nil
    }

    private func runIdleSweep() async {
        while !Task.isCancelled {
            enum Step { case expired; case sleep(Duration) }
            let step: Step? = state.withLock { state in
                guard state.phase != .closed else { return nil }
                guard let since = state.idleSince else { return .sleep(.seconds(Self.idleTimeout)) }
                let elapsed = since.duration(to: ContinuousClock.now)
                if elapsed >= .seconds(Self.idleTimeout) { return .expired }
                return .sleep(.seconds(Self.idleTimeout) - elapsed)
            }
            switch step {
            case nil:
                return
            case .expired:
                close(error: nil)
                return
            case .sleep(let duration):
                try? await Task.sleep(for: duration)
            }
        }
    }

    // MARK: - Streams

    func openStream(
        network: VLESSVisionUDPNetwork,
        host: String,
        port: UInt16,
        globalID: Data?
    ) async throws -> VLESSVisionUDPStream {
        let stream: VLESSVisionUDPStream
        let sessionID: UInt16
        let isXUDP: Bool
        (stream, sessionID, isXUDP) = try state.withLock { state in
            guard state.phase != .closed else {
                throw AnywhereError.proxy(.vless, .connectionClosed(detail: "Mux client closed"))
            }
            let sessionID: UInt16
            let xudp: Bool
            if globalID != nil {
                sessionID = 0
                state.isXUDP = true
                xudp = true
            } else {
                sessionID = state.nextSessionID
                state.nextSessionID &+= 1
                if state.nextSessionID == 0 { state.nextSessionID = 1 }
                xudp = false
            }
            let stream = VLESSVisionUDPStream(
                sessionID: sessionID,
                network: network,
                targetHost: host,
                targetPort: port,
                globalID: globalID,
                multiplexer: self
            )
            state.streams[sessionID] = stream
            markIdlenessLocked(&state)
            return (stream, sessionID, xudp)
        }

        do {
            try await ensureReady()
        } catch {
            removeStreamEntry(sessionID)
            throw error
        }

        if isXUDP {
            return stream
        }

        let metadata = VLESSVisionUDPFrameMetadata(
            sessionID: sessionID,
            status: .new,
            option: [],
            network: network,
            targetHost: host,
            targetPort: port,
            globalID: globalID
        )
        let frame = VLESSVisionUDPFrame.encode(metadata: metadata, payload: nil)
        do {
            try await writeFrame(frame)
        } catch {
            removeStreamEntry(sessionID)
            throw error
        }
        return stream
    }

    private func removeStreamEntry(_ sessionID: UInt16) {
        state.withLock { state in
            state.streams.removeValue(forKey: sessionID)
            markIdlenessLocked(&state)
        }
    }

    func removeStream(_ sessionID: UInt16) {
        state.withLock { state in
            state.streams.removeValue(forKey: sessionID)
            markIdlenessLocked(&state)
        }
    }

    // MARK: - Send

    func writeFrame(_ data: Data) async throws {
        let pending: SerialSender.Pending = try state.withLock { state in
            guard state.phase != .closed, let connection = state.proxyConnection else {
                throw AnywhereError.proxy(.vless, .connectionClosed(detail: "Mux client closed"))
            }
            return sendChain.submit { try await connection.sendRaw(data) }
        }
        do {
            try await pending.value()
        } catch {
            close(error: error)
            throw error
        }
    }

    // MARK: - Read Loop

    private func runReadLoop(_ connection: ProxyConnection) async {
        do {
            while true {
                guard let data = try await connection.receive(), !data.isEmpty else {
                    handleReadEnd(error: nil)   // clean EOF
                    return
                }
                handleInbound(data)
            }
        } catch {
            handleReadEnd(error: error)
        }
    }

    private func handleReadEnd(error: Error?) {
        guard !isClosed else { return }
        close(error: error)
    }

    // MARK: - Demux

    private func handleInbound(_ data: Data) {
        enum Deliver { case data(Data); case close }
        let actions: [(stream: VLESSVisionUDPStream, deliver: Deliver)] = state.withLock { state in
            let frames = state.frameParser.feed(data)
            var out: [(VLESSVisionUDPStream, Deliver)] = []
            for (metadata, payload) in frames {
                switch metadata.status {
                case .new:
                    break

                case .keep:
                    if let stream = state.streams[metadata.sessionID], let payload, !payload.isEmpty {
                        out.append((stream, .data(payload)))
                    }

                case .end:
                    if let stream = state.streams[metadata.sessionID] {
                        state.streams.removeValue(forKey: metadata.sessionID)
                        markIdlenessLocked(&state)
                        out.append((stream, .close))
                    }

                case .keepAlive:
                    break
                }
            }
            return out
        }

        for (stream, deliver) in actions {
            switch deliver {
            case .data(let payload): stream.deliverData(payload)
            case .close:            stream.deliverClose(error: nil)
            }
        }
    }

    // MARK: - Close

    func close(error: Error? = nil) {
        struct Teardown {
            var streams: [VLESSVisionUDPStream]
            var connection: ProxyConnection?
            var client: ProxyClient?
            var readyTask: Task<Void, Error>?
            var runTask: Task<Void, Never>?
        }

        let teardown: Teardown? = state.withLock { state in
            guard state.transition(to: .closed) else { return nil }

            let snapshot = Teardown(
                streams: Array(state.streams.values),
                connection: state.proxyConnection,
                client: state.proxyClient,
                readyTask: state.readyTask,
                runTask: state.runTask
            )
            state.streams.removeAll()
            state.proxyConnection = nil
            state.proxyClient = nil
            state.readyTask = nil
            state.runTask = nil
            state.frameParser.reset()
            return snapshot
        }
        guard let teardown else { return }

        teardown.runTask?.cancel()

        for stream in teardown.streams {
            stream.deliverClose(error: error)
        }

        sendChain.cancel()
        teardown.connection?.cancel()
        teardown.client?.cancel()
        teardown.readyTask?.cancel()
        onClose?(self)
    }
}
