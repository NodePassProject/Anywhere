//
//  VLESSVisionUDPMultiplexer.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "VLESSVisionUDPMultiplexer")

nonisolated final class VLESSVisionUDPMultiplexer: Multiplexer {

    // MARK: - Properties

    let configuration: ProxyConfiguration

    /// Fields guarded by `lock`.
    private struct State {
        var proxyClient: ProxyClient?
        var proxyConnection: ProxyConnection?
        var streams: [UInt16: VLESSVisionUDPStream] = [:]
        var nextSessionID: UInt16 = 1
        var connecting = false
        var connected = false
        var closed = false
        var isXUDP = false

        /// Coalesced connect waiters (parked while dialing); resumed on connect / failed on close.
        var connectContinuations: [CheckedContinuation<Void, Error>] = []

        var frameParser = VLESSVisionUDPFrameParser()

        /// Idle-close timer as a cancellable `Task` (re-armed whenever the stream set empties).
        var idleTask: Task<Void, Never>?

        /// Tail of the wire-send chain: each frame links after the previous and runs only once it
        /// finishes, so frames never interleave on the shared connection — no lock held across the write.
        var sendTail: Task<Void, Error>?
    }

    private let lock = Mutex(State())

    private static let idleTimeout: TimeInterval = 16

    /// Called once when the mux becomes permanently unusable (idle timeout, transport failure,
    /// or explicit close) so the pool can evict it. Set once by the pool right after creation.
    var onClose: (() -> Void)?

    // MARK: - Init

    init(configuration: ProxyConfiguration) {
        self.configuration = configuration
    }

    // MARK: - Capacity

    var activeStreamCount: Int { lock.withLock { $0.streams.count } }
    var isClosed: Bool { lock.withLock { $0.closed } }
    var isFull: Bool { lock.withLock { $0.closed || $0.isXUDP } }

    // MARK: - Lifecycle

    /// Parks the caller until the underlying proxy connection is ready, lazily dialing on
    /// first use. Multiple callers coalesce onto one dial.
    private func ensureReady() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            // Decide + park under one lock section so a concurrent `finishConnect` can't
            // resume the waiter set before this continuation is enqueued.
            var clientToStart: ProxyClient?
            let immediate: Result<Void, Error>? = lock.withLock { state in
                if state.connected { return .success(()) }
                if state.closed { return .failure(ProxyError.connectionFailed("Mux client closed")) }
                if !state.connecting {
                    state.connecting = true
                    let client = ProxyClient(configuration: configuration, isDefaultProxy: true)
                    state.proxyClient = client
                    clientToStart = client
                }
                state.connectContinuations.append(continuation)
                return nil
            }
            switch immediate {
            case .success:
                continuation.resume()
            case .failure(let error):
                continuation.resume(throwing: error)
            case nil:
                if let clientToStart { startConnect(client: clientToStart) }
            }
        }
    }

    private func startConnect(client: ProxyClient) {
        Task { [weak self] in
            let result: Result<ProxyConnection, Error>
            do {
                result = .success(try await client.connectMultiplexer())
            } catch {
                result = .failure(error)
            }
            self?.finishConnect(result)
        }
    }

    private func finishConnect(_ result: Result<ProxyConnection, Error>) {
        switch result {
        case .success(let connection):
            let waiters: [CheckedContinuation<Void, Error>]? = lock.withLock { state in
                guard !state.closed else { return nil }
                state.connecting = false
                state.connected = true
                state.proxyConnection = connection
                let waiters = state.connectContinuations
                state.connectContinuations.removeAll()
                return waiters
            }
            guard let waiters else {
                // Closed mid-dial: `close()` already failed the waiters; just drop the connection.
                connection.cancel()
                return
            }
            startReadLoop(connection)
            resetIdleTimer()
            for continuation in waiters { continuation.resume() }

        case .failure(let error):
            let waiters: [CheckedContinuation<Void, Error>] = lock.withLock { state in
                state.connecting = false
                let waiters = state.connectContinuations
                state.connectContinuations.removeAll()
                return waiters
            }
            for continuation in waiters { continuation.resume(throwing: error) }
            close(error: error)
        }
    }

    private func resetIdleTimer() {
        lock.withLock { state in
            state.idleTask?.cancel()
            state.idleTask = nil
            guard !state.closed, state.streams.isEmpty else { return }
            state.idleTask = Task { [weak self] in
                try? await Task.sleep(nanoseconds: UInt64(Self.idleTimeout * 1_000_000_000))
                guard !Task.isCancelled else { return }
                self?.idleTimerFired()
            }
        }
    }

    private func idleTimerFired() {
        let shouldClose = lock.withLock { state in !state.closed && state.streams.isEmpty }
        if shouldClose { close(error: nil) }
    }

    // MARK: - Streams

    /// Lazily connects the underlying proxy connection on first use, then opens a stream.
    func openStream(
        network: VLESSVisionUDPNetwork,
        host: String,
        port: UInt16,
        globalID: Data?
    ) async throws -> VLESSVisionUDPStream {
        let stream: VLESSVisionUDPStream
        let sessionID: UInt16
        let isXUDP: Bool
        (stream, sessionID, isXUDP) = try lock.withLock { state in
            guard !state.closed else {
                throw ProxyError.connectionFailed("Mux client closed")
            }
            let sessionID: UInt16
            let xudp: Bool
            if globalID != nil {
                // VLESSVisionUDPGlobalID: one flow per mux connection, always stream ID 0
                sessionID = 0
                state.isXUDP = true
                xudp = true
            } else {
                sessionID = state.nextSessionID
                state.nextSessionID &+= 1
                // Skip 0 (reserved)
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
            return (stream, sessionID, xudp)
        }

        resetIdleTimer()

        do {
            try await ensureReady()
        } catch {
            removeStreamEntry(sessionID)
            throw error
        }

        // For VLESSVisionUDPGlobalID, the first UDP payload must be sent on the New frame so the
        // server parses GlobalID from a data-bearing packet.
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

    /// Drops a stream after a failed open — cleanup only, no idle re-arm.
    private func removeStreamEntry(_ sessionID: UInt16) {
        lock.withLock { _ = $0.streams.removeValue(forKey: sessionID) }
    }

    /// Removes a stream that closed itself; re-arms the idle timer if the mux went idle.
    func removeStream(_ sessionID: UInt16) {
        let becameIdle: Bool = lock.withLock { state in
            state.streams.removeValue(forKey: sessionID)
            return state.streams.isEmpty
        }
        if becameIdle { resetIdleTimer() }
    }

    // MARK: - Send

    /// Links a framed write onto the send chain; a failed write tears the mux down.
    func writeFrame(_ data: Data) async throws {
        let task: Task<Void, Error> = try lock.withLock { state in
            guard !state.closed, let connection = state.proxyConnection else {
                throw ProxyError.connectionFailed("Mux client closed")
            }
            let previous = state.sendTail
            let task = Task<Void, Error> {
                _ = try? await previous?.value
                try await connection.sendRaw(data)
            }
            state.sendTail = task
            return task
        }
        do {
            try await task.value
        } catch {
            close(error: error)
            throw error
        }
    }

    // MARK: - Read Loop

    private func startReadLoop(_ connection: ProxyConnection) {
        Task { [weak self] in
            do {
                while true {
                    guard let data = try await connection.receive(), !data.isEmpty else {
                        self?.handleReadEnd(error: nil)   // clean EOF
                        return
                    }
                    self?.handleInbound(data)
                }
            } catch {
                self?.handleReadEnd(error: error)
            }
        }
    }

    private func handleReadEnd(error: Error?) {
        guard !isClosed else { return }
        close(error: error)
    }

    // MARK: - Demux

    private func handleInbound(_ data: Data) {
        enum Deliver { case data(Data); case close }
        // Parse + resolve stream targets under the lock; deliver outside it so the
        // per-stream channel writes never run while `lock` is held.
        let actions: [(stream: VLESSVisionUDPStream, deliver: Deliver)] = lock.withLock { state in
            let frames = state.frameParser.feed(data)
            var out: [(VLESSVisionUDPStream, Deliver)] = []
            for (metadata, payload) in frames {
                switch metadata.status {
                case .new:
                    // Server-initiated streams — not expected for outbound mux, ignore
                    break

                case .keep:
                    if let stream = state.streams[metadata.sessionID], let payload, !payload.isEmpty {
                        out.append((stream, .data(payload)))
                    }

                case .end:
                    if let stream = state.streams[metadata.sessionID] {
                        state.streams.removeValue(forKey: metadata.sessionID)
                        out.append((stream, .close))
                    }

                case .keepAlive:
                    // Ping from server — no action needed
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

    /// `error` is non-nil when the mux connection died with a transport failure;
    /// pass `nil` for normal teardown (idle close, deliberate cancel). Idempotent.
    func close(error: Error? = nil) {
        struct Teardown {
            var streams: [VLESSVisionUDPStream]
            var connection: ProxyConnection?
            var client: ProxyClient?
            var idleTask: Task<Void, Never>?
            var connectContinuations: [CheckedContinuation<Void, Error>]
        }

        let teardown: Teardown? = lock.withLock { state in
            guard !state.closed else { return nil }
            state.closed = true

            let snapshot = Teardown(
                streams: Array(state.streams.values),
                connection: state.proxyConnection,
                client: state.proxyClient,
                idleTask: state.idleTask,
                connectContinuations: state.connectContinuations
            )
            state.streams.removeAll()
            state.proxyConnection = nil
            state.proxyClient = nil
            state.idleTask = nil
            state.connectContinuations.removeAll()
            state.connecting = false
            state.frameParser.reset()
            return snapshot
        }
        guard let teardown else { return }

        // Captured before teardown; fired last so the pool evicts exactly once (the
        // `closed` guard above makes close() idempotent). Set once by the pool at creation.
        let notifyClose = onClose
        onClose = nil

        teardown.idleTask?.cancel()

        for stream in teardown.streams {
            stream.deliverClose(error: error)
        }

        teardown.connection?.cancel()
        teardown.client?.cancel()

        // Fail every parked connect waiter so its async caller unblocks rather than leaking a
        // suspended continuation. In-flight/queued sends fail fast on their own because the
        // connection above is now cancelled.
        let closeError = error ?? ProxyError.connectionFailed("Mux client closed")
        for continuation in teardown.connectContinuations {
            continuation.resume(throwing: closeError)
        }

        notifyClose?()
    }
}
