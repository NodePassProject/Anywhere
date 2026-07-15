//
//  VLESSVisionUDPMultiplexer.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "VLESSVisionUDPMultiplexer")

nonisolated class VLESSVisionUDPMultiplexer: Multiplexer {

    // MARK: - Properties

    let configuration: ProxyConfiguration
    let flowQueue: DispatchQueue

    /// Marks flowQueue so callers can detect they're already on it.
    private static let queueKey = DispatchSpecificKey<Bool>()

    private var proxyClient: ProxyClient?
    private var proxyConnection: ProxyConnection?
    private var streams: [UInt16: VLESSVisionUDPStream] = [:]
    private var nextSessionID: UInt16 = 1
    private var connecting = false
    private var connected = false
    private(set) var closed = false

    /// Pending connect completions (queued while connecting).
    private var connectCompletions: [(Error?) -> Void] = []

    /// Write serialization (frames must not interleave).
    private var writeQueue: [(Data, (Error?) -> Void)] = []
    private var isWriting = false
    /// The single in-flight write's completion, carried on `flowQueue` so the async send
    /// `Task` need not capture the (non-Sendable) completion closure.
    private var inFlightWriteCompletion: ((Error?) -> Void)?

    private var frameParser = VLESSVisionUDPFrameParser()

    private var idleTimer: DispatchSourceTimer?
    private static let idleTimeout: TimeInterval = 16

    private var isXUDP = false

    /// Called once when the mux becomes permanently unusable (idle timeout, transport failure,
    /// or explicit close) so the pool can evict it. Fired on `flowQueue`.
    var onClose: (() -> Void)?

    // MARK: - Init

    init(configuration: ProxyConfiguration, flowQueue: DispatchQueue) {
        self.configuration = configuration
        self.flowQueue = flowQueue
        flowQueue.setSpecific(key: Self.queueKey, value: true)
    }

    // MARK: - Capacity

    var activeStreamCount: Int { streams.count }
    var isClosed: Bool { closed }
    var isFull: Bool { closed || isXUDP }

    // MARK: - Lifecycle

    private func ensureReady(completion: @escaping (Error?) -> Void) {
        if connected {
            completion(nil)
            return
        }

        if closed {
            completion(ProxyError.connectionFailed("Mux client closed"))
            return
        }

        if connecting {
            connectCompletions.append(completion)
            return
        }

        connecting = true
        connectCompletions.append(completion)

        let client = ProxyClient(configuration: configuration, isDefaultProxy: true)
        self.proxyClient = client

        Task { [weak self] in
            let result: Result<ProxyConnection, Error>
            do {
                result = .success(try await client.connectMultiplexer())
            } catch {
                result = .failure(error)
            }
            guard let self else { return }

            self.flowQueue.async { [weak self] in
                guard let self else { return }

                self.connecting = false
                let completions = self.connectCompletions
                self.connectCompletions.removeAll()

                switch result {
                case .success(let connection):
                    self.proxyConnection = connection
                    self.connected = true
                    self.startReadLoop(connection)
                    self.resetIdleTimer()
                    for callback in completions { callback(nil) }

                case .failure(let error):
                    self.close(error: error)
                    for callback in completions { callback(error) }
                }
            }
        }
    }

    private func resetIdleTimer() {
        idleTimer?.cancel()
        idleTimer = nil

        guard !closed, streams.isEmpty else { return }

        let timer = DispatchSource.makeTimerSource(queue: flowQueue)
        timer.schedule(deadline: .now() + Self.idleTimeout)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            if self.streams.isEmpty {
                self.close()
            }
        }
        timer.resume()
        idleTimer = timer
    }

    // MARK: - Streams

    /// Lazily connects the underlying proxy connection on first use.
    func openStream(
        network: VLESSVisionUDPNetwork,
        host: String,
        port: UInt16,
        globalID: Data?,
        completion: @escaping (Result<VLESSVisionUDPStream, Error>) -> Void
    ) {
        guard !closed else {
            completion(.failure(ProxyError.connectionFailed("Mux client closed")))
            return
        }

        let sessionID: UInt16
        if globalID != nil {
            // VLESSVisionUDPGlobalID: one flow per mux connection, always stream ID 0
            sessionID = 0
            isXUDP = true
        } else {
            sessionID = nextSessionID
            nextSessionID &+= 1
            // Skip 0 (reserved)
            if nextSessionID == 0 { nextSessionID = 1 }
        }

        let stream = VLESSVisionUDPStream(
            sessionID: sessionID,
            network: network,
            targetHost: host,
            targetPort: port,
            globalID: globalID,
            multiplexer: self
        )
        streams[sessionID] = stream

        resetIdleTimer()

        let finishCreation = { [weak self] (error: Error?) in
            guard let self else { return }
            if let error {
                self.streams.removeValue(forKey: sessionID)
                completion(.failure(error))
                return
            }

            // For VLESSVisionUDPGlobalID, the first UDP payload must be sent on the New frame so the
            // server parses GlobalID from a data-bearing packet.
            if globalID != nil {
                completion(.success(stream))
                return
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
            self.writeFrame(frame) { [weak self] writeError in
                if let writeError {
                    self?.streams.removeValue(forKey: sessionID)
                    completion(.failure(writeError))
                } else {
                    completion(.success(stream))
                }
            }
        }

        if connected {
            finishCreation(nil)
        } else {
            ensureReady { error in
                finishCreation(error)
            }
        }
    }

    /// Safe to call from any thread — dispatches to flowQueue if needed.
    func removeStream(_ sessionID: UInt16) {
        if DispatchQueue.getSpecific(key: Self.queueKey) != nil {
            streams.removeValue(forKey: sessionID)
            if streams.isEmpty {
                resetIdleTimer()
            }
        } else {
            flowQueue.async { [weak self] in
                guard let self else { return }
                self.streams.removeValue(forKey: sessionID)
                if self.streams.isEmpty {
                    self.resetIdleTimer()
                }
            }
        }
    }

    // MARK: - Send

    func writeFrame(_ data: Data, completion: @escaping (Error?) -> Void) {
        flowQueue.async { [weak self] in
            guard let self, !self.closed else {
                completion(ProxyError.connectionFailed("Mux client closed"))
                return
            }
            self.writeQueue.append((data, completion))
            self.drainWriteQueue()
        }
    }

    private func drainWriteQueue() {
        guard !isWriting, !writeQueue.isEmpty, let connection = proxyConnection else { return }

        isWriting = true
        let (data, completion) = writeQueue.removeFirst()
        inFlightWriteCompletion = completion

        Task { [weak self] in
            var sendError: Error?
            do {
                try await connection.sendRaw(data)
            } catch {
                sendError = error
            }
            self?.flowQueue.async { [weak self] in
                guard let self else { return }
                self.isWriting = false
                let completion = self.inFlightWriteCompletion
                self.inFlightWriteCompletion = nil
                completion?(sendError)

                if let sendError {
                    self.close(error: sendError)
                } else {
                    self.drainWriteQueue()
                }
            }
        }
    }

    // MARK: - Read Loop

    private func startReadLoop(_ connection: ProxyConnection) {
        Task { [weak self] in
            do {
                while true {
                    guard let data = try await connection.receive(), !data.isEmpty else {
                        self?.flowQueue.async { [weak self] in
                            guard let self, !self.closed else { return }
                            self.close(error: nil)   // clean EOF
                        }
                        return
                    }
                    self?.flowQueue.async { [weak self] in
                        self?.handleInbound(data)
                    }
                }
            } catch {
                self?.flowQueue.async { [weak self] in
                    guard let self, !self.closed else { return }
                    self.close(error: error)
                }
            }
        }
    }

    // MARK: - Demux

    private func handleInbound(_ data: Data) {
        let frames = frameParser.feed(data)

        for (metadata, payload) in frames {
            switch metadata.status {
            case .new:
                // Server-initiated streams — not expected for outbound mux, ignore
                break

            case .keep:
                if let stream = streams[metadata.sessionID], let payload, !payload.isEmpty {
                    stream.deliverData(payload)
                }

            case .end:
                if let stream = streams[metadata.sessionID] {
                    streams.removeValue(forKey: metadata.sessionID)
                    stream.deliverClose()
                }

            case .keepAlive:
                // Ping from server — no action needed
                break
            }
        }
    }

    // MARK: - Close

    /// `error` is non-nil when the mux connection died with a transport failure;
    /// pass `nil` for normal teardown (idle close, deliberate cancel).
    func close(error: Error? = nil) {
        guard !closed else { return }
        closed = true

        // Captured before teardown; fired last so the pool evicts exactly once (the
        // `closed` guard above makes close() idempotent).
        let notifyClose = onClose
        onClose = nil

        idleTimer?.cancel()
        idleTimer = nil

        let allStreams = streams.values
        streams.removeAll()

        for stream in allStreams {
            stream.deliverClose(error: error)
        }

        proxyConnection?.cancel()
        proxyClient?.cancel()
        proxyConnection = nil
        proxyClient = nil

        frameParser.reset()

        // Fail every pending write so its async caller unblocks (rather than leaking a
        // suspended continuation): the in-flight send plus anything still queued.
        let closeError = error ?? ProxyError.connectionFailed("Mux client closed")
        let pendingWrites = writeQueue
        writeQueue.removeAll()
        let inFlight = inFlightWriteCompletion
        inFlightWriteCompletion = nil
        isWriting = false
        inFlight?(closeError)
        for (_, completion) in pendingWrites {
            completion(closeError)
        }

        let pendingCompletions = connectCompletions
        connectCompletions.removeAll()
        connecting = false
        for callback in pendingCompletions {
            callback(ProxyError.connectionFailed("Mux client closed"))
        }

        notifyClose?()
    }
}
