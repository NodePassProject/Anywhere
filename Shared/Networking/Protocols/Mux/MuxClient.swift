//
//  MuxClient.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

private let logger = AnywhereLogger(category: "MuxClient")

nonisolated class MuxClient {
    let configuration: ProxyConfiguration
    let flowQueue: DispatchQueue

    /// Marks flowQueue so callers can detect they're already on it.
    private static let queueKey = DispatchSpecificKey<Bool>()

    private var proxyClient: ProxyClient?
    private var proxyConnection: ProxyConnection?
    private var sessions: [UInt16: MuxSession] = [:]
    private var nextSessionID: UInt16 = 1
    private var connecting = false
    private var connected = false
    private(set) var closed = false

    // Pending connect completions (queued while connecting)
    private var connectCompletions: [(Error?) -> Void] = []

    // Write serialization (frames must not interleave)
    private var writeQueue: [(Data, (Error?) -> Void)] = []
    private var isWriting = false

    private var frameParser = MuxFrameParser()

    // 16s idle timer
    private var idleTimer: DispatchSourceTimer?
    private static let idleTimeout: TimeInterval = 16

    private var isXUDP = false

    var sessionCount: Int { sessions.count }
    var isFull: Bool { closed || isXUDP }

    init(configuration: ProxyConfiguration, flowQueue: DispatchQueue) {
        self.configuration = configuration
        self.flowQueue = flowQueue
        flowQueue.setSpecific(key: Self.queueKey, value: true)
    }

    // MARK: - Session Management

    /// Lazily connects the underlying proxy connection on first use.
    func createSession(
        network: MuxNetwork,
        host: String,
        port: UInt16,
        globalID: Data?,
        completion: @escaping (Result<MuxSession, Error>) -> Void
    ) {
        guard !closed else {
            completion(.failure(ProxyError.connectionFailed("Mux client closed")))
            return
        }

        let sessionID: UInt16
        if globalID != nil {
            // XUDP: one flow per mux connection, always session ID 0
            sessionID = 0
            isXUDP = true
        } else {
            sessionID = nextSessionID
            nextSessionID &+= 1
            // Skip 0 (reserved)
            if nextSessionID == 0 { nextSessionID = 1 }
        }

        let session = MuxSession(
            sessionID: sessionID,
            network: network,
            targetHost: host,
            targetPort: port,
            globalID: globalID,
            client: self
        )
        sessions[sessionID] = session

        resetIdleTimer()

        let finishCreation = { [weak self] (error: Error?) in
            guard let self else { return }
            if let error {
                self.sessions.removeValue(forKey: sessionID)
                completion(.failure(error))
                return
            }

            // For XUDP, the first UDP payload must be sent on the New frame so the
            // server parses GlobalID from a data-bearing packet.
            if globalID != nil {
                completion(.success(session))
                return
            }

            let metadata = MuxFrameMetadata(
                sessionID: sessionID,
                status: .new,
                option: [],
                network: network,
                targetHost: host,
                targetPort: port,
                globalID: globalID
            )

            let frame = MuxFrame.encode(metadata: metadata, payload: nil)
            self.writeFrame(frame) { [weak self] writeError in
                if let writeError {
                    self?.sessions.removeValue(forKey: sessionID)
                    completion(.failure(writeError))
                } else {
                    completion(.success(session))
                }
            }
        }

        if connected {
            finishCreation(nil)
        } else {
            connectMux { error in
                finishCreation(error)
            }
        }
    }

    /// Safe to call from any thread — dispatches to flowQueue if needed.
    func removeSession(_ sessionID: UInt16) {
        if DispatchQueue.getSpecific(key: Self.queueKey) != nil {
            sessions.removeValue(forKey: sessionID)
            if sessions.isEmpty {
                resetIdleTimer()
            }
        } else {
            flowQueue.async { [weak self] in
                guard let self else { return }
                self.sessions.removeValue(forKey: sessionID)
                if self.sessions.isEmpty {
                    self.resetIdleTimer()
                }
            }
        }
    }

    /// `error` is non-nil when the mux connection died with a transport failure;
    /// pass `nil` for normal teardown (idle close, deliberate cancel).
    func closeAll(error: Error? = nil) {
        guard !closed else { return }
        closed = true

        idleTimer?.cancel()
        idleTimer = nil

        let allSessions = sessions.values
        sessions.removeAll()

        for session in allSessions {
            session.deliverClose(error: error)
        }

        proxyConnection?.cancel()
        proxyClient?.cancel()
        proxyConnection = nil
        proxyClient = nil

        frameParser.reset()
        writeQueue.removeAll()

        let pendingCompletions = connectCompletions
        connectCompletions.removeAll()
        connecting = false
        for cb in pendingCompletions {
            cb(ProxyError.connectionFailed("Mux client closed"))
        }
    }

    // MARK: - Mux Connection

    private func connectMux(completion: @escaping (Error?) -> Void) {
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

        client.connectMux { [weak self] (result: Result<ProxyConnection, Error>) in
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
                    self.startReceiveLoop(connection)
                    self.resetIdleTimer()
                    for cb in completions { cb(nil) }

                case .failure(let error):
                    self.closeAll(error: error)
                    for cb in completions { cb(error) }
                }
            }
        }
    }

    // MARK: - Write Serialization

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

        connection.sendRaw(data: data) { [weak self] (error: Error?) in
            guard let self else { return }
            self.flowQueue.async { [weak self] in
                guard let self else { return }
                self.isWriting = false
                completion(error)

                if let error {
                    self.closeAll(error: error)
                } else {
                    self.drainWriteQueue()
                }
            }
        }
    }

    // MARK: - Receive Loop

    private func startReceiveLoop(_ connection: ProxyConnection) {
        connection.startReceiving(handler: { [weak self] (data: Data) in
            guard let self else { return }
            self.flowQueue.async { [weak self] in
                self?.handleReceivedData(data)
            }
        }, errorHandler: { [weak self] (error: Error?) in
            guard let self, !self.closed else { return }
            self.flowQueue.async { [weak self] in
                self?.closeAll(error: error)
            }
        })
    }

    private func handleReceivedData(_ data: Data) {
        let frames = frameParser.feed(data)

        for (metadata, payload) in frames {
            switch metadata.status {
            case .new:
                // Server-initiated sessions — not expected for outbound mux, ignore
                break

            case .keep:
                if let session = sessions[metadata.sessionID], let payload, !payload.isEmpty {
                    session.deliverData(payload)
                }

            case .end:
                if let session = sessions[metadata.sessionID] {
                    sessions.removeValue(forKey: metadata.sessionID)
                    session.deliverClose()
                }

            case .keepAlive:
                // Ping from server — no action needed
                break
            }
        }
    }

    // MARK: - Idle Timer

    private func resetIdleTimer() {
        idleTimer?.cancel()
        idleTimer = nil

        guard !closed, sessions.isEmpty else { return }

        let timer = DispatchSource.makeTimerSource(queue: flowQueue)
        timer.schedule(deadline: .now() + Self.idleTimeout)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            if self.sessions.isEmpty {
                self.closeAll()
            }
        }
        timer.resume()
        idleTimer = timer
    }
}
