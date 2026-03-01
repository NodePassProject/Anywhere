//
//  MuxClient.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "MuxClient")

class MuxClient {
    let configuration: VLESSConfiguration
    let lwipQueue: DispatchQueue

    private var vlessClient: VLESSClient?
    private var vlessConnection: VLESSConnection?
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

    // Receive loop + frame parser
    private var frameParser = MuxFrameParser()

    // 16s idle timer (matching Xray-core)
    private var idleTimer: DispatchSourceTimer?
    private static let idleTimeout: TimeInterval = 16

    private var isXUDP = false

    var sessionCount: Int { sessions.count }
    var isFull: Bool { closed || isXUDP }

    init(configuration: VLESSConfiguration, lwipQueue: DispatchQueue) {
        self.configuration = configuration
        self.lwipQueue = lwipQueue
    }

    // MARK: - Session Management

    /// Creates a new mux session for the given target.
    /// Lazily connects the underlying VLESS connection on first use.
    func createSession(
        network: MuxNetwork,
        host: String,
        port: UInt16,
        globalID: Data?,
        completion: @escaping (Result<MuxSession, Error>) -> Void
    ) {
        guard !closed else {
            completion(.failure(VLESSError.connectionFailed("Mux client closed")))
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
            client: self
        )
        sessions[sessionID] = session

        // Reset idle timer when a new session is added
        resetIdleTimer()

        let finishCreation = { [weak self] (error: Error?) in
            guard let self else { return }
            if let error {
                self.sessions.removeValue(forKey: sessionID)
                completion(.failure(error))
                return
            }

            // Send New frame with target address
            let metadata = MuxFrameMetadata(
                sessionID: sessionID,
                status: .new,
                option: [],
                network: network,
                targetHost: host,
                targetPort: port,
                globalID: globalID
            )

            let frame = encodeMuxFrame(metadata: metadata, payload: nil)
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

    /// Removes a session from the map (called by MuxSession on close).
    func removeSession(_ sessionID: UInt16) {
        sessions.removeValue(forKey: sessionID)
        if sessions.isEmpty {
            resetIdleTimer()
        }
    }

    /// Closes all sessions and the underlying VLESS connection.
    func closeAll() {
        guard !closed else { return }
        closed = true

        idleTimer?.cancel()
        idleTimer = nil

        let allSessions = sessions.values
        sessions.removeAll()

        for session in allSessions {
            session.deliverClose()
        }

        vlessConnection?.cancel()
        vlessClient?.cancel()
        vlessConnection = nil
        vlessClient = nil

        frameParser.reset()
        writeQueue.removeAll()

        let pendingCompletions = connectCompletions
        connectCompletions.removeAll()
        connecting = false
        for cb in pendingCompletions {
            cb(VLESSError.connectionFailed("Mux client closed"))
        }
    }

    // MARK: - VLESS Mux Connection

    private func connectMux(completion: @escaping (Error?) -> Void) {
        if connected {
            completion(nil)
            return
        }

        if closed {
            completion(VLESSError.connectionFailed("Mux client closed"))
            return
        }

        // If already connecting, queue this completion for when connection finishes
        if connecting {
            connectCompletions.append(completion)
            return
        }

        connecting = true
        connectCompletions.append(completion)

        let client = VLESSClient(configuration: configuration)
        self.vlessClient = client

        client.connectMux { [weak self] (result: Result<VLESSConnection, Error>) in
            guard let self else { return }

            self.lwipQueue.async { [weak self] in
                guard let self else { return }

                self.connecting = false
                let completions = self.connectCompletions
                self.connectCompletions.removeAll()

                switch result {
                case .success(let connection):
                    self.vlessConnection = connection
                    self.connected = true
                    self.startReceiveLoop(connection)
                    self.resetIdleTimer()
                    for cb in completions { cb(nil) }

                case .failure(let error):
                    logger.error("[Mux] Connection failed: \(error.localizedDescription, privacy: .public)")
                    self.closeAll()
                    for cb in completions { cb(error) }
                }
            }
        }
    }

    // MARK: - Write Serialization

    /// Enqueues a frame for serialized writing.
    func writeFrame(_ data: Data, completion: @escaping (Error?) -> Void) {
        lwipQueue.async { [weak self] in
            guard let self, !self.closed else {
                completion(VLESSError.connectionFailed("Mux client closed"))
                return
            }
            self.writeQueue.append((data, completion))
            self.drainWriteQueue()
        }
    }

    private func drainWriteQueue() {
        guard !isWriting, !writeQueue.isEmpty, let connection = vlessConnection else { return }

        isWriting = true
        let (data, completion) = writeQueue.removeFirst()

        connection.sendRaw(data: data) { [weak self] (error: Error?) in
            guard let self else { return }
            self.lwipQueue.async { [weak self] in
                guard let self else { return }
                self.isWriting = false
                completion(error)

                if let error {
                    logger.error("[Mux] Write error: \(error.localizedDescription, privacy: .public)")
                    self.closeAll()
                } else {
                    self.drainWriteQueue()
                }
            }
        }
    }

    // MARK: - Receive Loop

    private func startReceiveLoop(_ connection: VLESSConnection) {
        connection.startReceiving(handler: { [weak self] (data: Data) in
            guard let self else { return }
            self.lwipQueue.async { [weak self] in
                self?.handleReceivedData(data)
            }
        }, errorHandler: { [weak self] (error: Error?) in
            guard let self else { return }
            if let error {
                logger.error("[Mux] Receive error: \(error.localizedDescription, privacy: .public)")
            }
            self.lwipQueue.async { [weak self] in
                self?.closeAll()
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

        let timer = DispatchSource.makeTimerSource(queue: lwipQueue)
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

    deinit {
        idleTimer?.cancel()
        vlessConnection?.cancel()
        vlessClient?.cancel()
    }
}
