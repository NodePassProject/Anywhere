//
//  MITMProfileServer.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import Foundation
import Network
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "MITMProfileServer")

actor MITMProfileServer {
    static let shared = MITMProfileServer()

    private var payload: Data?
    private var runTask: Task<Void, Never>?
    private var shutdownTask: Task<Void, Never>?
    private var legacyListener: LegacyMITMProfileListener?

    private static let lifetime: TimeInterval = 120

    private init() {}

    func start(payload: Data) async throws -> URL {
        stop()

        self.payload = payload

        let boundPort: NWEndpoint.Port
        if #available(iOS 26.0, macOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *) {
            boundPort = try await startModern()
        } else {
            boundPort = try await startLegacy(payload: payload)
        }

        shutdownTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(Self.lifetime))
            guard !Task.isCancelled else { return }
            await self?.stop()
        }

        guard let url = URL(string: "http://127.0.0.1:\(boundPort.rawValue)/AnywhereMITMRoot.mobileconfig") else {
            stop()
            throw AnywhereError.mitm(.profileServerBindFailed)
        }
        return url
    }

    func stop() {
        runTask?.cancel()
        runTask = nil
        legacyListener?.cancel()
        legacyListener = nil
        shutdownTask?.cancel()
        shutdownTask = nil
        payload = nil
    }

    // MARK: - Modern listener

    @available(iOS 26.0, macOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *)
    private func startModern() async throws -> NWEndpoint.Port {
        let listener = try NetworkListener(for: nil, using: { TCP() })

        let (portStream, portSignal) = AsyncThrowingStream.makeStream(of: NWEndpoint.Port.self)
        let configured = listener.onStateUpdate { listener, state in
            switch state {
            case .ready:
                if let port = listener.port {
                    portSignal.yield(port)
                    portSignal.finish()
                } else {
                    portSignal.finish(throwing: AnywhereError.mitm(.profileServerBindFailed))
                }
            case .failed(let error):
                portSignal.finish(throwing: error)
            case .cancelled:
                portSignal.finish(throwing: AnywhereError.mitm(.profileServerBindFailed))
            default:
                break
            }
        }

        runTask = Task { [weak self] in
            try? await configured.run { [weak self] connection in
                await self?.handle(connection: connection)
            }
        }

        var boundPort: NWEndpoint.Port?
        do {
            for try await port in portStream { boundPort = port }
        } catch {
            stop()
            throw AnywhereError.mitm(.profileServerBindFailed)
        }
        guard let boundPort else {
            stop()
            throw AnywhereError.mitm(.profileServerBindFailed)
        }
        return boundPort
    }

    // MARK: - Legacy listener

    private func startLegacy(payload: Data) async throws -> NWEndpoint.Port {
        let listener: LegacyMITMProfileListener
        do {
            listener = try LegacyMITMProfileListener(payload: payload)
        } catch {
            stop()
            throw AnywhereError.mitm(.profileServerBindFailed)
        }
        legacyListener = listener
        do {
            return try await listener.start()
        } catch {
            stop()
            throw AnywhereError.mitm(.profileServerBindFailed)
        }
    }

    // MARK: - Connection handling

    @available(iOS 26.0, macOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *)
    private func handle(connection: NetworkConnection<TCP>) async {
        var buffer = Data()
        do {
            while true {
                let message = try await connection.receive(atLeast: 1, atMost: 8192)
                if !message.content.isEmpty { buffer.append(message.content) }
                if buffer.range(of: Data([0x0D, 0x0A, 0x0D, 0x0A])) != nil {
                    try await sendResponse(on: connection)
                    return
                }
                if message.metadata.endOfStream { return }
            }
        } catch {
            logger.error("profile server connection error: \(error)")
        }
    }

    @available(iOS 26.0, macOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *)
    private func sendResponse(on connection: NetworkConnection<TCP>) async throws {
        guard let payload else { return }
        try await connection.send(Self.httpResponse(payload: payload), endOfStream: true)
    }

    fileprivate static func httpResponse(payload: Data) -> Data {
        let header = "HTTP/1.1 200 OK\r\n" +
                     "Content-Type: application/x-apple-aspen-config\r\n" +
                     "Content-Disposition: attachment; filename=\"AnywhereMITMRoot.mobileconfig\"\r\n" +
                     "Content-Length: \(payload.count)\r\n" +
                     "Connection: close\r\n" +
                     "Cache-Control: no-store\r\n\r\n"
        var response = Data(header.utf8)
        response.append(payload)
        return response
    }

}

// MARK: - Legacy listener

nonisolated private final class LegacyMITMProfileListener: Sendable {
    private let listener: NWListener
    private let payload: Data
    private let queue = DispatchQueue(label: "com.argsment.Anywhere.MITMProfileServer")

    private struct State {
        var connections: [ObjectIdentifier: NWConnection] = [:]
        var cancelled = false
    }

    private let state = Mutex(State())

    init(payload: Data) throws {
        self.payload = payload
        self.listener = try NWListener(using: .tcp)
    }

    deinit {
        cancel()
    }
    
    func start() async throws -> NWEndpoint.Port {
        let (portStream, portSignal) = AsyncThrowingStream.makeStream(of: NWEndpoint.Port.self)
        listener.stateUpdateHandler = { [weak listener] state in
            switch state {
            case .ready:
                if let port = listener?.port {
                    portSignal.yield(port)
                    portSignal.finish()
                } else {
                    portSignal.finish(throwing: AnywhereError.mitm(.profileServerBindFailed))
                }
            case .failed(let error):
                portSignal.finish(throwing: error)
            case .cancelled:
                portSignal.finish(throwing: AnywhereError.mitm(.profileServerBindFailed))
            default:
                break
            }
        }
        listener.newConnectionHandler = { [weak self] connection in
            self?.adopt(connection)
        }
        listener.start(queue: queue)

        var boundPort: NWEndpoint.Port?
        for try await port in portStream { boundPort = port }
        guard let boundPort else { throw AnywhereError.mitm(.profileServerBindFailed) }
        return boundPort
    }

    func cancel() {
        let connections: [NWConnection] = state.withLock { state in
            state.cancelled = true
            let open = Array(state.connections.values)
            state.connections.removeAll()
            return open
        }
        listener.cancel()
        for connection in connections { connection.cancel() }
    }

    // MARK: Connections

    private func adopt(_ connection: NWConnection) {
        let accepted: Bool = state.withLock { state in
            guard !state.cancelled else { return false }
            state.connections[ObjectIdentifier(connection)] = connection
            return true
        }
        guard accepted else {
            connection.cancel()
            return
        }
        let id = ObjectIdentifier(connection)
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .failed, .cancelled:
                self?.forget(id)
            default:
                break
            }
        }
        connection.start(queue: queue)
        serve(connection, buffered: Data())
    }

    private func serve(_ connection: NWConnection, buffered: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] content, _, isComplete, error in
            guard let self else {
                connection.cancel()
                return
            }
            if let error {
                logger.error("profile server connection error: \(error)")
                connection.cancel()
                return
            }
            var buffer = buffered
            if let content { buffer.append(content) }
            if buffer.range(of: Data([0x0D, 0x0A, 0x0D, 0x0A])) != nil {
                self.respond(on: connection)
                return
            }
            if isComplete {
                connection.cancel()
                return
            }
            self.serve(connection, buffered: buffer)
        }
    }

    private func respond(on connection: NWConnection) {
        let response = MITMProfileServer.httpResponse(payload: payload)
        connection.send(content: response, contentContext: .finalMessage, completion: .contentProcessed { _ in
            connection.cancel()
        })
    }

    private func forget(_ id: ObjectIdentifier) {
        state.withLock { _ = $0.connections.removeValue(forKey: id) }
    }
}
