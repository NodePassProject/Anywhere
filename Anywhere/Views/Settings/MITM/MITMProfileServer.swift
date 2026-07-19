//
//  MITMProfileServer.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import Foundation
import Network

nonisolated private let logger = AnywhereLogger(category: "MITMProfileServer")

actor MITMProfileServer {
    static let shared = MITMProfileServer()

    private var payload: Data?
    private var runTask: Task<Void, Never>?
    private var shutdownTask: Task<Void, Never>?

    private static let lifetime: TimeInterval = 120

    private init() {}

    func start(payload: Data) async throws -> URL {
        stop()
        
        let listener = try NetworkListener(for: nil, using: { TCP() })
        self.payload = payload
        
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
        shutdownTask?.cancel()
        shutdownTask = nil
        payload = nil
    }

    // MARK: - Connection handling
    
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

    private func sendResponse(on connection: NetworkConnection<TCP>) async throws {
        guard let payload else { return }
        let header = "HTTP/1.1 200 OK\r\n" +
                     "Content-Type: application/x-apple-aspen-config\r\n" +
                     "Content-Disposition: attachment; filename=\"AnywhereMITMRoot.mobileconfig\"\r\n" +
                     "Content-Length: \(payload.count)\r\n" +
                     "Connection: close\r\n" +
                     "Cache-Control: no-store\r\n\r\n"
        var response = Data(header.utf8)
        response.append(payload)
        try await connection.send(response, endOfStream: true)
    }

}
