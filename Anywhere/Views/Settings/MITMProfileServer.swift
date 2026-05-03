//
//  MITMProfileServer.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/3/26.
//

import Foundation
import Network

@MainActor
final class MITMProfileServer {
    static let shared = MITMProfileServer()

    private var listener: NWListener?
    private var port: NWEndpoint.Port?
    private var payload: Data?

    /// Auto-shutdown timer: even if the user dismisses the install prompt,
    /// the server stops serving after this window.
    private static let lifetime: TimeInterval = 120

    private var shutdownWork: DispatchWorkItem?

    private init() {}

    /// Starts the server (idempotent across calls — restarts with the new
    /// payload) and returns the URL to open in Safari.
    ///
    /// `NWListener` binds asynchronously when constructed with `.any`, so
    /// we await the first `.ready` state before reading the resolved port.
    func start(payload: Data) async throws -> URL {
        stop()

        let parameters = NWParameters.tcp
        let listener = try NWListener(using: parameters, on: .any)

        self.listener = listener
        self.payload = payload

        listener.newConnectionHandler = { [weak self] connection in
            Task { @MainActor in
                self?.handle(connection: connection)
            }
        }

        let resumedFlag = AtomicBool()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if resumedFlag.setOnce() {
                        continuation.resume()
                    }
                case .failed(let error):
                    if resumedFlag.setOnce() {
                        continuation.resume(throwing: error)
                    } else {
                        NSLog("[MITM-Profile] listener failed: \(error)")
                    }
                default:
                    break
                }
            }
            listener.start(queue: .main)
        }

        guard let resolvedPort = listener.port else {
            stop()
            throw ProfileServerError.bindFailed
        }
        self.port = resolvedPort

        let work = DispatchWorkItem { [weak self] in
            Task { @MainActor in
                self?.stop()
            }
        }
        shutdownWork = work
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.lifetime, execute: work)

        let portValue = resolvedPort.rawValue
        guard let url = URL(string: "http://127.0.0.1:\(portValue)/AnywhereMITMRoot.mobileconfig") else {
            stop()
            throw ProfileServerError.bindFailed
        }
        return url
    }

    func stop() {
        shutdownWork?.cancel()
        shutdownWork = nil
        listener?.cancel()
        listener = nil
        port = nil
        payload = nil
    }

    // MARK: - Connection handling

    private func handle(connection: NWConnection) {
        connection.start(queue: .main)
        receiveRequest(on: connection)
    }

    private func receiveRequest(on connection: NWConnection, accumulated: Data = Data()) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] data, _, isComplete, error in
            Task { @MainActor in
                guard let self else {
                    connection.cancel()
                    return
                }
                if let error {
                    NSLog("[MITM-Profile] receive error: \(error)")
                    connection.cancel()
                    return
                }
                var buffer = accumulated
                if let data { buffer.append(data) }

                // Wait for end-of-headers (CRLFCRLF). We don't bother
                // parsing the request method/path — there's only one
                // resource and it's only reachable from this device.
                if let range = buffer.range(of: Data([0x0D, 0x0A, 0x0D, 0x0A])) {
                    _ = range
                    self.send(connection: connection)
                    return
                }

                if isComplete {
                    connection.cancel()
                    return
                }

                self.receiveRequest(on: connection, accumulated: buffer)
            }
        }
    }

    private func send(connection: NWConnection) {
        guard let payload else {
            connection.cancel()
            return
        }
        let header = "HTTP/1.1 200 OK\r\n" +
                     "Content-Type: application/x-apple-aspen-config\r\n" +
                     "Content-Disposition: attachment; filename=\"AnywhereMITMRoot.mobileconfig\"\r\n" +
                     "Content-Length: \(payload.count)\r\n" +
                     "Connection: close\r\n" +
                     "Cache-Control: no-store\r\n\r\n"
        var response = Data(header.utf8)
        response.append(payload)

        connection.send(content: response, completion: .contentProcessed { _ in
            connection.cancel()
        })
    }

    enum ProfileServerError: Error, LocalizedError {
        case bindFailed

        var errorDescription: String? {
            switch self {
            case .bindFailed: return "Failed to start local profile server."
            }
        }
    }
}

/// One-shot atomic flag used to coalesce duplicate state notifications
/// from `NWListener.stateUpdateHandler` into a single continuation resume.
private final class AtomicBool: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false

    /// Returns `true` exactly once — the first call flips the flag and
    /// returns true; every subsequent call returns false.
    func setOnce() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if value { return false }
        value = true
        return true
    }
}
