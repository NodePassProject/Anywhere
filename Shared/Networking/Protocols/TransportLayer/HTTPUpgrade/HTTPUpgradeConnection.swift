//
//  HTTPUpgradeConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

// MARK: - HTTPUpgradeConnection

/// Performs an HTTP upgrade handshake, then passes data through as raw bytes (no WebSocket framing).
nonisolated class HTTPUpgradeConnection {

    // MARK: Transport closures

    private let transportSend: (Data, @escaping (Error?) -> Void) -> Void
    private let transportReceive: (@escaping (Data?, Bool, Error?) -> Void) -> Void
    private let transportCancel: () -> Void

    // MARK: State

    private let configuration: HTTPUpgradeConfiguration
    /// Leftover data received after the HTTP 101 response headers.
    private var leftoverBuffer = Data()
    private let lock = UnfairLock()
    private var _isConnected = false

    static let chromeUserAgent = ProxyUserAgent.chrome

    var isConnected: Bool {
        lock.lock()
        let v = _isConnected
        lock.unlock()
        return v
    }

    // MARK: - Initializers

    init(transport: TransportClosures, configuration: HTTPUpgradeConfiguration) {
        self.configuration = configuration
        self.transportSend = transport.send
        self.transportReceive = transport.receive
        self.transportCancel = transport.cancel
        self._isConnected = true
    }

    convenience init(transport: RawTCPSocket, configuration: HTTPUpgradeConfiguration) {
        self.init(transport: TransportClosures(rawTCP: transport), configuration: configuration)
    }

    convenience init(tlsConnection: TLSRecordConnection, configuration: HTTPUpgradeConfiguration) {
        self.init(transport: TransportClosures(tls: tlsConnection), configuration: configuration)
    }

    convenience init(tunnel: ProxyConnection, configuration: HTTPUpgradeConfiguration) {
        self.init(transport: TransportClosures(tunnel: tunnel), configuration: configuration)
    }

    // MARK: - HTTP Upgrade Handshake

    /// Performs the HTTP upgrade handshake.
    func performUpgrade(completion: @escaping (Error?) -> Void) {
        var request = "GET \(configuration.path) HTTP/1.1\r\n"
        request += "Host: \(configuration.host)\r\n"
        request += "Connection: Upgrade\r\n"
        request += "Upgrade: websocket\r\n"

        for (key, value) in configuration.headers {
            request += "\(key): \(value)\r\n"
        }

        // Fall back to Chrome UA if not set.
        if !configuration.headers.keys.contains(where: { $0.lowercased() == "user-agent" }) {
            request += "User-Agent: \(Self.chromeUserAgent)\r\n"
        }

        request += "\r\n"

        guard let requestData = request.data(using: .utf8) else {
            completion(HTTPUpgradeError.upgradeFailed("Failed to encode upgrade request"))
            return
        }

        transportSend(requestData) { [weak self] error in
            if let error {
                completion(HTTPUpgradeError.upgradeFailed(error.localizedDescription))
                return
            }
            self?.receiveUpgradeResponse(completion: completion)
        }
    }

    /// Reads the HTTP 101 response, validating status and Upgrade/Connection headers (case-insensitive).
    private func receiveUpgradeResponse(completion: @escaping (Error?) -> Void) {
        transportReceive { [weak self] data, _, error in
            guard let self else {
                completion(HTTPUpgradeError.upgradeFailed("Connection deallocated"))
                return
            }

            if let error {
                completion(HTTPUpgradeError.upgradeFailed(error.localizedDescription))
                return
            }

            guard let data, !data.isEmpty else {
                completion(HTTPUpgradeError.upgradeFailed("Empty response from server"))
                return
            }

            self.lock.lock()
            self.leftoverBuffer.append(data)

            let headerEnd = Data([0x0D, 0x0A, 0x0D, 0x0A]) // \r\n\r\n
            guard let range = self.leftoverBuffer.range(of: headerEnd) else {
                self.lock.unlock()
                self.receiveUpgradeResponse(completion: completion)
                return
            }

            let headerData = self.leftoverBuffer[self.leftoverBuffer.startIndex..<range.lowerBound]
            let leftover = self.leftoverBuffer[range.upperBound...]
            self.leftoverBuffer = Data(leftover)
            self.lock.unlock()

            guard let headerString = String(data: Data(headerData), encoding: .utf8) else {
                completion(HTTPUpgradeError.upgradeFailed("Cannot decode response headers"))
                return
            }

            let lines = headerString.split(separator: "\r\n")
            guard let statusLine = lines.first else {
                completion(HTTPUpgradeError.upgradeFailed("Empty response"))
                return
            }

            guard statusLine.contains("101") else {
                completion(HTTPUpgradeError.upgradeFailed("Expected HTTP 101, got: \(statusLine)"))
                return
            }

            var hasUpgradeWebSocket = false
            var hasConnectionUpgrade = false
            for line in lines.dropFirst() {
                let parts = line.split(separator: ":", maxSplits: 1)
                guard parts.count == 2 else { continue }
                let key = parts[0].trimmingCharacters(in: .whitespaces).lowercased()
                let value = parts[1].trimmingCharacters(in: .whitespaces).lowercased()
                if key == "upgrade" && value == "websocket" {
                    hasUpgradeWebSocket = true
                }
                if key == "connection" && value == "upgrade" {
                    hasConnectionUpgrade = true
                }
            }

            guard hasUpgradeWebSocket && hasConnectionUpgrade else {
                completion(HTTPUpgradeError.upgradeFailed("Missing Upgrade/Connection headers in 101 response"))
                return
            }

            completion(nil)
        }
    }

    // MARK: - Public API (Raw TCP passthrough)

    func send(data: Data, completion: @escaping (Error?) -> Void) {
        transportSend(data, completion)
    }

    func send(data: Data) {
        transportSend(data) { _ in }
    }

    /// Receives raw data; the first call drains bytes buffered past the 101 response headers.
    func receive(completion: @escaping (Data?, Error?) -> Void) {
        lock.lock()
        if !leftoverBuffer.isEmpty {
            let data = leftoverBuffer
            leftoverBuffer.removeAll(keepingCapacity: true)
            lock.unlock()
            completion(data, nil)
            return
        }
        lock.unlock()

        transportReceive { data, _, error in
            if let error {
                completion(nil, error)
                return
            }
            guard let data, !data.isEmpty else {
                completion(nil, nil) // EOF
                return
            }
            completion(data, nil)
        }
    }

    func cancel() {
        lock.lock()
        _isConnected = false
        leftoverBuffer.removeAll()
        lock.unlock()
        transportCancel()
    }
}
