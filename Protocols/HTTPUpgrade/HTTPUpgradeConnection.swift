//
//  HTTPUpgradeConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

// MARK: - HTTPUpgradeConnection

/// HTTP upgrade connection that performs an HTTP upgrade handshake and then
/// passes data through as raw TCP bytes (no WebSocket framing).
///
/// Closure-based transport abstraction avoids modifying ``BSDSocket`` or ``TLSRecordConnection``.
class HTTPUpgradeConnection {

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

    /// Chrome User-Agent string matching Xray-core's `utils.ChromeUA`.
    /// Uses a fixed base version (Chrome 144, released 2026-01-13) and advances
    /// by one version every ~35 days (midpoint of Xray-core's 25-45 day range).
    static let chromeUserAgent: String = {
        let baseVersion = 144
        let baseDate = DateComponents(calendar: Calendar(identifier: .gregorian),
                                      timeZone: TimeZone(identifier: "UTC"),
                                      year: 2026, month: 1, day: 13).date!
        let daysSinceBase = max(0, Int(Date().timeIntervalSince(baseDate) / 86400))
        let version = baseVersion + daysSinceBase / 35
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/\(version).0.0.0 Safari/537.36"
    }()

    var isConnected: Bool {
        lock.lock()
        let v = _isConnected
        lock.unlock()
        return v
    }

    // MARK: - Initializers

    /// Creates an HTTP upgrade connection over a plain BSD socket.
    init(socket: BSDSocket, configuration: HTTPUpgradeConfiguration) {
        self.configuration = configuration
        self.transportSend = { data, completion in
            socket.send(data: data, completion: completion)
        }
        self.transportReceive = { completion in
            socket.receive(maximumLength: 65536, completion: completion)
        }
        self.transportCancel = {
            socket.forceCancel()
        }
        self._isConnected = true
    }

    /// Creates an HTTP upgrade connection over a TLS record connection.
    init(tlsConnection: TLSRecordConnection, configuration: HTTPUpgradeConfiguration) {
        self.configuration = configuration
        self.transportSend = { data, completion in
            tlsConnection.send(data: data, completion: completion)
        }
        self.transportReceive = { completion in
            tlsConnection.receive { data, error in
                completion(data, false, error)
            }
        }
        self.transportCancel = {
            tlsConnection.cancel()
        }
        self._isConnected = true
    }

    // MARK: - HTTP Upgrade Handshake

    /// Performs the HTTP upgrade handshake.
    ///
    /// Sends an HTTP GET with `Connection: Upgrade` and `Upgrade: websocket` headers
    /// (matching Xray-core's httpupgrade dialer), then waits for HTTP 101.
    ///
    /// - Parameter completion: Called with `nil` on success or an error on failure.
    func performUpgrade(completion: @escaping (Error?) -> Void) {
        // Build HTTP upgrade request matching Xray-core's dialer.go
        var request = "GET \(configuration.path) HTTP/1.1\r\n"
        request += "Host: \(configuration.host)\r\n"
        request += "Connection: Upgrade\r\n"
        request += "Upgrade: websocket\r\n"

        // Default User-Agent (Chrome UA) if not set in custom headers.
        // Matches Xray-core's httpupgrade dialer which sets utils.ChromeUA.
        if configuration.headers["User-Agent"] == nil {
            request += "User-Agent: \(Self.chromeUserAgent)\r\n"
        }

        // Custom headers from configuration
        for (key, value) in configuration.headers {
            request += "\(key): \(value)\r\n"
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

    /// Reads the HTTP 101 response and validates upgrade headers.
    ///
    /// Matches Xray-core's `ConnRF.Read()` validation:
    /// - Status must be "101 Switching Protocols"
    /// - `Upgrade` header must be "websocket" (case-insensitive)
    /// - `Connection` header must be "upgrade" (case-insensitive)
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

            // Look for the end of HTTP headers
            let headerEnd = Data([0x0D, 0x0A, 0x0D, 0x0A]) // \r\n\r\n
            guard let range = self.leftoverBuffer.range(of: headerEnd) else {
                self.lock.unlock()
                // Haven't received the full header yet, keep reading
                self.receiveUpgradeResponse(completion: completion)
                return
            }

            let headerData = self.leftoverBuffer[self.leftoverBuffer.startIndex..<range.lowerBound]
            let leftover = self.leftoverBuffer[range.upperBound...]

            // Keep any leftover data after headers for the first receive
            self.leftoverBuffer = Data(leftover)
            self.lock.unlock()

            // Validate HTTP 101 response
            guard let headerString = String(data: Data(headerData), encoding: .utf8) else {
                completion(HTTPUpgradeError.upgradeFailed("Cannot decode response headers"))
                return
            }

            let lines = headerString.split(separator: "\r\n")
            guard let statusLine = lines.first else {
                completion(HTTPUpgradeError.upgradeFailed("Empty response"))
                return
            }

            // Xray-core checks: resp.Status == "101 Switching Protocols"
            guard statusLine.contains("101") else {
                completion(HTTPUpgradeError.upgradeFailed("Expected HTTP 101, got: \(statusLine)"))
                return
            }

            // Xray-core checks Upgrade and Connection headers (case-insensitive)
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

    /// Sends raw data through the transport (no framing).
    func send(data: Data, completion: @escaping (Error?) -> Void) {
        transportSend(data, completion)
    }

    /// Sends raw data through the transport without tracking completion.
    func send(data: Data) {
        transportSend(data) { _ in }
    }

    /// Receives raw data from the transport.
    ///
    /// On the first call, returns any leftover data buffered from the HTTP upgrade response.
    func receive(completion: @escaping (Data?, Error?) -> Void) {
        lock.lock()
        if !leftoverBuffer.isEmpty {
            let data = leftoverBuffer
            leftoverBuffer.removeAll()
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

    /// Cancels the connection.
    func cancel() {
        lock.lock()
        _isConnected = false
        leftoverBuffer.removeAll()
        lock.unlock()
        transportCancel()
    }
}
