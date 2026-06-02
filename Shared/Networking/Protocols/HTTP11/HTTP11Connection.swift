//
//  HTTP11Connection.swift
//  Anywhere
//
//  Created by NodePassProject on 3/10/26.
//

import Foundation

private let logger = AnywhereLogger(category: "HTTP11")

// MARK: - HTTP11Connection

/// HTTP/1.1 CONNECT tunnel through a TLS proxy, conforming to ``HTTPTunnel``.
///
/// Handles the full HTTP/1.1 CONNECT lifecycle:
/// 1. TLS connection to the proxy server (via ``TLSStreamTransport``)
/// 2. Send CONNECT request with Host, Proxy-Connection, plus caller-supplied
///    headers (User-Agent, auth, …)
/// 3. Parse the HTTP/1.1 response and validate status
/// 4. Bidirectional raw data relay through the tunnel
///
/// Request shape:
/// - `Proxy-Connection: keep-alive` for HTTP/1.0 proxy compatibility
/// - HTTP version validation on the response
/// - Rejects extraneous data after the 200 response (security hardening)
///
/// Parses only a status line, so ``responseHeaders`` is always empty — a proxy
/// layer wrapping it therefore negotiates `.none` (HTTP/1.1 carries no padding).
nonisolated class HTTP11Connection: HTTPTunnel {

    // MARK: Properties

    private let transport: TLSStreamTransport
    /// Extra CONNECT request headers (User-Agent, proxy auth, …) supplied by the
    /// caller, keeping this type free of any proxy-protocol specifics. Names are
    /// emitted verbatim so the caller controls header casing, letting it mimic a
    /// specific client's on-the-wire shape.
    private let extraHeaders: [(name: String, value: String)]
    /// The target `host:port` for the CONNECT tunnel.
    private let destination: String

    private var connected = false
    /// Serial queue protecting all mutable state.
    /// `.userInitiated`: data-plane queue, same priority as the rest of the chain.
    private let queue = DispatchQueue(label: "com.argsment.Anywhere.http11", qos: .userInitiated)

    /// HTTP/1.1 parses only a status line, so no response headers are exposed.
    let responseHeaders: [(name: String, value: String)] = []

    /// Whether the tunnel is open and ready for data transfer.
    var isConnected: Bool { connected }

    // MARK: Initialization

    /// Creates an HTTP/1.1 connection for a CONNECT tunnel.
    ///
    /// - Parameters:
    ///   - transport: The TLS transport to the proxy server (ALPN `["http/1.1"]`).
    ///   - extraHeaders: Extra CONNECT request headers (User-Agent, auth, …),
    ///     emitted in order with names verbatim.
    ///   - destination: The target `host:port` for the CONNECT tunnel.
    init(transport: TLSStreamTransport, extraHeaders: [(name: String, value: String)],
         destination: String) {
        self.transport = transport
        self.extraHeaders = extraHeaders
        self.destination = destination
    }

    // MARK: - Open Tunnel

    /// Establishes the TLS connection and opens an HTTP/1.1 CONNECT tunnel.
    ///
    /// Performs the full setup sequence:
    /// 1. TLS connection to the proxy server
    /// 2. CONNECT request with proper headers
    /// 3. Response validation (HTTP version, status code, no extraneous data)
    ///
    /// - Parameter completion: Called with `nil` on success or an error on failure.
    func openTunnel(completion: @escaping (Error?) -> Void) {
        queue.async { [self] in
            transport.connect { [weak self] error in
                guard let self else { return }
                self.queue.async {
                    if let error {
                        completion(error)
                        return
                    }
                    self.sendConnectRequest(completion: completion)
                }
            }
        }
    }

    // MARK: - Data Transfer

    /// Sends data through the CONNECT tunnel.
    ///
    /// After the tunnel is established, data passes directly through the TLS connection.
    ///
    /// - Parameters:
    ///   - data: The data to send through the tunnel.
    ///   - completion: Called with `nil` on success or an error on failure.
    func sendData(_ data: Data, completion: @escaping (Error?) -> Void) {
        transport.send(data: data, completion: completion)
    }

    /// Receives data from the CONNECT tunnel.
    ///
    /// - Parameter completion: Called with `(data, nil)` on success, `(nil, nil)` for EOF,
    ///   or `(nil, error)` on failure.
    func receiveData(completion: @escaping (Data?, Error?) -> Void) {
        transport.receive(completion: completion)
    }

    /// Closes the HTTP/1.1 connection.
    func close() {
        connected = false
        transport.cancel()
    }

    // MARK: - CONNECT Request

    /// Sends the CONNECT request: request line, Host, Proxy-Connection, then
    /// the caller-supplied headers.
    private func sendConnectRequest(completion: @escaping (Error?) -> Void) {
        var request = "CONNECT \(destination) HTTP/1.1\r\n"
        request += "Host: \(destination)\r\n"
        request += "Proxy-Connection: keep-alive\r\n"
        for header in extraHeaders {
            request += "\(header.name): \(header.value)\r\n"
        }
        request += "\r\n"

        transport.send(data: Data(request.utf8)) { [weak self] error in
            guard let self else { return }
            if let error {
                completion(error)
                return
            }
            self.receiveConnectResponse(buffer: Data(), completion: completion)
        }
    }

    // MARK: - CONNECT Response

    /// Receives the HTTP/1.1 CONNECT response, buffering until the header terminator is found.
    private func receiveConnectResponse(buffer: Data, completion: @escaping (Error?) -> Void) {
        transport.receive { [weak self] data, error in
            guard let self else { return }

            if let error {
                completion(error)
                return
            }

            guard let data, !data.isEmpty else {
                completion(TLSStreamError.connectionFailed("Connection closed during CONNECT"))
                return
            }

            var accumulated = buffer
            accumulated.append(data)

            // Look for end of HTTP headers (\r\n\r\n)
            guard let headerEnd = accumulated.findHTTP11HeaderEnd() else {
                // Need more data
                self.receiveConnectResponse(buffer: accumulated, completion: completion)
                return
            }

            // Parse status line
            let headerData = accumulated[..<headerEnd]
            guard let headerString = String(data: headerData, encoding: .utf8) else {
                completion(TLSStreamError.connectionFailed("Invalid CONNECT response encoding"))
                return
            }

            let statusLine = headerString.prefix(while: { $0 != "\r" && $0 != "\n" })
            let parts = statusLine.split(separator: " ", maxSplits: 2)
            guard parts.count >= 2 else {
                completion(TLSStreamError.connectionFailed("Malformed CONNECT status line"))
                return
            }

            // Require HTTP/1.x; reject anything else as a malformed response.
            guard parts[0].hasPrefix("HTTP/1.") else {
                completion(TLSStreamError.connectionFailed("Invalid HTTP version in CONNECT response"))
                return
            }

            let statusCode = String(parts[1])
            guard statusCode == "200" else {
                if statusCode == "407" {
                    completion(TLSStreamError.connectionFailed("Proxy authentication required (407)"))
                } else {
                    completion(TLSStreamError.connectionFailed("CONNECT failed with status \(statusCode)"))
                }
                return
            }

            // Reject extraneous data after the headers: the proxy must not send
            // anything before the tunnel is established (security hardening).
            let afterHeaders = headerEnd + 4  // skip \r\n\r\n
            if afterHeaders < accumulated.count {
                completion(TLSStreamError.connectionFailed("Proxy sent extraneous data after CONNECT response"))
                return
            }

            self.connected = true
            completion(nil)
        }
    }
}

// MARK: - Data Helpers

extension Data {
    /// Finds the position of `\r\n\r\n` in the data, returning the index of the first `\r`.
    func findHTTP11HeaderEnd() -> Int? {
        let marker: [UInt8] = [0x0D, 0x0A, 0x0D, 0x0A]
        guard count >= 4 else { return nil }
        for i in 0...(count - 4) {
            if self[self.startIndex + i] == marker[0] &&
               self[self.startIndex + i + 1] == marker[1] &&
               self[self.startIndex + i + 2] == marker[2] &&
               self[self.startIndex + i + 3] == marker[3] {
                return i
            }
        }
        return nil
    }
}
