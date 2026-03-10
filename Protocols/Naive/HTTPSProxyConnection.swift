//
//  HTTPSProxyConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/10/26.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "HTTPSProxy")

// MARK: - HTTPSProxyConnection

/// ProxyConnection subclass for standard HTTP/1.1 CONNECT proxies over TLS.
///
/// Establishes a TLS connection to the proxy server, sends an HTTP/1.1 CONNECT
/// request with optional Basic authentication, and after receiving a 200 response,
/// tunnels raw data bidirectionally through the TLS connection.
class HTTPSProxyConnection: ProxyConnection {
    private let tlsConnection: TLSRecordConnection
    private var connected = false

    init(tlsConnection: TLSRecordConnection) {
        self.tlsConnection = tlsConnection
        super.init()
        self.responseHeaderReceived = true  // No VLESS response header
    }

    override var isConnected: Bool { connected }
    override var outerTLSVersion: TLSVersion? { .tls13 }

    // MARK: - CONNECT Handshake

    /// Sends an HTTP/1.1 CONNECT request and waits for a 200 response.
    ///
    /// - Parameters:
    ///   - host: The destination host (for the CONNECT target).
    ///   - port: The destination port.
    ///   - username: Optional proxy username for Basic authentication.
    ///   - password: Optional proxy password for Basic authentication.
    ///   - completion: Called with `nil` on success or an error on failure.
    func sendConnect(
        host: String,
        port: UInt16,
        username: String?,
        password: String?,
        completion: @escaping (Error?) -> Void
    ) {
        var request = "CONNECT \(host):\(port) HTTP/1.1\r\n"
        request += "Host: \(host):\(port)\r\n"

        if let username, let password {
            let credentials = Data("\(username):\(password)".utf8).base64EncodedString()
            request += "Proxy-Authorization: Basic \(credentials)\r\n"
        }

        request += "\r\n"

        tlsConnection.send(data: Data(request.utf8)) { [weak self] error in
            if let error {
                completion(error)
                return
            }
            self?.receiveConnectResponse(buffer: Data(), completion: completion)
        }
    }

    /// Receives the HTTP/1.1 CONNECT response, buffering until the header terminator is found.
    private func receiveConnectResponse(buffer: Data, completion: @escaping (Error?) -> Void) {
        tlsConnection.receive { [weak self] data, error in
            guard let self else { return }

            if let error {
                completion(error)
                return
            }

            guard let data, !data.isEmpty else {
                completion(ProxyError.connectionFailed("Proxy closed connection during CONNECT"))
                return
            }

            var accumulated = buffer
            accumulated.append(data)

            // Look for end of HTTP headers
            guard let headerEnd = accumulated.findHeaderEnd() else {
                // Need more data
                self.receiveConnectResponse(buffer: accumulated, completion: completion)
                return
            }

            // Parse status line
            let headerData = accumulated[..<headerEnd]
            guard let headerString = String(data: headerData, encoding: .utf8) else {
                completion(ProxyError.invalidResponse("Invalid CONNECT response encoding"))
                return
            }

            let statusLine = headerString.prefix(while: { $0 != "\r" && $0 != "\n" })
            // Expected: "HTTP/1.1 200 ..."
            let parts = statusLine.split(separator: " ", maxSplits: 2)
            guard parts.count >= 2 else {
                completion(ProxyError.invalidResponse("Malformed CONNECT status line"))
                return
            }

            let statusCode = String(parts[1])
            guard statusCode == "200" else {
                logger.error("[HTTPSProxy] CONNECT rejected: \(String(statusLine), privacy: .public)")
                if statusCode == "407" {
                    completion(ProxyError.connectionFailed("Proxy authentication required (407)"))
                } else {
                    completion(ProxyError.connectionFailed("CONNECT failed with status \(statusCode)"))
                }
                return
            }

            self.connected = true

            // If there's data after the headers, prepend it to the receive buffer
            let afterHeaders = headerEnd + 4  // skip \r\n\r\n
            if afterHeaders < accumulated.count {
                self.tlsConnection.prependToReceiveBuffer(Data(accumulated[afterHeaders...]))
            }

            completion(nil)
        }
    }

    // MARK: - Data Transfer

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        tlsConnection.send(data: data, completion: completion)
    }

    override func sendRaw(data: Data) {
        tlsConnection.send(data: data)
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        tlsConnection.receive { data, error in
            if let error {
                completion(nil, error)
                return
            }
            guard let data, !data.isEmpty else {
                completion(nil, nil)
                return
            }
            completion(data, nil)
        }
    }

    // MARK: - Cancel

    override func cancel() {
        connected = false
        tlsConnection.cancel()
    }
}

// MARK: - Data Helpers

private extension Data {
    /// Finds the position of `\r\n\r\n` in the data, returning the index of the first `\r`.
    func findHeaderEnd() -> Int? {
        let marker: [UInt8] = [0x0D, 0x0A, 0x0D, 0x0A]  // \r\n\r\n
        guard count >= 4 else { return nil }
        for i in 0...(count - 4) {
            if self[i] == marker[0] && self[i+1] == marker[1] &&
               self[i+2] == marker[2] && self[i+3] == marker[3] {
                return i
            }
        }
        return nil
    }
}
