//
//  NaiveHTTP11Connection.swift
//  Anywhere
//
//  Created by NodePassProject on 3/10/26.
//

import Foundation

private let logger = AnywhereLogger(category: "NaiveHTTP11Connection")

// MARK: - NaiveHTTP11Connection

/// HTTP/1.1 CONNECT tunnel through a TLS proxy. Parses only the status line,
/// so `responseHeaders` is always empty.
nonisolated class NaiveHTTP11Connection: HTTPTunnel {

    // MARK: Properties

    private let transport: TLSStreamTransport
    /// Extra CONNECT headers; names are emitted verbatim so the caller controls wire casing.
    private let extraHeaders: [(name: String, value: String)]
    private let destination: String

    private var connected = false
    /// `.userInitiated` matches the data-plane priority of the rest of the chain.
    private let queue = DispatchQueue(label: AWCore.Identifier.http11Queue, qos: .userInitiated)

    let responseHeaders: [(name: String, value: String)] = []

    var isConnected: Bool { connected }

    // MARK: Initialization

    init(transport: TLSStreamTransport, extraHeaders: [(name: String, value: String)],
         destination: String) {
        self.transport = transport
        self.extraHeaders = extraHeaders
        self.destination = destination
    }

    // MARK: - Open Tunnel

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

    func sendData(_ data: Data, completion: @escaping (Error?) -> Void) {
        transport.send(data: data, completion: completion)
    }

    /// - Parameter completion: `(data, nil)` on success, `(nil, nil)` for EOF, `(nil, error)` on failure.
    func receiveData(completion: @escaping (Data?, Error?) -> Void) {
        transport.receive(completion: completion)
    }

    func close() {
        connected = false
        transport.cancel()
    }

    // MARK: - CONNECT Request

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

    /// Buffers chunks until `\r\n\r\n` is found, then validates the status line.
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

            guard let headerEnd = accumulated.findNaiveHTTP11HeaderEnd() else {
                self.receiveConnectResponse(buffer: accumulated, completion: completion)
                return
            }

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

            // Security hardening: the proxy must not send data before the tunnel is established.
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
    /// Returns the index of the leading `\r` of the `\r\n\r\n` header terminator, or `nil` if not yet present.
    func findNaiveHTTP11HeaderEnd() -> Int? {
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
