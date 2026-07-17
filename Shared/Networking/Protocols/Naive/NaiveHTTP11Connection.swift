//
//  NaiveHTTP11Connection.swift
//  Anywhere
//
//  Created by NodePassProject on 3/10/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "NaiveHTTP11Connection")

// MARK: - NaiveHTTP11Connection

/// Parses only the status line, so `responseHeaders` is always empty.
nonisolated final class NaiveHTTP11Connection: HTTPTunnel, Sendable {

    // MARK: - Properties

    private let transport: TLSStreamTransport
    /// Extra CONNECT headers; names are emitted verbatim so the caller controls wire casing.
    private let extraHeaders: [(name: String, value: String)]
    private let destination: String

    private let _connected = Atomic<Bool>(false)

    let responseHeaders: [(name: String, value: String)] = []

    var isConnected: Bool { _connected.load(ordering: .relaxed) }

    // MARK: - Initialization

    init(transport: TLSStreamTransport, extraHeaders: [(name: String, value: String)],
         destination: String) {
        self.transport = transport
        self.extraHeaders = extraHeaders
        self.destination = destination
    }

    // MARK: - Open Tunnel

    func openTunnel() async throws {
        try await transport.connect()
        try await sendConnectRequest()
    }

    // MARK: - Data Transfer

    func sendData(_ data: Data) async throws {
        try await transport.send(data)
    }

    func receiveData() async throws -> Data? {
        try await transport.receive()
    }

    func close() {
        _connected.store(false, ordering: .relaxed)
        transport.cancel()
    }

    // MARK: - CONNECT Request

    private func sendConnectRequest() async throws {
        var request = "CONNECT \(destination) HTTP/1.1\r\n"
        request += "Host: \(destination)\r\n"
        request += "Proxy-Connection: keep-alive\r\n"
        for header in extraHeaders {
            request += "\(header.name): \(header.value)\r\n"
        }
        request += "\r\n"

        try await transport.send(Data(request.utf8))
        try await receiveConnectResponse()
    }

    // MARK: - CONNECT Response

    private func receiveConnectResponse() async throws {
        var accumulated = Data()
        while true {
            guard let data = try await transport.receive(), !data.isEmpty else {
                throw TLSStreamError.connectionFailed("Connection closed during CONNECT")
            }
            accumulated.append(data)

            guard let headerEnd = accumulated.findNaiveHTTP11HeaderEnd() else {
                continue
            }

            let headerData = accumulated[..<headerEnd]
            guard let headerString = String(data: headerData, encoding: .utf8) else {
                throw TLSStreamError.connectionFailed("Invalid CONNECT response encoding")
            }

            let statusLine = headerString.prefix(while: { $0 != "\r" && $0 != "\n" })
            let parts = statusLine.split(separator: " ", maxSplits: 2)
            guard parts.count >= 2 else {
                throw TLSStreamError.connectionFailed("Malformed CONNECT status line")
            }

            guard parts[0].hasPrefix("HTTP/1.") else {
                throw TLSStreamError.connectionFailed("Invalid HTTP version in CONNECT response")
            }

            let statusCode = String(parts[1])
            guard statusCode == "200" else {
                if statusCode == "407" {
                    throw TLSStreamError.connectionFailed("Proxy authentication required (407)")
                }
                throw TLSStreamError.connectionFailed("CONNECT failed with status \(statusCode)")
            }

            // Security hardening: the proxy must not send data before the tunnel is established.
            let afterHeaders = headerEnd + 4  // skip \r\n\r\n
            if afterHeaders < accumulated.count {
                throw TLSStreamError.connectionFailed("Proxy sent extraneous data after CONNECT response")
            }

            _connected.store(true, ordering: .relaxed)
            return
        }
    }
}

// MARK: - Data Helpers

extension Data {
    /// Returns the index of the leading `\r` of the `\r\n\r\n` header terminator, or `nil` if not yet present.
    nonisolated func findNaiveHTTP11HeaderEnd() -> Int? {
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
