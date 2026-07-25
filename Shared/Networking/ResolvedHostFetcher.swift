//
//  ResolvedHostFetcher.swift
//  Anywhere
//
//  Created by NodePassProject on 7/24/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "ResolvedHostFetcher")

nonisolated enum ResolvedHostFetcher {
    static let deadline: Duration = .seconds(30)
    static let maxResponseBytes = 8 * 1024 * 1024
    static let maxRedirects = 3
    
    static func fetch(
        _ request: URLRequest,
        allowInsecure: Bool = false,
        resolveAddress: @escaping @Sendable (String) async throws -> String?
    ) async throws -> (data: Data, response: HTTPURLResponse) {
        var request = request
        var redirects = 0

        while true {
            guard let url = request.url, let host = url.host, !host.isEmpty else {
                throw AnywhereError.subscription(.invalidURL)
            }
            guard let scheme = url.scheme?.lowercased(), scheme == "https" || scheme == "http" else {
                throw AnywhereError.subscription(.invalidURL)
            }
            guard let address = try await resolveAddress(host) else {
                throw AnywhereError.dns(.noAddresses(host: host))
            }

            let port = UInt16(url.port ?? (scheme == "https" ? 443 : 80))
            let result = try await perform(request, url: url, host: host, address: address, port: port,
                                           secure: scheme == "https", allowInsecure: allowInsecure)

            guard let location = redirectTarget(result), redirects < maxRedirects else {
                guard let response = HTTPURLResponse(url: url, statusCode: result.status,
                                                     httpVersion: "HTTP/1.1", headerFields: result.headers) else {
                    throw AnywhereError.dns(.malformedResponse)
                }
                return (result.body, response)
            }

            guard let next = URL(string: location, relativeTo: url)?.absoluteURL else {
                throw AnywhereError.subscription(.invalidURL)
            }
            redirects += 1
            logger.debug("[ResolvedHostFetcher] \(result.status) → \(next.host ?? "?")")
            request.url = next
        }
    }

    // MARK: - One hop

    private struct Exchange: Sendable {
        let status: Int
        let headers: [String: String]
        let body: Data
    }

    private static func perform(_ request: URLRequest, url: URL, host: String, address: String,
                                port: UInt16, secure: Bool, allowInsecure: Bool) async throws -> Exchange {
        let transport: any ByteTransport
        if secure {
            let tls = TLSClient(configuration: TLSConfiguration(serverName: host, alpn: ["http/1.1"],
                                                                insecureSkipVerify: allowInsecure))
            transport = TLSByteTransport(try await tls.connect(host: address, port: port))
        } else {
            let tcp = TCPTransport(host: address, port: port)
            try await tcp.connect()
            transport = tcp
        }
        defer { transport.cancel() }

        let head = requestHead(request, url: url, host: host, port: port, secure: secure)
        return try await withDialDeadline(deadline) {
            transport.cancel()
        } error: {
            AnywhereError.transport(.timedOut(.receive, endpoint: "\(host) (\(address))", detail: "HTTP exchange"))
        } operation: {
            try await transport.send(head)
            return try await readResponse(from: transport)
        }
    }

    private static func requestHead(_ request: URLRequest, url: URL, host: String,
                                    port: UInt16, secure: Bool) -> Data {
        var target = url.path.isEmpty ? "/" : url.path
        if let query = url.query, !query.isEmpty { target += "?\(query)" }

        let defaultPort: UInt16 = secure ? 443 : 80
        let hostHeader = port == defaultPort ? host : "\(host):\(port)"

        var lines = ["GET \(target) HTTP/1.1", "Host: \(hostHeader)"]
        for (field, value) in request.allHTTPHeaderFields ?? [:] where field.lowercased() != "host" {
            lines.append("\(field): \(value)")
        }
        lines.append("Accept-Encoding: identity")
        lines.append("Connection: close")

        return Data((lines.joined(separator: "\r\n") + "\r\n\r\n").utf8)
    }

    // MARK: - Response
    
    private enum Framing {
        case chunked
        case length(Int)
        case untilEOF
        case empty
    }

    private struct Head {
        let status: Int
        let headers: [String: String]
        let framing: Framing
    }

    private static func readResponse(from transport: any ByteTransport) async throws -> Exchange {
        var buffer = Data()
        var cursor = buffer.startIndex
        var head: Head?
        var chunked = ChunkedDecoder()

        while true {
            if head == nil, let separator = buffer.range(of: Data("\r\n\r\n".utf8)) {
                head = try parseHead(buffer[buffer.startIndex..<separator.lowerBound])
                cursor = separator.upperBound
            }
            if let head, let exchange = try body(head, buffer: buffer, cursor: &cursor,
                                                 chunked: &chunked, atEOF: false) {
                return exchange
            }

            switch try await transport.receive() {
            case .bytes(let data):
                buffer.append(data)
                guard buffer.count <= maxResponseBytes else {
                    throw AnywhereError.subscription(.fetchFailed(underlying: AnywhereError.dns(.malformedResponse)))
                }
            case .end:
                guard let head, let exchange = try body(head, buffer: buffer, cursor: &cursor,
                                                        chunked: &chunked, atEOF: true) else {
                    throw AnywhereError.transport(.terminated)
                }
                return exchange
            }
        }
    }

    private static func parseHead(_ data: Data) throws -> Head {
        let headText = String(decoding: data, as: UTF8.self)
        var lines = headText.components(separatedBy: "\r\n")
        guard !lines.isEmpty else { throw AnywhereError.dns(.malformedResponse) }

        let statusLine = lines.removeFirst().split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard statusLine.count >= 2, let status = Int(statusLine[1]) else {
            throw AnywhereError.dns(.malformedResponse)
        }

        var headers: [String: String] = [:]
        for line in lines {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let field = String(line[line.startIndex..<colon]).trimmingCharacters(in: .whitespaces)
            let value = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            headers[field] = headers[field].map { "\($0), \(value)" } ?? value
        }

        let lookup = { (field: String) in
            headers.first { $0.key.caseInsensitiveCompare(field) == .orderedSame }?.value
        }

        let framing: Framing
        if lookup("Transfer-Encoding")?.lowercased().contains("chunked") == true {
            framing = .chunked
        } else if let lengthText = lookup("Content-Length"), let length = Int(lengthText), length >= 0 {
            framing = .length(length)
        } else if status == 204 || status == 304 {
            framing = .empty
        } else {
            framing = .untilEOF
        }

        return Head(status: status, headers: headers, framing: framing)
    }
    
    private static func body(_ head: Head, buffer: Data, cursor: inout Data.Index,
                             chunked: inout ChunkedDecoder, atEOF: Bool) throws -> Exchange? {
        func exchange(_ body: Data) -> Exchange {
            Exchange(status: head.status, headers: head.headers, body: body)
        }

        switch head.framing {
        case .chunked:
            try chunked.consume(buffer, from: &cursor)
            if chunked.finished { return exchange(chunked.body) }
            guard atEOF else { return nil }
            throw AnywhereError.dns(.malformedResponse)

        case .length(let length):
            guard buffer.distance(from: cursor, to: buffer.endIndex) >= length else {
                if atEOF { throw AnywhereError.transport(.terminated) }
                return nil
            }
            return exchange(Data(buffer[cursor..<buffer.index(cursor, offsetBy: length)]))

        case .empty:
            return exchange(Data())

        case .untilEOF:
            guard atEOF else { return nil }
            return exchange(Data(buffer[cursor...]))
        }
    }
    
    private struct ChunkedDecoder {
        private(set) var body = Data()
        private(set) var finished = false
        
        private var awaiting: Int?

        mutating func consume(_ buffer: Data, from cursor: inout Data.Index) throws {
            while !finished {
                if let need = awaiting {
                    guard buffer.distance(from: cursor, to: buffer.endIndex) >= need + 2 else { return }
                    let end = buffer.index(cursor, offsetBy: need)
                    body.append(buffer[cursor..<end])
                    cursor = buffer.index(end, offsetBy: 2)     // chunk data + its CRLF
                    awaiting = nil
                    continue
                }

                guard let lineEnd = buffer.range(of: Data("\r\n".utf8), in: cursor..<buffer.endIndex)
                else { return }
                let sizeText = String(decoding: buffer[cursor..<lineEnd.lowerBound], as: UTF8.self)
                // Chunk extensions follow a semicolon and are ignored.
                let sizeField = sizeText.split(separator: ";", maxSplits: 1).first.map(String.init) ?? sizeText
                guard let size = Int(sizeField.trimmingCharacters(in: .whitespaces), radix: 16), size >= 0 else {
                    throw AnywhereError.dns(.malformedResponse)
                }

                cursor = lineEnd.upperBound
                if size == 0 {                                  // trailers, if any, are of no use here
                    finished = true
                    return
                }
                awaiting = size
            }
        }
    }

    private static func redirectTarget(_ result: Exchange) -> String? {
        guard [301, 302, 303, 307, 308].contains(result.status) else { return nil }
        return result.headers.first { $0.key.caseInsensitiveCompare("Location") == .orderedSame }?.value
    }
}
