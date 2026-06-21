//
//  TunneledHTTP1Client.swift
//  Anywhere
//
//  Created by NodePassProject on 6/21/26.
//

import Foundation

enum TunneledHTTP1Client {
    static func get(
        stream: ByteStream,
        host: String,
        path: String,
        extraHeaders: [(String, String)] = []
    ) async throws -> HTTPResponse {
        var request = "GET \(path) HTTP/1.1\r\n"
        request += "Host: \(host)\r\n"
        request += "User-Agent: Anywhere\r\n"
        request += "Accept: */*\r\n"
        for (name, value) in extraHeaders { request += "\(name): \(value)\r\n" }
        request += "Connection: close\r\n\r\n"

        try await stream.sendBytes(Data(request.utf8))
        
        var buffer = Data()
        let headerTerminator = Data([0x0D, 0x0A, 0x0D, 0x0A]) // \r\n\r\n
        var headerEnd: Int? = nil
        while headerEnd == nil {
            guard let chunk = try await stream.receiveBytes() else {
                throw HTTPClientError.connectionClosed("before response headers were complete")
            }
            buffer.append(chunk)
            headerEnd = buffer.range(of: headerTerminator)?.lowerBound
        }

        let headerData = buffer[buffer.startIndex..<headerEnd!]
        let (statusCode, headers) = try parseHead(headerData)
        
        var body = Data(buffer[(headerEnd! + 4)...])
        if let lengthValue = headers.first(where: { $0.name.caseInsensitiveCompare("Content-Length") == .orderedSame })?.value,
           let contentLength = Int(lengthValue.trimmingCharacters(in: .whitespaces)) {
            while body.count < contentLength {
                guard let chunk = try await stream.receiveBytes() else {
                    throw HTTPClientError.connectionClosed("body truncated: got \(body.count) of \(contentLength) bytes")
                }
                body.append(chunk)
            }
            body = Data(body.prefix(contentLength))
        } else if headers.contains(where: { $0.name.caseInsensitiveCompare("Transfer-Encoding") == .orderedSame }) {
            throw HTTPClientError.unsupported("Transfer-Encoding (chunked) not supported by the test client")
        } else {
            while let chunk = try await stream.receiveBytes() {
                body.append(chunk)
            }
        }

        return HTTPResponse(statusCode: statusCode, headers: headers, body: body)
    }

    // MARK: - Parsing

    private static func parseHead(_ headerData: Data) throws -> (Int, [(name: String, value: String)]) {
        let text = String(decoding: headerData, as: UTF8.self)
        let lines = text.components(separatedBy: "\r\n")
        guard let statusLine = lines.first else {
            throw HTTPClientError.malformedResponse("empty response head")
        }

        // "HTTP/1.1 200 OK"
        let statusParts = statusLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard statusParts.count >= 2, statusParts[0].hasPrefix("HTTP/"),
              let statusCode = Int(statusParts[1]) else {
            throw HTTPClientError.malformedResponse("bad status line: \(statusLine)")
        }

        var headers: [(name: String, value: String)] = []
        for line in lines.dropFirst() where !line.isEmpty {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = String(line[line.startIndex..<colon]).trimmingCharacters(in: .whitespaces)
            let value = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            headers.append((name: name, value: value))
        }

        return (statusCode, headers)
    }
}
