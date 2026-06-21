//
//  TunneledHTTP.swift
//  Anywhere
//
//  Created by NodePassProject on 6/21/26.
//

import Foundation

struct HTTPResponse {
    let statusCode: Int
    let headers: [(name: String, value: String)]
    let body: Data

    func header(_ name: String) -> String? {
        headers.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }?.value
    }

    var bodyText: String { String(decoding: body, as: UTF8.self) }
}

enum HTTPClientError: Error, CustomStringConvertible {
    case connectionClosed(String)
    case malformedResponse(String)
    case unsupported(String)

    var description: String {
        switch self {
        case .connectionClosed(let m): return "Connection closed: \(m)"
        case .malformedResponse(let m): return "Malformed response: \(m)"
        case .unsupported(let m): return "Unsupported: \(m)"
        }
    }
}

struct EchoResponse: Decodable, Equatable {
    let marker: String
    let proto: String
    let tls: Bool
    let alpn: String
    let method: String
    let host: String
    let path: String
    let token: String
    let userAgent: String
    let remote: String

    enum CodingKeys: String, CodingKey {
        case marker, proto, tls, alpn, method, host, path, token
        case userAgent = "user_agent"
        case remote
    }

    static let expectedMarker = "anywhere-test-backend"
}
