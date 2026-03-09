//
//  NaiveConfiguration.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/9/26.
//

import Foundation

/// Configuration for a NaiveProxy connection.
struct NaiveConfiguration {
    let proxyHost: String
    let proxyPort: UInt16
    let username: String?
    let password: String?
    /// TLS SNI override. Defaults to `proxyHost` when `nil`.
    let sni: String?
    let scheme: NaiveScheme
    /// Skip server certificate validation (for testing only).
    let insecureTLS: Bool

    enum NaiveScheme: String, Codable {
        case https   // HTTP/2 over TLS
        case quic    // HTTP/3 over QUIC
    }

    /// The SNI value to use during the TLS handshake.
    var effectiveSNI: String { sni ?? proxyHost }

    /// Base64-encoded `user:pass` for Proxy-Authorization, or `nil` if no credentials.
    var basicAuth: String? {
        guard let username, let password else { return nil }
        return Data("\(username):\(password)".utf8).base64EncodedString()
    }
}
