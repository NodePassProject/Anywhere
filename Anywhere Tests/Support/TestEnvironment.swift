//
//  TestEnvironment.swift
//  Anywhere
//
//  Created by NodePassProject on 6/21/26.
//

import Foundation
@testable import Anywhere

enum TestConfigError: Error, CustomStringConvertible {
    case missing(String)

    var description: String {
        switch self {
        case .missing(let key): return "Missing required environment variable \(key)"
        }
    }
}

enum TestEnvironment {
    private static func string(_ key: String) -> String? {
        guard let value = ProcessInfo.processInfo.environment[key], !value.isEmpty else { return nil }
        return value
    }
    
    static let defaultTargetHost = "test.anywhere-proxy.com"
    static let defaultHTTPPort: UInt16 = 30080
    static let defaultHTTPSPort: UInt16 = 30443

    static var proxyURL: String? { string("ANYWHERE_TEST_PROXY_URL") }
    static var targetHost: String { string("ANYWHERE_TEST_TARGET_HOST") ?? defaultTargetHost }
    static var httpPort: UInt16 { string("ANYWHERE_TEST_HTTP_PORT").flatMap(UInt16.init) ?? defaultHTTPPort }
    static var httpsPort: UInt16 { string("ANYWHERE_TEST_HTTPS_PORT").flatMap(UInt16.init) ?? defaultHTTPSPort }
    static var allowInsecure: Bool { string("ANYWHERE_TEST_ALLOW_INSECURE") != "0" }
    
    static var isConfigured: Bool { proxyURL != nil }
    
    static func requireTargetHost() throws -> String { targetHost }
    
    static func proxyConfiguration() throws -> ProxyConfiguration {
        guard let url = proxyURL else { throw TestConfigError.missing("ANYWHERE_TEST_PROXY_URL") }
        return try ProxyConfiguration.parse(url: url)
    }
    
    static func applyInsecureOverrideIfNeeded() {
        guard allowInsecure else { return }
        AWCore.setAllowInsecure(true)
        CertificatePolicy.reload()
    }
}
