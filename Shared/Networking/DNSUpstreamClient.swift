//
//  DNSUpstreamClient.swift
//  Anywhere
//
//  Created by NodePassProject on 7/24/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "DNSUpstreamClient")

nonisolated enum DNSUpstreamClient {

    static let queryTimeout: Duration = .seconds(4)

    enum Family {
        case ipv4
        case both
    }

    // MARK: - Public API
    
    static func resolve(_ host: String, via upstream: DNSUpstream, family: Family = .both) async throws -> [String] {
        let addresses: [String]
        do {
            switch upstream {
            case .system:
                throw AnywhereError.dns(.resolutionFailed(host: host, detail: "no upstream configured"))
            case .plain(let server, let port):
                addresses = try await queryAll(host, family: family) { name, type in
                    try await queryPlain(name, type: type, server: server, port: port)
                }
            case .doh(let url):
                addresses = try await queryAll(host, family: family) { name, type in
                    try await queryDoH(name, type: type, url: url)
                }
            }
        } catch {
            logger.warning("[DNSUpstreamClient] Lookup for \(host) via \(describe(upstream)) failed: \(error)")
            throw error
        }

        guard !addresses.isEmpty else {
            logger.warning("[DNSUpstreamClient] \(describe(upstream)) returned no address for \(host)")
            throw AnywhereError.dns(.noAddresses(host: host))
        }
        return addresses
    }

    // MARK: - Internal
    
    private static func queryAll(
        _ host: String,
        family: Family,
        query: @escaping @Sendable (String, UInt16) async throws -> [String]
    ) async throws -> [String] {
        switch family {
        case .ipv4:
            return try await query(host, DNSMessage.typeA)
        case .both:
            async let ipv4 = query(host, DNSMessage.typeA)
            async let ipv6 = query(host, DNSMessage.typeAAAA)
            var addresses: [String] = []
            var failure: (any Error)?
            do { addresses += try await ipv4 } catch { failure = error }
            do { addresses += try await ipv6 } catch { failure = failure ?? error }
            if addresses.isEmpty, let failure { throw failure }
            return addresses
        }
    }

    // MARK: - Plain

    private static func queryPlain(_ name: String, type: UInt16,
                                   server: String, port: UInt16) async throws -> [String] {
        let id = UInt16.random(in: UInt16.min...UInt16.max)
        guard let query = DNSMessage.makeQuery(domain: name, type: type, id: id) else {
            throw AnywhereError.dns(.resolutionFailed(host: name, detail: "name not encodable"))
        }

        let transport = UDPTransport(host: server, port: port)
        defer { transport.cancel() }
        
        return try await withDialDeadline(queryTimeout) {
            transport.cancel()
        } error: {
            AnywhereError.dns(.timedOut(host: name))
        } operation: {
            try await transport.connect()
            try await transport.send(query)
            while true {
                let datagram = try await transport.receive()
                if let addresses = try decode(datagram, id: id, name: name) { return addresses }
            }
        }
    }

    // MARK: - DoH

    private static func queryDoH(_ name: String, type: UInt16, url: URL) async throws -> [String] {
        let id: UInt16 = 0
        guard let query = DNSMessage.makeQuery(domain: name, type: type, id: id) else {
            throw AnywhereError.dns(.resolutionFailed(host: name, detail: "name not encodable"))
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = query
        request.setValue("application/dns-message", forHTTPHeaderField: "Content-Type")
        request.setValue("application/dns-message", forHTTPHeaderField: "Accept")
        request.setValue(ProxyUserAgent.default, forHTTPHeaderField: "User-Agent")
        request.timeoutInterval = TimeInterval(queryTimeout.components.seconds)
        request.cachePolicy = .reloadIgnoringLocalCacheData

        let (data, response) = try await URLSession.shared.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? -1
        guard status == 200 else {
            throw AnywhereError.dns(.resolutionFailed(host: name, detail: "DoH HTTP \(status)"))
        }
        guard let addresses = try decode(data, id: id, name: name) else {
            throw AnywhereError.dns(.malformedResponse)
        }
        return addresses
    }

    // MARK: - Shared decoding
    
    private static func decode(_ message: Data, id: UInt16, name: String) throws -> [String]? {
        do {
            return try DNSMessage.parseAddresses(message, expectedID: id)
        } catch DNSMessage.ParseFailure.identifierMismatch {
            return nil
        } catch DNSMessage.ParseFailure.serverFailure(let rcode) {
            logger.debug("[DNSUpstreamClient] \(name) answered with RCODE \(rcode)")
            return []
        } catch {
            throw AnywhereError.dns(.malformedResponse)
        }
    }
    
    private static func describe(_ upstream: DNSUpstream) -> String {
        switch upstream {
        case .system: return "system"
        case .plain(let host, let port): return "\(host):\(port)"
        case .doh(let url): return "DoH \(url.host ?? "?")"
        }
    }
}
