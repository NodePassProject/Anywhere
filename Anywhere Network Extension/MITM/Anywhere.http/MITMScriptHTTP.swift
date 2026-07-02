//
//  MITMScriptHTTP.swift
//  Anywhere
//
//  Created by NodePassProject on 6/2/26.
//

import Foundation

final class MITMScriptHTTPClient {
    static let shared = MITMScriptHTTPClient()
    private init() {}

    // MARK: - Global in-flight byte budget

    /// Cross-fetch ceiling on buffered response bytes; keeps concurrent fetches well under the NE's ~50 MiB budget.
    static let maxGlobalInFlightBytes: Int = 16 * 1024 * 1024

    private static let inFlightLock = UnfairLock()
    private static var inFlightBytes = 0

    static func reserveInFlight(_ count: Int) -> Bool {
        inFlightLock.lock(); defer { inFlightLock.unlock() }
        guard inFlightBytes + count <= maxGlobalInFlightBytes else { return false }
        inFlightBytes += count
        return true
    }

    /// Clamped at 0 to guard against double-release.
    static func releaseInFlight(_ count: Int) {
        guard count > 0 else { return }
        inFlightLock.lock(); defer { inFlightLock.unlock() }
        inFlightBytes = max(0, inFlightBytes - count)
    }

    struct Response {
        let status: Int
        let headers: [(name: String, value: String)]
        let body: Data
        let finalURL: String?
    }

    enum ClientError: Error, LocalizedError {
        case notHTTP
        case responseTooLarge(Int)
        case globalBudgetExceeded(Int)

        var errorDescription: String? {
            switch self {
            case .notHTTP:
                return "response was not HTTP"
            case .responseTooLarge(let cap):
                return "response body exceeds the \(cap)-byte cap"
            case .globalBudgetExceeded(let cap):
                return "aggregate in-flight response bytes exceed the \(cap)-byte global budget; retry once other requests finish"
            }
        }
    }

    /// Calls `completion` exactly once; response-size caps are enforced as the body streams.
    func send(
        _ request: URLRequest,
        followRedirects: Bool,
        insecure: Bool,
        maxBytes: Int,
        resourceTimeout: TimeInterval,
        completion: @escaping (Result<Response, Error>) -> Void
    ) {
        // Dialed through the tunnel's routing (direct / reject / proxy), with TLS layered on for
        // https. The engine already guarantees an absolute http(s) URL with a host.
        guard let scheme = request.url?.scheme?.lowercased(), scheme == "http" || scheme == "https",
              request.url?.host?.isEmpty == false else {
            completion(.failure(ClientError.notHTTP))
            return
        }
        sendViaTunnel(request: request, followRedirects: followRedirects, insecure: insecure,
                      maxBytes: maxBytes, resourceTimeout: resourceTimeout, completion: completion)
    }

    private func sendViaTunnel(
        request: URLRequest,
        followRedirects: Bool,
        insecure: Bool,
        maxBytes: Int,
        resourceTimeout: TimeInterval,
        completion: @escaping (Result<Response, Error>) -> Void
    ) {
        routedRequest(request, redirectsRemaining: followRedirects ? Self.maxRedirects : 0,
                      insecure: insecure, maxBytes: maxBytes, resourceTimeout: resourceTimeout,
                      completion: completion)
    }

    /// Runs one request; on a followable 3xx, recurses on the `Location` target (re-routed per hop).
    private func routedRequest(
        _ request: URLRequest,
        redirectsRemaining: Int,
        insecure: Bool,
        maxBytes: Int,
        resourceTimeout: TimeInterval,
        completion: @escaping (Result<Response, Error>) -> Void
    ) {
        performRoutedRequest(request, insecure: insecure, maxBytes: maxBytes, resourceTimeout: resourceTimeout) { result in
            guard case .success(let response) = result else { completion(result); return }
            guard redirectsRemaining > 0, Self.isRedirect(response.status),
                  let location = Self.firstHeaderValue(response.headers, name: "Location"),
                  let next = Self.makeRedirectRequest(from: request, location: location, status: response.status)
            else {
                completion(result)
                return
            }
            self.routedRequest(next, redirectsRemaining: redirectsRemaining - 1, insecure: insecure,
                               maxBytes: maxBytes, resourceTimeout: resourceTimeout, completion: completion)
        }
    }

    /// Routes one request. For https, prefers a pooled, multiplexed HTTP/2 connection and falls back
    /// to HTTP/1.1 when the origin doesn't negotiate `h2`; plain http stays HTTP/1.1 (no h2c).
    private func performRoutedRequest(
        _ request: URLRequest,
        insecure: Bool,
        maxBytes: Int,
        resourceTimeout: TimeInterval,
        completion: @escaping (Result<Response, Error>) -> Void
    ) {
        guard let scheme = request.url?.scheme?.lowercased(), let host = request.url?.host, !host.isEmpty else {
            completion(.failure(ClientError.notHTTP))
            return
        }
        let isTLS = scheme == "https"
        let defaultPort: UInt16 = isTLS ? 443 : 80
        let port = UInt16(exactly: request.url?.port ?? Int(defaultPort)) ?? defaultPort
        let hostHeader = Self.hostHeader(host: host, port: port, defaultPort: defaultPort)

        guard isTLS else {
            performHTTP1Request(request, host: host, port: port, hostHeader: hostHeader, isTLS: false,
                                insecure: insecure, maxBytes: maxBytes, resourceTimeout: resourceTimeout,
                                completion: completion)
            return
        }

        MITMScriptHTTP2Pool.shared.perform(
            request: request, host: host, port: port, hostHeader: hostHeader, insecure: insecure,
            maxBytes: maxBytes, resourceTimeout: resourceTimeout
        ) { [weak self] outcome in
            switch outcome {
            case .response(let response):
                completion(.success(response))
            case .failure(let error):
                completion(.failure(error))
            case .fallbackToHTTP1:
                guard let self else { completion(.failure(ClientError.notHTTP)); return }
                self.performHTTP1Request(request, host: host, port: port, hostHeader: hostHeader, isTLS: true,
                                         insecure: insecure, maxBytes: maxBytes, resourceTimeout: resourceTimeout,
                                         completion: completion)
            }
        }
    }

    /// Dials the host via `OutboundConnector`, then runs one HTTP/1.1 exchange — over TLS first for https.
    private func performHTTP1Request(
        _ request: URLRequest,
        host: String,
        port: UInt16,
        hostHeader: String,
        isTLS: Bool,
        insecure: Bool,
        maxBytes: Int,
        resourceTimeout: TimeInterval,
        completion: @escaping (Result<Response, Error>) -> Void
    ) {
        let queue = DispatchQueue(label: "com.anywhere.ne.tunneled-http")
        OutboundConnector.dial(host: host, port: port, queue: queue) { result in
            switch result {
            case .failure(let error):
                completion(.failure(error))
            case .success(let dialed):
                if isTLS {
                    self.runTLSExchange(dialed: dialed, request: request, host: host, hostHeader: hostHeader,
                                        insecure: insecure, maxBytes: maxBytes, resourceTimeout: resourceTimeout,
                                        queue: queue, completion: completion)
                } else {
                    let exchange = TunneledHTTP1Exchange(
                        connection: dialed.connection, request: request, hostHeader: hostHeader,
                        maxBytes: maxBytes, resourceTimeout: resourceTimeout, queue: queue,
                        teardown: { dialed.connection.cancel(); dialed.proxyClient?.cancel() },
                        completion: completion
                    )
                    exchange.start()
                }
            }
        }
    }

    private func runTLSExchange(
        dialed: OutboundConnector.Dialed,
        request: URLRequest,
        host: String,
        hostHeader: String,
        insecure: Bool,
        maxBytes: Int,
        resourceTimeout: TimeInterval,
        queue: DispatchQueue,
        completion: @escaping (Result<Response, Error>) -> Void
    ) {
        // ALPN pinned to http/1.1 (the exchange speaks only 1.1). `insecure` skips cert checks for
        // this connection alone.
        let tlsConfiguration = TLSConfiguration(serverName: host, alpn: ["http/1.1"], insecureSkipVerify: insecure)
        let tlsClient = TLSClient(configuration: tlsConfiguration)
        tlsClient.connect(overTunnel: dialed.connection) { result in
            queue.async {
                switch result {
                case .failure(let error):
                    dialed.connection.cancel()
                    dialed.proxyClient?.cancel()
                    completion(.failure(error))
                case .success(let tlsConnection):
                    let tlsProxyConnection = TLSProxyConnection(tlsConnection: tlsConnection)
                    let exchange = TunneledHTTP1Exchange(
                        connection: tlsProxyConnection, request: request, hostHeader: hostHeader,
                        maxBytes: maxBytes, resourceTimeout: resourceTimeout, queue: queue,
                        teardown: {
                            tlsProxyConnection.cancel()
                            tlsClient.cancel()
                            dialed.proxyClient?.cancel()
                        },
                        completion: completion
                    )
                    exchange.start()
                }
            }
        }
    }

    private static func hostHeader(host: String, port: UInt16, defaultPort: UInt16) -> String {
        let hostPart = host.contains(":") ? "[\(host)]" : host
        return port == defaultPort ? hostPart : "\(hostPart):\(port)"
    }

    // MARK: - Redirects

    private static let maxRedirects = 10

    private static func isRedirect(_ status: Int) -> Bool {
        status == 301 || status == 302 || status == 303 || status == 307 || status == 308
    }

    private static func firstHeaderValue(_ headers: [(name: String, value: String)], name: String) -> String? {
        for header in headers where header.name.caseInsensitiveCompare(name) == .orderedSame { return header.value }
        return nil
    }

    /// Builds the next request for a 3xx `Location`. 303 (and 301/302 on a non-GET/HEAD method)
    /// downgrade to GET and drop the body; 307/308 preserve method and body. Sensitive headers are
    /// stripped on a cross-origin hop; Host / Content-Length are recomputed by the exchange.
    private static func makeRedirectRequest(from request: URLRequest, location: String, status: Int) -> URLRequest? {
        guard let base = request.url,
              let target = URL(string: location, relativeTo: base)?.absoluteURL,
              let scheme = target.scheme?.lowercased(), scheme == "http" || scheme == "https",
              let host = target.host, !host.isEmpty else {
            return nil
        }

        var next = URLRequest(url: target)
        let method = (request.httpMethod ?? "GET").uppercased()
        let downgradeToGET = status == 303 || ((status == 301 || status == 302) && method != "GET" && method != "HEAD")
        if downgradeToGET {
            next.httpMethod = "GET"
        } else {
            next.httpMethod = method
            next.httpBody = request.httpBody
        }
        next.timeoutInterval = request.timeoutInterval

        let sameOrigin = host.caseInsensitiveCompare(base.host ?? "") == .orderedSame
            && scheme == (base.scheme?.lowercased() ?? "")
            && target.port == base.port
        let bodyHeaders: Set<String> = ["content-length", "content-type", "transfer-encoding"]
        let sensitiveCrossOrigin: Set<String> = ["authorization", "cookie", "proxy-authorization"]
        for (name, value) in request.allHTTPHeaderFields ?? [:] {
            let lower = name.lowercased()
            if lower == "host" { continue }
            if downgradeToGET && bodyHeaders.contains(lower) { continue }
            if !sameOrigin && sensitiveCrossOrigin.contains(lower) { continue }
            next.addValue(value, forHTTPHeaderField: name)
        }
        return next
    }

}
