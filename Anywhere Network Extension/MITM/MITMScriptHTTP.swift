//
//  MITMScriptHTTP.swift
//  Anywhere
//
//  Created by NodePassProject on 6/2/26.
//

import Foundation
import Network

/// Outbound HTTP for the ``Anywhere/http`` script API. A buffered MITM script
/// (an `async function process(ctx)`) calls `Anywhere.http.get` / `post` /
/// `request`, which ``MITMScriptEngine`` routes here.
///
/// ### Loopback
/// Requests go out as the Network Extension's **own** `URLSession` traffic,
/// which the kernel keeps out of the tunnel the extension manages — so a
/// script fetch does not loop back through the MITM (the same bypass
/// ``RawTCPSocket`` relies on for upstream sockets). DNS resolves on the
/// physical interface for the extension's own queries, so no special routing
/// is needed here.
///
/// Each call gets its own ephemeral `URLSession` so per-request redirect and
/// TLS-trust policy can differ without a shared cookie jar; the session is
/// invalidated once its task settles.
final class MITMScriptHTTPClient {
    static let shared = MITMScriptHTTPClient()
    private init() {}

    // MARK: - SSRF guard

    /// Whether a script's ``Anywhere/http`` request to `host` must be refused.
    /// Rule sets are untrusted (imported / subscribed), and these requests
    /// resolve on the device's real interface **outside** the tunnel — so
    /// without this a malicious script could pivot to loopback, link-local
    /// (incl. the `169.254.169.254` cloud-metadata endpoint), or RFC1918 / ULA
    /// LAN services. Blocks `localhost` / `*.local` by name and any IP
    /// **literal** in a non-public range.
    ///
    /// A hostname that *resolves* to an internal address (DNS rebinding) is not
    /// caught here — name resolution happens inside `URLSession`; the redirect
    /// delegate re-applies this check to every hop, and the stronger mitigation
    /// is gating ``Anywhere/http`` behind a per-rule-set opt-in.
    static func isBlockedHost(_ host: String) -> Bool {
        let h = host.lowercased()
        if h == "localhost" || h.hasSuffix(".localhost") || h.hasSuffix(".local") { return true }
        // Strip IPv6 URI brackets before attempting a literal parse.
        let bare = (h.hasPrefix("[") && h.hasSuffix("]")) ? String(h.dropFirst().dropLast()) : h
        if let v4 = IPv4Address(bare) { return isBlockedIPv4([UInt8](v4.rawValue)) }
        if let v6 = IPv6Address(bare) { return isBlockedIPv6([UInt8](v6.rawValue)) }
        return false
    }

    private static func isBlockedIPv4(_ a: [UInt8]) -> Bool {
        guard a.count == 4 else { return true }
        switch a[0] {
        case 0:   return true                       // 0.0.0.0/8 "this host"
        case 10:  return true                       // 10.0.0.0/8 private
        case 127: return true                       // 127.0.0.0/8 loopback
        case 100: return (64...127).contains(a[1])  // 100.64.0.0/10 CGNAT
        case 169: return a[1] == 254                // 169.254.0.0/16 link-local (metadata)
        case 172: return (16...31).contains(a[1])   // 172.16.0.0/12 private
        case 192: return a[1] == 168                // 192.168.0.0/16 private
        case 255: return a == [255, 255, 255, 255]  // broadcast
        default:  return false
        }
    }

    private static func isBlockedIPv6(_ a: [UInt8]) -> Bool {
        guard a.count == 16 else { return true }
        // :: (unspecified) and ::1 (loopback)
        if a[0..<15].allSatisfy({ $0 == 0 }) && (a[15] == 0 || a[15] == 1) { return true }
        // fc00::/7 unique-local
        if (a[0] & 0xFE) == 0xFC { return true }
        // fe80::/10 link-local
        if a[0] == 0xFE && (a[1] & 0xC0) == 0x80 { return true }
        // ::ffff:0:0/96 IPv4-mapped — judge by the embedded IPv4 address
        if a[0..<10].allSatisfy({ $0 == 0 }) && a[10] == 0xFF && a[11] == 0xFF {
            return isBlockedIPv4(Array(a[12..<16]))
        }
        return false
    }

    /// One HTTP response handed back to a script. `headers` are flattened to
    /// pairs (URLSession combines duplicate field names); `finalURL` is the
    /// URL after any followed redirects.
    struct Response {
        let status: Int
        let headers: [(name: String, value: String)]
        let body: Data
        let finalURL: String?
    }

    enum ClientError: Error, LocalizedError {
        case notHTTP
        case responseTooLarge(Int)

        var errorDescription: String? {
            switch self {
            case .notHTTP:
                return "response was not HTTP"
            case .responseTooLarge(let cap):
                return "response body exceeds the \(cap)-byte cap"
            }
        }
    }

    /// Sends `request` and calls `completion` exactly once, on a URLSession
    /// background queue. `followRedirects` chooses whether 3xx are followed or
    /// returned as-is; `insecure` accepts self-signed server certificates
    /// (the caller gates this to the global Allow-Insecure setting);
    /// `maxBytes` caps the response body (larger → ``ClientError/responseTooLarge``).
    func send(
        _ request: URLRequest,
        followRedirects: Bool,
        insecure: Bool,
        maxBytes: Int,
        completion: @escaping (Result<Response, Error>) -> Void
    ) {
        let delegate = SessionDelegate(followRedirects: followRedirects, insecure: insecure)
        let session = URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
        let task = session.dataTask(with: request) { data, response, error in
            // One session per request: tear it down once the task settles so
            // the delegate (which the session retains until invalidation) is
            // released and no sessions accumulate.
            defer { session.finishTasksAndInvalidate() }
            if let error {
                completion(.failure(error))
                return
            }
            guard let http = response as? HTTPURLResponse else {
                completion(.failure(ClientError.notHTTP))
                return
            }
            let body = data ?? Data()
            if body.count > maxBytes {
                completion(.failure(ClientError.responseTooLarge(maxBytes)))
                return
            }
            var headers: [(name: String, value: String)] = []
            headers.reserveCapacity(http.allHeaderFields.count)
            for (key, value) in http.allHeaderFields {
                guard let name = key as? String else { continue }
                headers.append((name: name, value: String(describing: value)))
            }
            completion(.success(Response(
                status: http.statusCode,
                headers: headers,
                body: body,
                finalURL: http.url?.absoluteString
            )))
        }
        task.resume()
    }

    /// Per-request delegate applying the redirect and TLS-trust policy. The
    /// session retains it until `finishTasksAndInvalidate`.
    private final class SessionDelegate: NSObject, URLSessionDataDelegate {
        private let followRedirects: Bool
        private let insecure: Bool

        init(followRedirects: Bool, insecure: Bool) {
            self.followRedirects = followRedirects
            self.insecure = insecure
        }

        func urlSession(
            _ session: URLSession,
            task: URLSessionTask,
            willPerformHTTPRedirection response: HTTPURLResponse,
            newRequest request: URLRequest,
            completionHandler: @escaping (URLRequest?) -> Void
        ) {
            // Re-apply the SSRF guard to the redirect target: a 3xx must not be
            // followed into a blocked host (loopback/link-local/private/.local).
            if let host = request.url?.host, MITMScriptHTTPClient.isBlockedHost(host) {
                completionHandler(nil)
                return
            }
            // nil → don't follow: the 3xx response itself is returned to the
            // caller (manual redirect handling).
            completionHandler(followRedirects ? request : nil)
        }

        func urlSession(
            _ session: URLSession,
            didReceive challenge: URLAuthenticationChallenge,
            completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
        ) {
            // Mirrors SubscriptionFetcher's insecure delegate: accept the
            // server trust only when the caller opted in.
            if insecure,
               challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
               let trust = challenge.protectionSpace.serverTrust {
                completionHandler(.useCredential, URLCredential(trust: trust))
                return
            }
            completionHandler(.performDefaultHandling, nil)
        }
    }
}
