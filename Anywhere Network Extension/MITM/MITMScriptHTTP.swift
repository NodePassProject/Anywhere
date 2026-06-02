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

    // MARK: - Global in-flight byte budget

    /// Ceiling on response-body bytes buffered across **all** in-flight
    /// ``Anywhere/http`` fetches at once. The per-request `maxBytes` cap
    /// (``MITMScriptEngine``'s 4 MiB) bounds a single response; this bounds
    /// their *sum*, so the per-invocation (4 / 16) and global (32) concurrency
    /// caps can't aggregate past the Network Extension's ~50 MiB budget —
    /// 32 concurrent × 4 MiB = 128 MiB without it. ``SessionDelegate`` enforces
    /// it as bytes stream in: a chunk that would push the running total over the
    /// budget cancels the fetch that received it
    /// (``ClientError/globalBudgetExceeded``) rather than risking an OOM-kill of
    /// the whole tunnel. Sized to the script engine's soft typed-array budget so
    /// the two MITM memory pools stay aligned, and ≥ one full per-request cap so
    /// any single fetch can still complete.
    static let maxGlobalInFlightBytes: Int = 16 * 1024 * 1024

    private static let inFlightLock = UnfairLock()
    private static var inFlightBytes = 0

    /// Reserves `count` bytes against the global budget, returning false — and
    /// reserving nothing — when the reservation would exceed it.
    private static func reserveInFlight(_ count: Int) -> Bool {
        inFlightLock.lock(); defer { inFlightLock.unlock() }
        guard inFlightBytes + count <= maxGlobalInFlightBytes else { return false }
        inFlightBytes += count
        return true
    }

    /// Returns `count` previously-reserved bytes to the budget. Clamped at 0 so
    /// a double release can't drive the counter negative and strand capacity.
    private static func releaseInFlight(_ count: Int) {
        guard count > 0 else { return }
        inFlightLock.lock(); defer { inFlightLock.unlock() }
        inFlightBytes = max(0, inFlightBytes - count)
    }

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

    /// Sends `request` and calls `completion` exactly once, on the session's
    /// serial delegate queue. `followRedirects` chooses whether 3xx are
    /// followed or returned as-is; `insecure` accepts self-signed server
    /// certificates (the caller gates this to the global Allow-Insecure
    /// setting); `maxBytes` caps the response body (larger →
    /// ``ClientError/responseTooLarge``).
    ///
    /// The body cap is enforced **as the response streams**, not after the
    /// fact. The buffering `completionHandler` convenience task materialises
    /// the entire body in memory before handing it back, so a size check there
    /// only fires once the bytes are already resident — a large, slow, or
    /// hostile response (including a gzip bomb `URLSession` transparently
    /// inflates) could pressure the Network Extension's ~50 MiB budget and
    /// OOM-kill the tunnel before the cap could reject it. The delegate below
    /// instead tallies bytes per chunk and cancels the task the moment the
    /// running total crosses `maxBytes`, so peak memory stays near the cap.
    func send(
        _ request: URLRequest,
        followRedirects: Bool,
        insecure: Bool,
        maxBytes: Int,
        completion: @escaping (Result<Response, Error>) -> Void
    ) {
        let delegate = SessionDelegate(
            followRedirects: followRedirects,
            insecure: insecure,
            maxBytes: maxBytes,
            completion: completion
        )
        // The session strongly retains the delegate, and the running task
        // retains the session, until the terminal `didCompleteWithError`
        // callback calls `finishTasksAndInvalidate` — so nothing here needs to
        // outlive the call.
        let session = URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
        session.dataTask(with: request).resume()
    }

    /// Per-request delegate. Applies the redirect + TLS-trust policy, caps the
    /// response body **as it streams** (cancelling the task the moment the
    /// running total crosses `maxBytes`), and delivers the result exactly once
    /// via `completion`. The session retains it until `finishTasksAndInvalidate`,
    /// which the terminal `didCompleteWithError` callback triggers.
    ///
    /// All callbacks for one session arrive on the session's serial delegate
    /// queue (`delegateQueue: nil` → a private serial queue, and there is one
    /// task per session), so the mutable accumulator/response/flags below are
    /// touched serially and need no extra locking.
    private final class SessionDelegate: NSObject, URLSessionDataDelegate {
        private let followRedirects: Bool
        private let insecure: Bool
        private let maxBytes: Int
        private let completion: (Result<Response, Error>) -> Void

        /// The final response head (after any followed redirects).
        private var response: HTTPURLResponse?
        /// Body bytes accumulated so far, bounded by ``maxBytes``.
        private var buffer = Data()
        /// Bytes this fetch has reserved against the shared global in-flight
        /// budget; released in full when the task completes.
        private var reservedBytes = 0
        /// The error to deliver when we cancel the task ourselves — for crossing
        /// the per-fetch ``maxBytes`` cap or the global byte budget — so the
        /// cancellation surfaced in `didCompleteWithError` reports that rather
        /// than a transport error. nil when the task ended on its own.
        private var cancelReason: ClientError?
        /// Guards the single ``completion`` delivery.
        private var finished = false

        init(
            followRedirects: Bool,
            insecure: Bool,
            maxBytes: Int,
            completion: @escaping (Result<Response, Error>) -> Void
        ) {
            self.followRedirects = followRedirects
            self.insecure = insecure
            self.maxBytes = maxBytes
            self.completion = completion
        }

        /// Delivers `completion` at most once.
        private func finish(_ result: Result<Response, Error>) {
            guard !finished else { return }
            finished = true
            completion(result)
        }

        // MARK: Response head

        func urlSession(
            _ session: URLSession,
            dataTask: URLSessionDataTask,
            didReceive response: URLResponse,
            completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
        ) {
            // The final response after any followed redirects. Reset any bytes
            // a prior response on this task delivered so `buffer` reflects only
            // the body we hand back.
            buffer.removeAll(keepingCapacity: false)
            self.response = response as? HTTPURLResponse
            // Early reject: when the server already declares a body larger than
            // the cap, fail before downloading a single body byte. A missing /
            // unknown length is -1, which never trips this. (The per-chunk
            // check below is the real guard — `expectedContentLength` reflects
            // the on-the-wire size, which `URLSession` may transparently
            // inflate past the cap after decompression.)
            if response.expectedContentLength >= 0,
               response.expectedContentLength > Int64(maxBytes) {
                cancelReason = .responseTooLarge(maxBytes)
                completionHandler(.cancel)
                return
            }
            completionHandler(.allow)
        }

        // MARK: Body chunks

        func urlSession(
            _ session: URLSession,
            dataTask: URLSessionDataTask,
            didReceive data: Data
        ) {
            guard cancelReason == nil else { return }
            // Reserve against the shared global budget before holding the bytes,
            // so the sum buffered across every in-flight fetch stays bounded.
            // A reservation that would overflow the budget cancels this fetch
            // (the prior reservations release as their fetches finish, so the
            // script can retry).
            guard MITMScriptHTTPClient.reserveInFlight(data.count) else {
                cancelReason = .globalBudgetExceeded(MITMScriptHTTPClient.maxGlobalInFlightBytes)
                buffer.removeAll(keepingCapacity: false)
                dataTask.cancel()
                return
            }
            reservedBytes += data.count
            buffer.append(data)
            if buffer.count > maxBytes {
                // Per-fetch cap crossed mid-stream: stop the download now rather
                // than let this one body grow unbounded. Drop what we buffered
                // and cancel; the cancellation surfaces in `didCompleteWithError`,
                // where `cancelReason` maps it to `responseTooLarge`. The global
                // reservation is released there too.
                cancelReason = .responseTooLarge(maxBytes)
                buffer.removeAll(keepingCapacity: false)
                dataTask.cancel()
            }
        }

        // MARK: Completion

        func urlSession(
            _ session: URLSession,
            task: URLSessionTask,
            didCompleteWithError error: Error?
        ) {
            // Release this fetch's global reservation and tear the session down
            // (it retains the delegate until invalidation) so neither the byte
            // budget nor sessions accumulate. Runs on every exit path.
            defer {
                MITMScriptHTTPClient.releaseInFlight(reservedBytes)
                reservedBytes = 0
                session.finishTasksAndInvalidate()
            }
            if let cancelReason {
                finish(.failure(cancelReason))
                return
            }
            if let error {
                finish(.failure(error))
                return
            }
            guard let http = response ?? (task.response as? HTTPURLResponse) else {
                finish(.failure(ClientError.notHTTP))
                return
            }
            var headers: [(name: String, value: String)] = []
            headers.reserveCapacity(http.allHeaderFields.count)
            for (key, value) in http.allHeaderFields {
                guard let name = key as? String else { continue }
                headers.append((name: name, value: String(describing: value)))
            }
            finish(.success(Response(
                status: http.statusCode,
                headers: headers,
                body: buffer,
                finalURL: http.url?.absoluteString
            )))
        }

        // MARK: Redirect + TLS trust

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
            // Accept the server's trust only when the caller opted into
            // insecure mode; otherwise defer to the system's validation.
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
