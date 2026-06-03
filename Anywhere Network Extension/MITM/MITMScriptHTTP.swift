//
//  MITMScriptHTTP.swift
//  Anywhere
//
//  Created by NodePassProject on 6/2/26.
//

import Foundation

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
        timeout: TimeInterval,
        completion: @escaping (Result<Response, Error>) -> Void
    ) {
        // No host-level SSRF filtering: Anywhere.http may reach any address,
        // including loopback / LAN / link-local. This is an intentional
        // capability for rule sets that talk to local or on-network services;
        // URLSession performs DNS resolution and connects.
        let delegate = SessionDelegate(
            followRedirects: followRedirects,
            insecure: insecure,
            maxBytes: maxBytes,
            completion: completion
        )
        // The session strongly retains the delegate, and the running task
        // retains the session, until the terminal `didCompleteWithError`
        // callback calls `finishTasksAndInvalidate` — so nothing here needs to
        // outlive the call. Creating the session and resuming the task are
        // non-blocking, so this runs inline on the caller's queue.
        let configuration = URLSessionConfiguration.ephemeral
        // `request.timeoutInterval` (set by the caller) bounds *inactivity*: a
        // slow-drip server that dribbles a byte before each interval elapses
        // never trips it, so a fetch could outlive its documented `timeout` and
        // park the script's connection up to the engine's idle watchdog.
        // `timeoutIntervalForResource` is a wall-clock cap on total duration;
        // each fetch has its own ephemeral session, so it is effectively
        // per-request. Both are set to the same clamped `timeout`.
        configuration.timeoutIntervalForResource = timeout
        let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
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
            // Only follow http(s) redirects with a host. There is no host-level
            // SSRF filtering — Anywhere.http may reach any address (see
            // ``send``); fail closed only on a target that isn't a parseable
            // http(s) URL with a host, since URLSession can't act on it anyway.
            guard let url = request.url,
                  let scheme = url.scheme?.lowercased(),
                  scheme == "http" || scheme == "https",
                  url.host != nil else {
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
