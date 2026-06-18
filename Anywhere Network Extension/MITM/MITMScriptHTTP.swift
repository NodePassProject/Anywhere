//
//  MITMScriptHTTP.swift
//  Anywhere
//
//  Created by NodePassProject on 6/2/26.
//

import Foundation

/// Outbound HTTP for the Anywhere.http script API. Requests go out as the NE's own URLSession
/// traffic, which the kernel keeps out of the managed tunnel. Each call gets its own ephemeral
/// session for independent redirect/TLS policy and no shared cookie jar.
final class MITMScriptHTTPClient {
    static let shared = MITMScriptHTTPClient()
    private init() {}

    // MARK: - Global in-flight byte budget

    /// Ceiling on response bytes buffered across all in-flight fetches; without it, concurrent
    /// fetches (up to 32 × 4 MiB) could far exceed the NE's ~50 MiB budget.
    static let maxGlobalInFlightBytes: Int = 16 * 1024 * 1024

    private static let inFlightLock = UnfairLock()
    private static var inFlightBytes = 0

    private static func reserveInFlight(_ count: Int) -> Bool {
        inFlightLock.lock(); defer { inFlightLock.unlock() }
        guard inFlightBytes + count <= maxGlobalInFlightBytes else { return false }
        inFlightBytes += count
        return true
    }

    /// Clamped at 0 to guard against double-release.
    private static func releaseInFlight(_ count: Int) {
        guard count > 0 else { return }
        inFlightLock.lock(); defer { inFlightLock.unlock() }
        inFlightBytes = max(0, inFlightBytes - count)
    }

    /// `finalURL` reflects the URL after any followed redirects.
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

    /// Calls `completion` exactly once. The body cap is enforced as the response streams, so a
    /// transparently-inflated gzip bomb is caught before being buffered in full.
    func send(
        _ request: URLRequest,
        followRedirects: Bool,
        insecure: Bool,
        maxBytes: Int,
        resourceTimeout: TimeInterval,
        completion: @escaping (Result<Response, Error>) -> Void
    ) {
        // Intentional: no SSRF filtering — local-service rule sets need loopback/LAN/link-local access.
        let delegate = SessionDelegate(
            followRedirects: followRedirects,
            insecure: insecure,
            maxBytes: maxBytes,
            completion: completion
        )
        let configuration = URLSessionConfiguration.ephemeral
        // Set to the engine's invocation ceiling so one fetch can't outlive the script's backstop.
        configuration.timeoutIntervalForResource = resourceTimeout
        let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
        session.dataTask(with: request).resume()
    }

    /// Callbacks arrive on the session's private serial queue, so mutable state needs no locking.
    private final class SessionDelegate: NSObject, URLSessionDataDelegate {
        private let followRedirects: Bool
        private let insecure: Bool
        private let maxBytes: Int
        private let completion: (Result<Response, Error>) -> Void

        private var response: HTTPURLResponse?
        private var buffer = Data()
        private var reservedBytes = 0
        /// Set before self-cancelling so `didCompleteWithError` reports the real cause, not a generic cancellation.
        private var cancelReason: ClientError?
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
            // Discard any prior redirect leg's bytes and return them to the global budget.
            buffer.removeAll(keepingCapacity: false)
            MITMScriptHTTPClient.releaseInFlight(reservedBytes)
            reservedBytes = 0
            self.response = response as? HTTPURLResponse
            // Content-Length is the on-wire (possibly compressed) size, so the per-chunk
            // check below remains the definitive guard.
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
            guard MITMScriptHTTPClient.reserveInFlight(data.count) else {
                cancelReason = .globalBudgetExceeded(MITMScriptHTTPClient.maxGlobalInFlightBytes)
                buffer.removeAll(keepingCapacity: false)
                dataTask.cancel()
                return
            }
            reservedBytes += data.count
            buffer.append(data)
            if buffer.count > maxBytes {
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
            // Fail closed on non-http(s)/host-less redirect targets only; no additional SSRF filtering.
            guard let url = request.url,
                  let scheme = url.scheme?.lowercased(),
                  scheme == "http" || scheme == "https",
                  url.host != nil else {
                completionHandler(nil)
                return
            }
            // nil tells URLSession to stop following; the 3xx is returned as-is.
            completionHandler(followRedirects ? request : nil)
        }

        func urlSession(
            _ session: URLSession,
            didReceive challenge: URLAuthenticationChallenge,
            completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
        ) {
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
