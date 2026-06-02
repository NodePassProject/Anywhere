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
