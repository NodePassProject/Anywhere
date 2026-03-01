//
//  SubscriptionFetcher.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

struct SubscriptionFetcher {
    struct Result {
        let configurations: [VLESSConfiguration]
        let name: String?
        let upload: Int64?
        let download: Int64?
        let total: Int64?
        let expire: Date?
    }

    enum FetchError: Error, LocalizedError {
        case invalidURL
        case noConfigurations
        case networkError(String)

        var errorDescription: String? {
            switch self {
            case .invalidURL:
                return "Invalid subscription URL."
            case .noConfigurations:
                return "No valid VLESS configurations found in subscription."
            case .networkError(let message):
                return "Network error: \(message)"
            }
        }
    }

    static func fetch(url urlString: String) async throws -> Result {
        guard let url = URL(string: urlString) else {
            throw FetchError.invalidURL
        }

        var request = URLRequest(url: url)
        request.setValue("Anywhere/1.0", forHTTPHeaderField: "User-Agent")

        // Use a delegate that accepts untrusted certificates — subscription
        // servers commonly run on IP addresses with self-signed certs.
        let delegate = InsecureSessionDelegate()
        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await URLSession(configuration: .default, delegate: delegate, delegateQueue: nil).data(for: request)
        } catch {
            throw FetchError.networkError(error.localizedDescription)
        }

        let httpResponse = response as? HTTPURLResponse

        // Parse response headers
        let profileTitle = parseProfileTitle(from: httpResponse)
        let userInfo = parseSubscriptionUserInfo(from: httpResponse)

        // Decode body: try base64 first, fall back to raw UTF-8
        let bodyString: String
        if let decoded = Data(base64Encoded: data, options: .ignoreUnknownCharacters),
           let decodedString = String(data: decoded, encoding: .utf8),
           decodedString.contains("vless://") {
            bodyString = decodedString
        } else if let rawString = String(data: data, encoding: .utf8) {
            bodyString = rawString
        } else {
            throw FetchError.noConfigurations
        }

        // Parse VLESS lines
        let configurations = bodyString
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { $0.hasPrefix("vless://") }
            .compactMap { try? VLESSConfiguration.parse(url: $0) }

        guard !configurations.isEmpty else {
            throw FetchError.noConfigurations
        }

        return Result(
            configurations: configurations,
            name: profileTitle,
            upload: userInfo.upload,
            download: userInfo.download,
            total: userInfo.total,
            expire: userInfo.expire
        )
    }

    // MARK: - Header Parsing

    private static func parseProfileTitle(from response: HTTPURLResponse?) -> String? {
        guard let value = response?.value(forHTTPHeaderField: "profile-title") else { return nil }
        // Supports base64: prefix
        if value.hasPrefix("base64:") {
            let encoded = String(value.dropFirst("base64:".count))
            if let data = Data(base64Encoded: encoded),
               let decoded = String(data: data, encoding: .utf8) {
                return decoded
            }
        }
        return value
    }

    private static func parseSubscriptionUserInfo(from response: HTTPURLResponse?) -> (upload: Int64?, download: Int64?, total: Int64?, expire: Date?) {
        guard let value = response?.value(forHTTPHeaderField: "subscription-userinfo") else {
            return (nil, nil, nil, nil)
        }

        var upload: Int64?
        var download: Int64?
        var total: Int64?
        var expire: Date?

        // Format: upload=X; download=Y; total=Z; expire=T
        for part in value.split(separator: ";") {
            let trimmed = part.trimmingCharacters(in: .whitespaces)
            let keyValue = trimmed.split(separator: "=", maxSplits: 1)
            guard keyValue.count == 2 else { continue }
            let key = keyValue[0].trimmingCharacters(in: .whitespaces)
            let val = keyValue[1].trimmingCharacters(in: .whitespaces)

            switch key {
            case "upload":
                upload = Int64(val)
            case "download":
                download = Int64(val)
            case "total":
                total = Int64(val)
            case "expire":
                if let timestamp = TimeInterval(val) {
                    expire = Date(timeIntervalSince1970: timestamp)
                }
            default:
                break
            }
        }

        return (upload, download, total, expire)
    }
}

// MARK: - URLSession delegate that accepts self-signed certificates

private final class InsecureSessionDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let trust = challenge.protectionSpace.serverTrust {
            return (.useCredential, URLCredential(trust: trust))
        }
        return (.performDefaultHandling, nil)
    }
}
