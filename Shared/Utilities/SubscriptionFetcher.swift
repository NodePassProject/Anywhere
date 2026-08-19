//
//  SubscriptionFetcher.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "SubscriptionFetcher")

nonisolated struct SubscriptionFetcher {
    struct Result {
        let configurations: [ProxyConfiguration]
        let name: String?
        let upload: Int64?
        let download: Int64?
        let total: Int64?
        let expire: Date?
        let iconLight: Data?
        let iconDark: Data?
    }

    static func fetch(url urlString: String) async throws -> Result {
        guard let url = URL(string: urlString) else {
            throw AnywhereError.subscription(.invalidURL)
        }

        var request = URLRequest(url: url)
        request.setValue("Anywhere", forHTTPHeaderField: "User-Agent")
        if AWCore.getRemnawaveHWIDEnabled() {
            request.setValue(AWCore.getRemnawaveHWID(), forHTTPHeaderField: "x-hwid")
        }

        let allowInsecure = AWCore.getAllowInsecure()
        let (data, response): (Data, URLResponse)
        do {
            if let viaUpstream = try await fetchViaConfiguredDNS(request, allowInsecure: allowInsecure) {
                (data, response) = viaUpstream
            } else if allowInsecure {
                let session = URLSession(configuration: .default, delegate: InsecureSessionDelegate(), delegateQueue: nil)
                defer { session.finishTasksAndInvalidate() }
                (data, response) = try await session.data(for: request)
            } else {
                (data, response) = try await URLSession.shared.data(for: request)
            }
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as URLError where error.code == .cancelled {
            throw error
        } catch {
            throw AnywhereError.subscription(.fetchFailed(underlying: error))
        }

        let httpResponse = response as? HTTPURLResponse

        let profileTitle = parseProfileTitle(from: httpResponse)
        let userInfo = parseSubscriptionUserInfo(from: httpResponse)
        let iconLight = parseIcon(from: httpResponse, field: "aw-icon-light")
        let iconDark = parseIcon(from: httpResponse, field: "aw-icon-dark")

        let bodyString: String
        if let decoded = Data(base64Encoded: data, options: .ignoreUnknownCharacters),
           let decodedString = String(data: decoded, encoding: .utf8),
           ProxyConfiguration.parsableURLPrefixes.contains(where: { decodedString.contains($0) }) {
            bodyString = decodedString
        } else if let rawString = String(data: data, encoding: .utf8) {
            bodyString = rawString
        } else {
            throw AnywhereError.subscription(.noConfigurations)
        }

        if bodyString.contains("proxies:") {
            let result = try ClashProxyParser.parse(yaml: bodyString)
            guard !result.configurations.isEmpty else {
                throw AnywhereError.subscription(.noConfigurations)
            }
            return Result(
                configurations: result.configurations,
                name: profileTitle,
                upload: userInfo.upload,
                download: userInfo.download,
                total: userInfo.total,
                expire: userInfo.expire,
                iconLight: iconLight,
                iconDark: iconDark
            )
        }

        let configurations = bodyString
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { ProxyConfiguration.canParseURL($0) }
            .compactMap { try? ProxyConfiguration.parse(url: $0) }

        guard !configurations.isEmpty else {
            throw AnywhereError.subscription(.noConfigurations)
        }

        return Result(
            configurations: configurations,
            name: profileTitle,
            upload: userInfo.upload,
            download: userInfo.download,
            total: userInfo.total,
            expire: userInfo.expire,
            iconLight: iconLight,
            iconDark: iconDark
        )
    }

    // MARK: - Configured DNS
    
    private static func fetchViaConfiguredDNS(_ request: URLRequest, allowInsecure: Bool) async throws -> (Data, URLResponse)? {
        let upstream = AWCore.getSubscriptionDNSUpstream()
        guard !upstream.isSystem else { return nil }

        let result = try await ResolvedHostFetcher.fetch(request, allowInsecure: allowInsecure) { host in
            try await DNSUpstreamClient.resolve(host, via: upstream).first
        }
        return (result.data, result.response)
    }

    // MARK: - Header Parsing

    private static func parseProfileTitle(from response: HTTPURLResponse?) -> String? {
        guard let value = response?.value(forHTTPHeaderField: "profile-title") else { return nil }
        let decoded: String
        if value.hasPrefix("base64:") {
            let encoded = String(value.dropFirst("base64:".count))
            if let data = Data(base64Encoded: encoded),
               let utf8 = String(data: data, encoding: .utf8) {
                decoded = utf8
            } else {
                decoded = value
            }
        } else {
            decoded = value
        }
        let trimmed = decoded.trimmingCharacters(in: .whitespaces)
        return trimmed.isEmpty ? nil : decoded
    }

    private static func parseIcon(from response: HTTPURLResponse?, field: String) -> Data? {
        guard let value = response?.value(forHTTPHeaderField: field) else { return nil }
        return Data(iconBase64: value)
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
            let valueString = keyValue[1].trimmingCharacters(in: .whitespaces)

            switch key {
            case "upload":
                upload = Int64(valueString)
            case "download":
                download = Int64(valueString)
            case "total":
                total = Int64(valueString)
            case "expire":
                if let timestamp = TimeInterval(valueString) {
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

nonisolated private final class InsecureSessionDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let trust = challenge.protectionSpace.serverTrust {
            return (.useCredential, URLCredential(trust: trust))
        }
        return (.performDefaultHandling, nil)
    }
}
