//
//  SampleData.swift
//  Anywhere
//
//  Sample data for Xcode Previews, shared between iOS and tvOS targets.
//

#if DEBUG

import Foundation

enum SampleData {

    static let subscriptionId = UUID()

    private static let dummyReality = XraySecurityLayer.reality(
        RealityConfiguration(serverName: "example.com", publicKey: Data(repeating: 0, count: 32), shortId: Data())
    )
    private static let dummyTLS = XraySecurityLayer.tls(
        TLSConfiguration(serverName: "example.com")
    )

    private static func sampleVLESS(
        flow: String? = nil,
        transport: XrayTransportLayer = .tcp,
        security: XraySecurityLayer
    ) -> Outbound {
        .vless(
            uuid: UUID(),
            encryption: "none",
            flow: flow,
            transport: transport,
            security: security
        )
    }

    // MARK: - Configurations

    static let configurations: [ProxyConfiguration] = [
        ProxyConfiguration(name: "Tokyo", serverAddress: "jp-tok.example.com", serverPort: 443,
                           outbound: sampleVLESS(flow: "xtls-rprx-vision", security: dummyReality)),
        ProxyConfiguration(name: "Seoul", serverAddress: "kr.example.com", serverPort: 443,
                           outbound: sampleVLESS(
                               transport: .ws(WebSocketConfiguration(host: "kr.example.com", path: "/")),
                               security: dummyTLS)),
        ProxyConfiguration(name: "US - New York", serverAddress: "us-ny.example.com", serverPort: 443, subscriptionId: subscriptionId,
                           outbound: sampleVLESS(flow: "xtls-rprx-vision", security: dummyReality)),
        ProxyConfiguration(name: "US - Los Angeles", serverAddress: "us-la.example.com", serverPort: 443, subscriptionId: subscriptionId,
                           outbound: sampleVLESS(flow: "xtls-rprx-vision", security: dummyReality)),
        ProxyConfiguration(name: "JP - Tokyo", serverAddress: "jp-tok.example.net", serverPort: 443, subscriptionId: subscriptionId,
                           outbound: sampleVLESS(
                               transport: .ws(WebSocketConfiguration(host: "jp-tok.example.net", path: "/")),
                               security: dummyTLS)),
        ProxyConfiguration(name: "DE - Frankfurt", serverAddress: "de-fra.example.net", serverPort: 443, subscriptionId: subscriptionId,
                           outbound: sampleVLESS(
                               transport: .httpUpgrade(HTTPUpgradeConfiguration(host: "de-fra.example.net", path: "/")),
                               security: dummyTLS)),
        ProxyConfiguration(name: "SG - Singapore", serverAddress: "sg.example.net", serverPort: 443, subscriptionId: subscriptionId,
                           outbound: sampleVLESS(
                               transport: .xhttp(XHTTPConfiguration(host: "sg.example.net", path: "/")),
                               security: dummyReality)),
    ]

    // MARK: - Subscription

    static let subscription = Subscription(
        id: subscriptionId,
        name: "Subscription",
        url: "https://example.com/subscribe"
    )

    // MARK: - Latency Results

    static let latencyResults: [UUID: LatencyResult] = [
        configurations[0].id: .success(85),
        configurations[1].id: .success(142),
        configurations[2].id: .success(210),
        configurations[3].id: .success(450),
        configurations[4].id: .success(620),
        configurations[5].id: .failed,
        configurations[6].id: .testing,
    ]

    // MARK: - Chains

    static let chains: [ProxyChain] = [
        ProxyChain(name: "Relay", proxyIds: [configurations[0].id, configurations[2].id]),
        ProxyChain(name: "Triple Hop", proxyIds: [configurations[1].id, configurations[4].id, configurations[6].id]),
    ]

    static let chainLatencyResults: [UUID: LatencyResult] = [
        chains[0].id: .success(295),
        chains[1].id: .success(580),
    ]

    // MARK: - Convenience

    static var standaloneConfigurations: [ProxyConfiguration] {
        configurations.filter { $0.subscriptionId == nil }
    }

    static var subscriptionConfigurations: [ProxyConfiguration] {
        configurations.filter { $0.subscriptionId == subscriptionId }
    }
}

#endif
