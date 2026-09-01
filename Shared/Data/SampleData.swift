//
//  SampleData.swift
//  Anywhere
//
//  Created by NodePassProject on 8/23/26.
//

#if DEBUG

import Foundation

nonisolated enum SampleData {

    static let subscriptionId = UUID()

    private static let dummyReality = XraySecurityLayer.reality(
        RealityConfiguration(serverName: "example.com", publicKey: Data(repeating: 0, count: 32), shortId: Data())
    )
    private static let dummyTLS = XraySecurityLayer.tls(
        TLSConfiguration(serverName: "example.com")
    )

    private static func sampleVLESS(
        flow: String? = nil,
        transport: XrayTransportLayer = .raw,
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
        ProxyConfiguration(
            name: "🇺🇸 New York",
            serverAddress: "us-ny.example.com",
            serverPort: 443,
            outbound: sampleVLESS(flow: "xtls-rprx-vision", security: dummyReality)
        ),
        ProxyConfiguration(
            name: "🇺🇸 Los Angeles",
            serverAddress: "us-la.example.com",
            serverPort: 443,
            outbound: sampleVLESS(flow: "xtls-rprx-vision", security: dummyReality)
        ),
        ProxyConfiguration(
            name: "🇯🇵 Tokyo",
            serverAddress: "jp-tok.example.net",
            serverPort: 443,
            outbound: sampleVLESS(
                transport: .ws(WebSocketConfiguration(host: "jp-tok.example.net", path: "/")),
                security: dummyTLS
            )
        ),
        ProxyConfiguration(
            name: "🇩🇪 Frankfurt",
            serverAddress: "de-fra.example.net",
            serverPort: 443,
            outbound: sampleVLESS(
                transport: .httpUpgrade(HTTPUpgradeConfiguration(host: "de-fra.example.net", path: "/")),
                security: dummyTLS
            )
        ),
        ProxyConfiguration(
            name: "🇫🇷 Paris",
            serverAddress: "fr-par.example.net",
            serverPort: 443,
            outbound: sampleVLESS(
                transport: .xhttp(XHTTPConfiguration(host: "fr-par.example.net", path: "/")),
                security: dummyReality
            )
        ),
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
    ]

    // MARK: - Chains

    static let chains: [ProxyChain] = [
        ProxyChain(name: "Relay", proxyIds: [configurations[0].id, configurations[2].id]),
        ProxyChain(name: "Triple Hop", proxyIds: [configurations[1].id, configurations[3].id, configurations[4].id]),
    ]

    static let chainLatencyResults: [UUID: LatencyResult] = [
        chains[0].id: .success(295),
        chains[1].id: .success(580),
    ]

    // MARK: - Connection Stats

    static let routes: [RouteTrafficEntry] = [
        RouteTrafficEntry(target: .proxy(configurations[0].id), bytesIn: 1_600_000_000, bytesOut: 280_000_000),
        RouteTrafficEntry(target: .proxy(configurations[2].id), bytesIn: 620_000_000, bytesOut: 94_000_000),
        RouteTrafficEntry(target: .proxy(configurations[3].id), bytesIn: 180_000_000, bytesOut: 26_000_000),
        RouteTrafficEntry(target: .direct, bytesIn: 240_000_000, bytesOut: 40_000_000),
    ]

    static let stats = StatsResponse(
        bytesIn: routes.reduce(0) { $0 + $1.bytesIn },
        bytesOut: routes.reduce(0) { $0 + $1.bytesOut },
        routes: routes,
        tcpConnectionCount: 5,
        udpConnectionCount: 64,
        memoryBytes: 31_000_000,
        wakeSeconds: 3 * 3600 + 24 * 60,
        sleepSeconds: 47 * 60,
        dialMs: 62,
        handshakeMs: 200,
        avgDialMs: 50,
        avgHandshakeMs: 150
    )

    static let uploadBytesPerSecond: Int64 = 1_200_000
    static let downloadBytesPerSecond: Int64 = 5_100_000

    // MARK: - Convenience

    static var standaloneConfigurations: [ProxyConfiguration] {
        configurations.filter { $0.subscriptionId == nil }
    }

    static var subscriptionConfigurations: [ProxyConfiguration] {
        configurations.filter { $0.subscriptionId == subscriptionId }
    }
}

#endif
