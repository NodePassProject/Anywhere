//
//  ProxyClient+XHTTP.swift
//  Anywhere
//
//  Created by NodePassProject on 9/13/26.
//

import Foundation

nonisolated extension ProxyClient {
    fileprivate static let sharedH2BringUpTimeout: TimeInterval = 30

    // MARK: - XHTTP Connection

    private enum XHTTPHTTPVersion {
        case http11
        case http2
        case http3

        var logName: String {
            switch self {
            case .http11:
                return "http/1.1"
            case .http2:
                return "h2"
            case .http3:
                return "h3"
            }
        }
    }

    private func decideXHTTPHTTPVersion(for xraySecurityLayer: XraySecurityLayer? = nil) -> XHTTPHTTPVersion {
        let security = xraySecurityLayer ?? configuration.xraySecurityLayer
        if case .reality = security {
            return .http2
        }

        guard case .tls(let tlsConfig) = security else {
            return .http11
        }

        let alpn = tlsConfig.alpn ?? []
        guard alpn.count == 1 else {
            return .http2
        }

        switch alpn[0].lowercased() {
        case "http/1.1":
            return .http11
        case "h3":
            return .http3
        default:
            return .http2
        }
    }

    private func sanitizedXHTTPTLSConfiguration(
        from base: TLSConfiguration,
        httpVersion: XHTTPHTTPVersion
    ) -> TLSConfiguration {
        let sanitizedALPN: [String]?

        switch httpVersion {
        case .http11:
            sanitizedALPN = ["http/1.1"]
        case .http2:
            if let configuredALPN = base.alpn {
                let filtered = configuredALPN.filter {
                    $0.caseInsensitiveCompare("h2") == .orderedSame ||
                    $0.caseInsensitiveCompare("http/1.1") == .orderedSame
                }
                if filtered.isEmpty || (filtered.count == 1 && filtered[0].caseInsensitiveCompare("http/1.1") == .orderedSame) {
                    sanitizedALPN = ["h2", "http/1.1"]
                } else {
                    sanitizedALPN = filtered
                }
            } else {
                sanitizedALPN = nil
            }
        case .http3:
            sanitizedALPN = ["h3"]
        }

        return TLSConfiguration(
            serverName: base.serverName,
            alpn: sanitizedALPN,
            echEnabled: base.echEnabled,
            echConfig: base.echConfig,
            fingerprint: base.fingerprint
        )
    }

    func connectWithXHTTP(_ request: ProxyRequest) async throws -> ProxyConnection {
        guard case .xhttp(let xhttpConfig) = configuration.xrayTransportLayer else {
            throw AnywhereError.proxy(.xhttp, .invalidConfiguration(detail: "XHTTP transport specified but no XHTTP configuration"))
        }

        let httpVersion = decideXHTTPHTTPVersion()

        var resolvedMode: XHTTPMode
        if xhttpConfig.mode == .auto {
            if case .reality = configuration.xraySecurityLayer {
                resolvedMode = .streamOne
            } else {
                resolvedMode = .packetUp
            }
        } else {
            resolvedMode = xhttpConfig.mode
        }
        
        if let downloadSettings = xhttpConfig.downloadSettings {
            if resolvedMode == .streamOne { resolvedMode = .streamUp }
            let downloadHTTPVersion = decideXHTTPHTTPVersion(for: downloadSettings.xraySecurityLayer)
            return try await connectXHTTPDetached(
                xhttpConfig: xhttpConfig, downloadSettings: downloadSettings,
                mode: resolvedMode, sessionId: xhttpConfig.generateSessionID(),
                mainHTTPVersion: httpVersion, downloadHTTPVersion: downloadHTTPVersion,
                request: request
            )
        }

        let sessionId = (resolvedMode == .packetUp || resolvedMode == .streamUp) ? xhttpConfig.generateSessionID() : ""
        return try await connectXHTTPCombined(
            xhttpConfig: xhttpConfig, mode: resolvedMode, sessionId: sessionId,
            httpVersion: httpVersion, request: request
        )
    }

    // MARK: Combined XHTTP

    private func connectXHTTPCombined(
        xhttpConfig: XHTTPConfiguration,
        mode: XHTTPMode,
        sessionId: String,
        httpVersion: XHTTPHTTPVersion,
        request: ProxyRequest
    ) async throws -> ProxyConnection {
        let route = consumeMainXHTTPRoute()
        let needsUploadFactory = httpVersion == .http11 && (mode == .packetUp || mode == .streamUp)
        let uploadFactory = needsUploadFactory
            ? makeXHTTPUploadFactory(
                security: configuration.xraySecurityLayer,
                httpVersion: httpVersion,
                mode: mode,
                xmux: xhttpConfig.effectiveXMUX
            )
            : nil
        let xhttpConnection = try await dialXHTTPLeg(
            endpoint: mainXHTTPEndpoint(),
            httpVersion: httpVersion,
            route: route,
            xhttp: xhttpConfig,
            mode: mode,
            sessionId: sessionId,
            role: .combined,
            uploadFactory: uploadFactory
        )
        do {
            return try await performXHTTPSetup(xhttpConnection: xhttpConnection, request: request)
        } catch {
            xhttpConnection.cancel()
            throw error
        }
    }

    private func performXHTTPSetup(
        xhttpConnection: XHTTPConnection,
        request: ProxyRequest
    ) async throws -> ProxyConnection {
        try await xhttpConnection.performSetup()
        let xhttpProxyConnection = XHTTPProxyConnection(xhttpConnection: xhttpConnection)
        return try await sendVLESSProtocolHandshake(
            over: xhttpProxyConnection,
            request: request,
            supportsVision: self.transportSupportsVision
        )
    }

    // MARK: XHTTP up/download detach

    private func connectXHTTPDetached(
        xhttpConfig: XHTTPConfiguration,
        downloadSettings: XHTTPDownloadSettings,
        mode: XHTTPMode,
        sessionId: String,
        mainHTTPVersion: XHTTPHTTPVersion,
        downloadHTTPVersion: XHTTPHTTPVersion,
        request: ProxyRequest
    ) async throws -> ProxyConnection {
        let uploadRoute = consumeMainXHTTPRoute()
        let uploadLeg = try await dialXHTTPLeg(
            endpoint: mainXHTTPEndpoint(),
            httpVersion: mainHTTPVersion,
            route: uploadRoute,
            xhttp: xhttpConfig,
            mode: mode,
            sessionId: sessionId,
            role: .uploadOnly,
            uploadFactory: nil
        )
        let downloadLeg: XHTTPConnection
        do {
            downloadLeg = try await dialXHTTPLeg(
                endpoint: self.downloadXHTTPEndpoint(downloadSettings),
                httpVersion: downloadHTTPVersion,
                route: .direct,
                xhttp: downloadSettings.xhttp,
                mode: mode,
                sessionId: sessionId,
                role: .downloadOnly,
                uploadFactory: nil
            )
        } catch {
            uploadLeg.cancel()
            throw error
        }
        downloadLeg.attachUploadChannel(uploadLeg)
        do {
            return try await performXHTTPSetup(xhttpConnection: downloadLeg, request: request)
        } catch {
            downloadLeg.cancel()
            throw error
        }
    }

    // MARK: XHTTP leg factory

    private struct XHTTPEndpoint {
        let directHost: String
        let chainHost: String
        let serverName: String
        let port: UInt16
        let security: XraySecurityLayer
    }

    private enum XHTTPLegRoute {
        case direct
        case overTunnel(ProxyConnection)
        case buildChain([ProxyConfiguration])
    }

    private enum XHTTPDialedTransport {
        case byteStream(any ByteTransport)
        case http3(HTTP3Multiplexer)
    }

    private func mainXHTTPEndpoint() -> XHTTPEndpoint {
        XHTTPEndpoint(
            directHost: directDialHost,
            chainHost: configuration.serverAddress,
            serverName: configuration.xraySecurityLayer.serverName(fallback: configuration.serverAddress),
            port: configuration.serverPort,
            security: configuration.xraySecurityLayer
        )
    }

    private func downloadXHTTPEndpoint(_ downloadSettings: XHTTPDownloadSettings) -> XHTTPEndpoint {
        XHTTPEndpoint(
            directHost: downloadSettings.serverAddress,
            chainHost: downloadSettings.serverAddress,
            serverName: downloadSettings.xraySecurityLayer.serverName(fallback: downloadSettings.serverAddress),
            port: downloadSettings.serverPort,
            security: downloadSettings.xraySecurityLayer
        )
    }

    private func consumeMainXHTTPRoute() -> XHTTPLegRoute {
        if let takenTunnel = takeChainTunnel() {
            return .overTunnel(takenTunnel)
        }
        if let chain = configuration.chain, !chain.isEmpty {
            return .buildChain(chain)
        }
        return .direct
    }

    private func dialXHTTPLeg(
        endpoint: XHTTPEndpoint,
        httpVersion: XHTTPHTTPVersion,
        route: XHTTPLegRoute,
        xhttp: XHTTPConfiguration,
        mode: XHTTPMode,
        sessionId: String,
        role: XHTTPChannelRole,
        uploadFactory: (@Sendable () async throws -> any ByteTransport)?
    ) async throws -> XHTTPConnection {
        if httpVersion == .http3, case .direct = route {
            return try await acquirePooledH3(
                endpoint: endpoint, xmux: xhttp.effectiveXMUX, xhttp: xhttp,
                mode: mode, sessionId: sessionId, role: role
            )
        }

        if httpVersion == .http2, case .direct = route {
            return try await acquirePooledH2(
                endpoint: endpoint, xmux: xhttp.effectiveXMUX, xhttp: xhttp,
                mode: mode, sessionId: sessionId, role: role
            )
        }

        let transport = try await dialXHTTPTransport(endpoint: endpoint, httpVersion: httpVersion, route: route)
        let connection: XHTTPConnection
        switch transport {
        case .byteStream(let closures):
            connection = XHTTPConnection(
                download: closures, configuration: xhttp, mode: mode, sessionId: sessionId,
                useHTTP2: httpVersion == .http2, uploadConnectionFactory: uploadFactory
            )
        case .http3(let session):
            connection = XHTTPConnection(
                h3Multiplexer: session, configuration: xhttp, mode: mode, sessionId: sessionId
            )
        }
        connection.configureRole(role)
        return connection
    }

    private func acquirePooledH3(
        endpoint: XHTTPEndpoint,
        xmux: XHTTPXMUXMultiplexerConfiguration,
        xhttp: XHTTPConfiguration,
        mode: XHTTPMode,
        sessionId: String,
        role: XHTTPChannelRole
    ) async throws -> XHTTPConnection {
        let host = endpoint.directHost
        let port = endpoint.port
        let serverName = endpoint.serverName
        let key = "h3|\(host)|\(port)|\(serverName)"
        let manager = XHTTPXMUXMultiplexerRegistry.shared.manager(key: key, config: xmux) {
            { () async -> XHTTPXMUXMultiplexerPoolable? in
                HTTP3Multiplexer(host: host, port: port, serverName: serverName)
            }
        }
        guard let lease = await manager.acquire(), let session = lease.connection as? HTTP3Multiplexer else {
            throw AnywhereError.transport(.connectionFailed(endpoint: "\(host):\(port)", detail: "xmux H3 session acquisition failed"))
        }
        let connection = XHTTPConnection(
            h3Multiplexer: session, configuration: xhttp, mode: mode, sessionId: sessionId
        )
        connection.configureRole(role)
        connection.configureXMUXLease(lease)
        return connection
    }

    private func acquirePooledH2(
        endpoint: XHTTPEndpoint,
        xmux: XHTTPXMUXMultiplexerConfiguration,
        xhttp: XHTTPConfiguration,
        mode: XHTTPMode,
        sessionId: String,
        role: XHTTPChannelRole
    ) async throws -> XHTTPConnection {
        let host = endpoint.directHost
        let port = endpoint.port
        let security = endpoint.security
        let serverName = endpoint.serverName
        let key = "h2|\(host)|\(port)|\(serverName)|\(Self.xmuxSecurityKey(security))"
        let manager = XHTTPXMUXMultiplexerRegistry.shared.manager(key: key, config: xmux) {
            { () async -> XHTTPXMUXMultiplexerPoolable? in
                try? await ProxyClient.dialSharedH2(host: host, port: port, security: security)
            }
        }
        guard let lease = await manager.acquire(), let shared = lease.connection as? XHTTPH2Multiplexer else {
            throw AnywhereError.transport(.connectionFailed(endpoint: "\(host):\(port)", detail: "xmux H2 connection acquisition failed"))
        }
        let connection = XHTTPConnection(sharedH2: shared, configuration: xhttp, mode: mode, sessionId: sessionId)
        connection.configureRole(role)
        connection.configureXMUXLease(lease)
        return connection
    }
    
    private static func xmuxSecurityKey(_ security: XraySecurityLayer) -> String {
        switch security {
        case .none:
            return "none"
        case .tls(let tls):
            return "tls|\(tls.fingerprint.rawValue)|\(tls.echEnabled)|\(tls.echConfig ?? "")"
        case .reality(let reality):
            return "reality|\(reality.fingerprint.rawValue)|\(reality.publicKey.base64EncodedString())|\(reality.shortId.base64EncodedString())"
        }
    }

    private static func dialSharedH2(
        host: String,
        port: UInt16,
        security: XraySecurityLayer
    ) async throws -> XHTTPH2Multiplexer {
        func bringUp(_ transport: any ByteTransport, retaining object: (any Sendable)?) async throws -> XHTTPH2Multiplexer {
            let shared = XHTTPH2Multiplexer(transport: transport)
            if let object { shared.retain(object) }
            do {
                try await withDialDeadline(
                    .seconds(Self.sharedH2BringUpTimeout),
                    onExpiry: { shared.poolClose() },
                    error: {
                        AnywhereError.transport(
                            .timedOut(
                                .connect,
                                endpoint: "\(host):\(port)",
                                detail: "shared H2 settings")
                        )
                    }
                ) {
                    try await withTaskCancellationHandler {
                        try await shared.connect()
                    } onCancel: {
                        shared.poolClose()
                    }
                }
            } catch {
                shared.poolClose()
                throw error
            }
            return shared
        }
        switch security {
        case .none:
            let transport = TCPTransport(host: host, port: port, resolution: .proxies)
            try await transport.connect()
            return try await bringUp(transport, retaining: transport)
        case .tls(let tlsConfig):
            let h2TLS = TLSConfiguration(
                serverName: tlsConfig.serverName, alpn: ["h2", "http/1.1"],
                echEnabled: tlsConfig.echEnabled, echConfig: tlsConfig.echConfig, fingerprint: tlsConfig.fingerprint
            )
            let client = TLSClient(configuration: h2TLS)
            let connection = try await client.connect(host: host, port: port)
            return try await bringUp(TLSByteTransport(connection), retaining: client)
        case .reality(let realityConfig):
            let client = RealityClient(configuration: realityConfig)
            let connection = try await client.connect(host: host, port: port)
            return try await bringUp(TLSByteTransport(connection), retaining: client)
        }
    }

    private func dialXHTTPTransport(
        endpoint: XHTTPEndpoint,
        httpVersion: XHTTPHTTPVersion,
        route: XHTTPLegRoute
    ) async throws -> XHTTPDialedTransport {
        if httpVersion == .http3 {
            return try await dialXHTTPHTTP3Session(endpoint: endpoint, route: route)
        }
        switch route {
        case .direct:
            return try await dialXHTTPByteStream(
                host: endpoint.directHost,
                port: endpoint.port,
                security: endpoint.security,
                httpVersion: httpVersion,
                overTunnel: nil
            )
        case .overTunnel(let tunnel):
            return try await dialXHTTPByteStream(
                host: endpoint.chainHost,
                port: endpoint.port,
                security: endpoint.security,
                httpVersion: httpVersion,
                overTunnel: tunnel
            )
        case .buildChain(let chain):
            let hopNetworks = [ProxyNetwork](repeating: .tcp, count: chain.count)
            let tunnel = try await self.buildChainTunnel(chain: chain, index: 0, currentTunnel: nil, hopNetworks: hopNetworks)
            return try await dialXHTTPByteStream(
                host: endpoint.chainHost,
                port: endpoint.port,
                security: endpoint.security,
                httpVersion: httpVersion,
                overTunnel: tunnel
            )
        }
    }

    private func dialXHTTPByteStream(
        host: String,
        port: UInt16,
        security: XraySecurityLayer,
        httpVersion: XHTTPHTTPVersion,
        overTunnel: ProxyConnection?
    ) async throws -> XHTTPDialedTransport {
        switch security {
        case .none:
            if let tunnel = overTunnel {
                return .byteStream(TunneledTransport(tunnel: tunnel))
            } else {
                let transport = TCPTransport(host: host, port: port, resolution: .proxies)
                try await transport.connect()
                return .byteStream(transport)
            }
        case .tls(let tlsConfig):
            let client = TLSClient(configuration: sanitizedXHTTPTLSConfiguration(from: tlsConfig, httpVersion: httpVersion))
            let connection: TLSRecordConnection
            if let tunnel = overTunnel {
                connection = try await client.connect(overTunnel: tunnel)
            } else {
                connection = try await client.connect(host: host, port: port)
            }
            return .byteStream(TLSByteTransport(connection))
        case .reality(let realityConfig):
            let client = RealityClient(configuration: realityConfig)
            let connection: TLSRecordConnection
            if let tunnel = overTunnel {
                connection = try await client.connect(overTunnel: tunnel)
            } else {
                connection = try await client.connect(host: host, port: port)
            }
            return .byteStream(TLSByteTransport(connection))
        }
    }

    private func dialXHTTPHTTP3Session(
        endpoint: XHTTPEndpoint,
        route: XHTTPLegRoute
    ) async throws -> XHTTPDialedTransport {
        let makeSession: (String, QUICDatagramTransport?) -> XHTTPDialedTransport = { host, transport in
            .http3(HTTP3Multiplexer(host: host, port: endpoint.port, serverName: endpoint.serverName, transport: transport))
        }
        switch route {
        case .direct:
            return makeSession(endpoint.directHost, nil)
        case .overTunnel(let tunnel):
            return makeSession(endpoint.chainHost, ProxyConnectionDatagramTransport(connection: tunnel))
        case .buildChain(let chain):
            let hopNetworks = try Self.computeChainHopNetworks(chain: chain, lastDeliver: .udp).get()
            let tunnel = try await self.buildChainTunnel(chain: chain, index: 0, currentTunnel: nil, hopNetworks: hopNetworks)
            return makeSession(endpoint.chainHost, ProxyConnectionDatagramTransport(connection: tunnel))
        }
    }

    private func makeXHTTPUploadFactory(
        security: XraySecurityLayer,
        httpVersion: XHTTPHTTPVersion,
        mode: XHTTPMode,
        xmux: XHTTPXMUXMultiplexerConfiguration
    ) -> (@Sendable () async throws -> any ByteTransport) {
        let hasChain = (configuration.chain?.isEmpty == false)
        if mode == .packetUp, !hasChain {
            let endpoint = mainXHTTPEndpoint()
            let host = endpoint.directHost
            let port = endpoint.port
            let sec = endpoint.security
            let serverName = endpoint.serverName
            var uploadXMUX = xmux
            uploadXMUX.maxConcurrency = XHTTPXMUXMultiplexerRange(from: 1, to: 1)
            let key = "h1up|\(host)|\(port)|\(serverName)|\(Self.xmuxSecurityKey(sec))"
            let manager = XHTTPXMUXMultiplexerRegistry.shared.manager(key: key, config: uploadXMUX) {
                { () async -> XHTTPXMUXMultiplexerPoolable? in
                    await ProxyClient.dialH1UploadConnection(host: host, port: port, security: sec)
                }
            }
            return {
                try await ConnectionMetrics.$currentAttempt.withValue(nil) {
                    guard let lease = await manager.acquire(), let connection = lease.connection as? XHTTPH1Multiplexer else {
                        throw AnywhereError.transport(.connectionFailed(endpoint: "\(host):\(port)", detail: "xmux H1 upload acquisition failed"))
                    }
                    connection.adoptLease(lease)
                    return connection.sessionTransport
                }
            }
        }

        return { [weak self] in
            guard let self else {
                throw AnywhereError.transport(.terminated)
            }
            let route: XHTTPLegRoute
            if let chain = self.configuration.chain, !chain.isEmpty {
                route = .buildChain(chain)
            } else {
                route = .direct
            }
            let transport = try await ConnectionMetrics.$currentAttempt.withValue(nil) {
                try await self.dialXHTTPTransport(endpoint: self.mainXHTTPEndpoint(), httpVersion: httpVersion, route: route)
            }
            switch transport {
            case .byteStream(let closures):
                return closures
            case .http3:
                throw AnywhereError.proxy(.xhttp, .invalidConfiguration(detail: "HTTP/3 has no separate upload connection"))
            }
        }
    }

    private static func dialH1UploadConnection(
        host: String,
        port: UInt16,
        security: XraySecurityLayer
    ) async -> XHTTPH1Multiplexer? {
        func wrap(_ transport: any ByteTransport, retaining object: (any Sendable)?) -> XHTTPH1Multiplexer {
            let connection = XHTTPH1Multiplexer(transport: transport)
            if let object { connection.retain(object) }
            return connection
        }
        switch security {
        case .none:
            let transport = TCPTransport(host: host, port: port, resolution: .proxies)
            do {
                try await transport.connect()
            } catch {
                transport.cancel()
                return nil
            }
            return wrap(transport, retaining: transport)
        case .tls(let tlsConfig):
            let h1TLS = TLSConfiguration(
                serverName: tlsConfig.serverName, alpn: ["http/1.1"],
                echEnabled: tlsConfig.echEnabled, echConfig: tlsConfig.echConfig, fingerprint: tlsConfig.fingerprint
            )
            let client = TLSClient(configuration: h1TLS)
            guard let connection = try? await client.connect(host: host, port: port) else { return nil }
            return wrap(TLSByteTransport(connection), retaining: client)
        case .reality(let realityConfig):
            let client = RealityClient(configuration: realityConfig)
            guard let connection = try? await client.connect(host: host, port: port) else { return nil }
            return wrap(TLSByteTransport(connection), retaining: client)
        }
    }
}
