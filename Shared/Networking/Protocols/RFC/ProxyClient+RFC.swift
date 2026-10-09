//
//  ProxyClient+RFC.swift
//  Anywhere
//
//  Created by NodePassProject on 9/11/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "ProxyClient+RFC")

extension ProxyClient {
    func connectWithRFC(_ request: ProxyRequest) async throws -> ProxyConnection {
        guard case .rfc(let rfc) = configuration.outbound else {
            throw AnywhereError.proxy(.rfc, .invalidConfiguration(detail: "RFC outbound expected"))
        }

        guard request.network == .tcp else {
            throw AnywhereError.proxy(.rfc, .unsupported(feature: "UDP over CONNECT"))
        }

        let initialData = request.initialData
        let authority = RFCProtocol.authority(host: request.host, port: request.port)
        let credentials = rfc.basicCredentials
        
        let chained = tunnel != nil
        let pool = chained ? nil : RFCMultiplexerRegistry.shared.pool(for: configuration)
        if let pool, let warm = pool.reserveWarmSession() {
            do {
                return try await openRFCTunnel(
                    on: warm, onEnd: pool.idleClockHook(for: warm), authority: authority,
                    credentials: credentials, initialData: initialData
                )
            } catch {
                guard Self.isRetryableRFCSessionFailure(error) else { throw error }
            }
        }

        let dialed = try await dialRFC(securityLayer: rfc.securityLayer)
        guard !isCancelled else {
            dialed.connection.cancel()
            throw AnywhereError.transport(.terminated)
        }

        switch dialed.version {
        case .http2:
            guard let pool else {
                guard chained else {
                    dialed.connection.cancel()
                    throw AnywhereError.proxy(.rfc, .notReady)
                }
                return try await openDedicatedRFCTunnel(
                    over: dialed.connection, authority: authority,
                    credentials: credentials, initialData: initialData
                )
            }
            guard let multiplexer = try await pool.adopt(dialed.connection) else {
                dialed.connection.cancel()
                throw AnywhereError.transport(.terminated)
            }
            return try await openRFCTunnel(
                on: multiplexer, onEnd: pool.idleClockHook(for: multiplexer), authority: authority,
                credentials: credentials, initialData: initialData
            )

        case .http11:
            do {
                let tunnel = try await RFCHTTP11Tunnel.establish(
                    over: dialed.connection, authority: authority, credentials: credentials
                )
                guard !isCancelled else {
                    tunnel.cancel()
                    throw AnywhereError.transport(.terminated)
                }
                if let initialData, !initialData.isEmpty {
                    try await tunnel.send(initialData)
                }
                return tunnel
            } catch {
                dialed.connection.cancel()
                throw error
            }
        }
    }

    // MARK: - Dial

    private struct RFCDial {
        let connection: ProxyConnection
        let version: RFCProtocol.Version
        let negotiatedALPN: String
    }
    
    private func dialRFC(securityLayer: GenericSecurityLayer) async throws -> RFCDial {
        switch securityLayer {
        case .tls(let tlsConfig):
            let negotiating = TLSConfiguration(
                serverName: tlsConfig.serverName,
                alpn: tlsConfig.alpn ?? RFCProtocol.defaultALPN,
                minVersion: tlsConfig.minVersion,
                maxVersion: tlsConfig.maxVersion,
                echEnabled: tlsConfig.echEnabled,
                echConfig: tlsConfig.echConfig,
                fingerprint: tlsConfig.fingerprint,
                insecureSkipVerify: tlsConfig.insecureSkipVerify
            )
            let tlsClient = TLSClient(configuration: negotiating)
            let record: TLSRecordConnection
            if let tunnel = self.tunnel {
                record = try await tlsClient.connect(overTunnel: tunnel)
            } else {
                record = try await tlsClient.connect(host: directDialHost, port: configuration.serverPort)
            }
            let alpn = record.negotiatedALPN
            return RFCDial(
                connection: TLSProxyConnection(tlsConnection: record),
                version: RFCProtocol.Version(negotiatedALPN: alpn),
                negotiatedALPN: alpn
            )

        case .none:
            let transport: any ByteTransport
            if let tunnel = self.tunnel {
                transport = TunneledTransport(tunnel: tunnel)
            } else {
                let tcp = TCPTransport(
                    host: directDialHost,
                    port: configuration.serverPort,
                    resolution: .proxies
                )
                try await tcp.connect()
                transport = tcp
            }
            return RFCDial(
                connection: DirectProxyConnection(transport: transport),
                version: .http11,
                negotiatedALPN: ""
            )
        }
    }

    // MARK: - HTTP/2 tunnel
    
    private func openRFCTunnel(
        on multiplexer: RFCHTTP2Multiplexer,
        onEnd: @escaping @Sendable () -> Void,
        authority: String,
        credentials: String?,
        initialData: Data?
    ) async throws -> ProxyConnection {
        let stream = try await multiplexer.openTunnel(
            authority: authority,
            credentials: credentials,
            onEnd: onEnd
        )
        guard !isCancelled else {
            stream.cancel()
            throw AnywhereError.transport(.terminated)
        }
        if let initialData, !initialData.isEmpty {
            do {
                try await stream.send(initialData)
            } catch {
                stream.cancel()
                throw error
            }
        }
        return stream
    }
    
    private func openDedicatedRFCTunnel(
        over connection: ProxyConnection,
        authority: String,
        credentials: String?,
        initialData: Data?
    ) async throws -> ProxyConnection {
        let multiplexer = RFCHTTP2Multiplexer(inner: connection)
        _ = multiplexer.tryReserveStream()
        do {
            try await multiplexer.start()
            return try await openRFCTunnel(
                on: multiplexer,
                onEnd: { [weak multiplexer] in multiplexer?.close(error: nil) },
                authority: authority,
                credentials: credentials,
                initialData: initialData
            )
        } catch {
            multiplexer.close(error: error)
            throw error
        }
    }

    // MARK: - Retry classification
    
    private static func isRetryableRFCSessionFailure(_ error: Error) -> Bool {
        guard let anywhereError = error as? AnywhereError else { return true }
        guard case .proxy(_, let detail) = anywhereError else { return true }
        switch detail {
        case .tunnelRejected, .authenticationRejected, .authenticationRequired, .unsupported:
            return false
        default:
            return true
        }
    }
}
