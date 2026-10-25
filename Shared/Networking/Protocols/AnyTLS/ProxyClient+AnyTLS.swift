//
//  ProxyClient+AnyTLS.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation

extension ProxyClient {
    func connectWithAnyTLS(_ request: ProxyRequest) async throws -> ProxyConnection {
        guard let anytls = configuration.anytls, !anytls.password.isEmpty,
              let tlsConfig = anytls.tlsConfiguration else {
            throw AnywhereError.proxy(.anyTLS, .protocolViolation(detail: "AnyTLS password not set"))
        }

        let directHost = directDialHost
        let serverHost = configuration.serverAddress
        let directPort = configuration.serverPort
        let tunnel = self.tunnel
        let chain = undialedChain
        let useResolvedAddress = useResolvedAddressForDirectDial

        let dialOut: AnyTLSMultiplexerPool.DialOut = {
            try await ProxyClient.withChainTunnel(
                through: chain,
                to: (serverHost, directPort),
                useResolvedAddressForDirectDial: useResolvedAddress
            ) { chainTunnel in
                let tlsClient = TLSClient(configuration: tlsConfig)
                let tlsConnection: TLSRecordConnection
                if let tunnel = chainTunnel ?? tunnel {
                    tlsConnection = try await tlsClient.connect(overTunnel: tunnel)
                } else {
                    tlsConnection = try await tlsClient.connect(host: directHost, port: directPort)
                }
                return TLSProxyConnection(tlsConnection: tlsConnection)
            }
        }
        
        let stream: AnyTLSStream
        if tunnel != nil {
            let connection = try await dialOut()
            let multiplexer = AnyTLSMultiplexer(
                inner: connection,
                passwordHash: AnyTLSProtocol.passwordHash(anytls.password),
                padding: AnyTLSPaddingScheme.default
            )
            _ = multiplexer.tryReserveStream()
            await multiplexer.start()
            guard let opened = await multiplexer.openStream(onEnd: { [weak multiplexer] in
                multiplexer?.close(error: nil)
            }) else {
                multiplexer.close(error: nil)
                throw AnywhereError.proxy(.anyTLS, .connectionClosed(detail: "Failed to open AnyTLS stream"))
            }
            stream = opened
        } else {
            guard let pool = AnyTLSMultiplexerRegistry.shared.pool(for: configuration, dialOut: dialOut) else {
                throw AnywhereError.proxy(.anyTLS, .notReady)
            }
            stream = try await pool.acquireStream()
        }
        guard !isCancelled else {
            stream.cancel()
            throw AnywhereError.transport(.terminated)
        }

        switch request.network {
        case .tcp:
            var bootstrap = AnyTLSProtocol.encodeAddrPort(host: request.host, port: request.port)
            if let initialData = request.initialData, !initialData.isEmpty {
                bootstrap.append(initialData)
            }
            do {
                try await stream.send(bootstrap)
            } catch {
                stream.cancel()
                throw error
            }
            return stream

        case .udp:
            var bootstrap = AnyTLSProtocol.encodeAddrPort(host: AnyTLSProtocol.uotMagicAddress, port: 0)
            bootstrap.append(0x01)
            bootstrap.append(AnyTLSProtocol.encodeAddrPort(host: request.host, port: request.port))
            do {
                try await stream.send(bootstrap)
            } catch {
                stream.cancel()
                throw error
            }
            return AnyTLSUDPConnection(inner: stream)
        }
    }
}
