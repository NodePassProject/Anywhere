//
//  ProxyClient+AnyTLS.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "ProxyClient+AnyTLS")

extension ProxyClient {
    /// Connects through an AnyTLS server: TCP → TLS → AnyTLS handshake → stream + destination.
    /// AnyTLS mandates TLS (the password SHA256 is the first thing the server reads after the
    /// handshake); UDP rides a UoT stream opened to the `sp.v2.udp-over-tcp.arpa` magic FQDN.
    func connectWithAnyTLS(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?
    ) async throws -> ProxyConnection {
        logger.debug("[AnyTLS] connect cmd=\(command) dest=\(destinationHost):\(destinationPort) initialData=\(initialData?.count ?? 0)B chained=\(tunnel != nil)")
        guard case .anytls(let password, _, _, _, let securityLayer) = configuration.outbound, !password.isEmpty,
              let tlsConfig = securityLayer.tlsConfiguration else {
            logger.debug("[AnyTLS] reject: password not set")
            throw AnywhereError.proxy(.anyTLS, .protocolViolation(detail: "AnyTLS password not set"))
        }
        if command == .mux {
            logger.debug("[AnyTLS] reject: mux not supported")
            throw AnywhereError.proxy(.anyTLS, .protocolViolation(detail: "Mux is not supported with AnyTLS"))
        }
        logger.debug("[AnyTLS] sni=\(tlsConfig.serverName) alpn=\(tlsConfig.alpn?.joined(separator: ",") ?? "<none>") fp=\(tlsConfig.fingerprint.rawValue)")

        // Don't capture self in the dial closure: AnyTLSMultiplexerPool persists across ProxyClient instances.
        let directHost = directDialHost
        let directPort = configuration.serverPort
        let tunnel = self.tunnel

        let dialOut: AnyTLSMultiplexerPool.DialOut = {
            let tlsClient = TLSClient(configuration: tlsConfig)
            let tlsConnection: TLSRecordConnection
            if let tunnel {
                logger.debug("[AnyTLS] dialing TLS over chained tunnel")
                tlsConnection = try await tlsClient.connect(overTunnel: tunnel)
            } else {
                logger.debug("[AnyTLS] dialing TLS direct \(directHost):\(directPort)")
                tlsConnection = try await tlsClient.connect(host: directHost, port: directPort)
            }
            logger.debug("[AnyTLS] TLS handshake ok, version=\(tlsConnection.tlsVersion)")
            return TLSProxyConnection(tlsConnection: tlsConnection)
        }

        guard let pool = AnyTLSMultiplexerRegistry.shared.pool(for: configuration, dialOut: dialOut) else {
            logger.debug("[AnyTLS] AnyTLSMultiplexerRegistry returned nil pool (outbound type mismatch?)")
            throw AnywhereError.proxy(.anyTLS, .notReady)
        }

        let stream = try await pool.acquireStream()
        guard !isCancelled else {
            stream.cancel()
            throw AnywhereError.transport(.terminated)
        }
        logger.debug("[AnyTLS] stream opened sid=\(stream.sid) cmd=\(command)")

        switch command {
        case .tcp:
            // The first cmdPSH carries the destination; coalescing initialData into the
            // same send avoids an extra TLS record.
            var bootstrap = AnyTLSProtocol.encodeAddrPort(host: destinationHost, port: destinationPort)
            if let initialData, !initialData.isEmpty {
                bootstrap.append(initialData)
            }
            logger.debug("[AnyTLS] tcp bootstrap sid=\(stream.sid) bytes=\(bootstrap.count)")
            do {
                try await stream.send(bootstrap)
            } catch {
                logger.debug("[AnyTLS] tcp bootstrap failed sid=\(stream.sid): \(error.localizedDescription)")
                stream.cancel()
                throw error
            }
            return stream

        case .udp:
            // UoT bootstrap: magic-FQDN address, then [isConnect=1][realDest].
            var bootstrap = AnyTLSProtocol.encodeAddrPort(host: AnyTLSProtocol.uotMagicAddress, port: 0)
            bootstrap.append(0x01) // isConnect = true
            bootstrap.append(AnyTLSProtocol.encodeAddrPort(host: destinationHost, port: destinationPort))
            logger.debug("[AnyTLS] uot bootstrap sid=\(stream.sid) bytes=\(bootstrap.count)")
            do {
                try await stream.send(bootstrap)
            } catch {
                logger.debug("[AnyTLS] uot bootstrap failed sid=\(stream.sid): \(error.localizedDescription)")
                stream.cancel()
                throw error
            }
            return AnyTLSUDPConnection(inner: stream)

        case .mux:
            // Already rejected above; here for switch exhaustiveness.
            stream.cancel()
            throw AnywhereError.proxy(.anyTLS, .protocolViolation(detail: "Mux is not supported with AnyTLS"))
        }
    }
}
