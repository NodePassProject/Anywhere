//
//  ProxyClient+AnyTLS.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation

private let logger = AnywhereLogger(category: "ProxyClient+AnyTLS")

extension ProxyClient {
    /// Connects through an AnyTLS server: TCP → TLS → AnyTLS handshake → stream + destination.
    /// AnyTLS mandates TLS (the password SHA256 is the first thing the server reads after the
    /// handshake); UDP rides a UoT stream opened to the `sp.v2.udp-over-tcp.arpa` magic FQDN.
    func connectWithAnyTLS(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        logger.debug("[AnyTLS] connect cmd=\(command) dest=\(destinationHost):\(destinationPort) initialData=\(initialData?.count ?? 0)B chained=\(tunnel != nil)")
        guard case .anytls(let password, _, _, _, let tlsConfig) = configuration.outbound, !password.isEmpty else {
            logger.debug("[AnyTLS] reject: password not set")
            completion(.failure(ProxyError.protocolError("AnyTLS password not set")))
            return
        }
        if command == .mux {
            logger.debug("[AnyTLS] reject: mux not supported")
            completion(.failure(ProxyError.protocolError("Mux is not supported with AnyTLS")))
            return
        }
        logger.debug("[AnyTLS] sni=\(tlsConfig.serverName) alpn=\(tlsConfig.alpn?.joined(separator: ",") ?? "<none>") fp=\(tlsConfig.fingerprint.rawValue)")

        // Don't capture self in the dial closure: AnyTLSMultiplexerPool persists across ProxyClient instances.
        let directHost = directDialHost
        let directPort = configuration.serverPort
        let tunnel = self.tunnel

        let dialOut: AnyTLSMultiplexerPool.DialOut = { dialCompletion in
            let tlsClient = TLSClient(configuration: tlsConfig)
            // Anchor `tlsClient` until the async connect finishes; otherwise the socket's
            // write-source fires after deallocation and the dial hangs silently.
            let handleTLSResult: (Result<TLSRecordConnection, Error>) -> Void = { result in
                withExtendedLifetime(tlsClient) {
                    switch result {
                    case .success(let tlsConnection):
                        logger.debug("[AnyTLS] TLS handshake ok, version=\(tlsConnection.tlsVersion)")
                        dialCompletion(.success(TLSProxyConnection(tlsConnection: tlsConnection)))
                    case .failure(let error):
                        logger.debug("[AnyTLS] TLS handshake failed: \(error.localizedDescription)")
                        dialCompletion(.failure(error))
                    }
                }
            }
            if let tunnel {
                logger.debug("[AnyTLS] dialing TLS over chained tunnel")
                tlsClient.connect(overTunnel: tunnel, completion: handleTLSResult)
            } else {
                logger.debug("[AnyTLS] dialing TLS direct \(directHost):\(directPort)")
                tlsClient.connect(host: directHost, port: directPort, completion: handleTLSResult)
            }
        }

        guard let client = AnyTLSMultiplexerRegistry.shared.client(for: configuration, dialOut: dialOut) else {
            logger.debug("[AnyTLS] AnyTLSMultiplexerRegistry returned nil client (outbound type mismatch?)")
            completion(.failure(ProxyError.connectionFailed("Failed to acquire AnyTLS client")))
            return
        }

        client.acquireStream { result in
            switch result {
            case .failure(let error):
                logger.debug("[AnyTLS] acquireStream failed: \(error.localizedDescription)")
                completion(.failure(error))

            case .success(let stream):
                logger.debug("[AnyTLS] stream opened sid=\(stream.sid) cmd=\(command)")
                switch command {
                case .tcp:
                    // The first cmdPSH carries the destination; coalescing
                    // initialData into the same send avoids an extra TLS record.
                    var bootstrap = AnyTLSProtocol.encodeAddrPort(
                        host: destinationHost, port: destinationPort
                    )
                    if let initialData, !initialData.isEmpty {
                        bootstrap.append(initialData)
                    }
                    logger.debug("[AnyTLS] tcp bootstrap sid=\(stream.sid) bytes=\(bootstrap.count)")
                    stream.send(data: bootstrap) { error in
                        if let error {
                            logger.debug("[AnyTLS] tcp bootstrap failed sid=\(stream.sid): \(error.localizedDescription)")
                            stream.cancel()
                            completion(.failure(error))
                        } else {
                            completion(.success(stream))
                        }
                    }

                case .udp:
                    // UoT bootstrap: magic-FQDN address, then [isConnect=1][realDest].
                    var bootstrap = AnyTLSProtocol.encodeAddrPort(
                        host: AnyTLSProtocol.uotMagicAddress, port: 0
                    )
                    bootstrap.append(0x01) // isConnect = true
                    bootstrap.append(AnyTLSProtocol.encodeAddrPort(
                        host: destinationHost, port: destinationPort
                    ))
                    logger.debug("[AnyTLS] uot bootstrap sid=\(stream.sid) bytes=\(bootstrap.count)")
                    stream.send(data: bootstrap) { error in
                        if let error {
                            logger.debug("[AnyTLS] uot bootstrap failed sid=\(stream.sid): \(error.localizedDescription)")
                            stream.cancel()
                            completion(.failure(error))
                        } else {
                            completion(.success(AnyTLSUDPConnection(inner: stream)))
                        }
                    }

                case .mux:
                    // Already rejected above; here for switch exhaustiveness.
                    stream.cancel()
                    completion(.failure(ProxyError.protocolError("Mux is not supported with AnyTLS")))
                }
            }
        }
    }
}
