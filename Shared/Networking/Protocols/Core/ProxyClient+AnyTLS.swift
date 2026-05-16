//
//  ProxyClient+AnyTLS.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation

private let logger = AnywhereLogger(category: "AnyTLS")

extension ProxyClient {
    /// Connects through an AnyTLS server: TCP → TLS → AnyTLS handshake →
    /// stream + destination address (or stream + UoT request for UDP).
    ///
    /// AnyTLS mandates TLS on the wire (the password SHA256 is the first
    /// thing the server reads after the TLS handshake), so there's no
    /// plaintext or Reality variant. UDP rides a stream opened to the
    /// `sp.v2.udp-over-tcp.arpa` magic FQDN, with `[isConnect=1][addr]`
    /// preceding the per-datagram `[length][payload]` framing.
    func connectWithAnyTLS(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        logger.info("[AnyTLS] connect cmd=\(command) dest=\(destinationHost):\(destinationPort) initialData=\(initialData?.count ?? 0)B chained=\(tunnel != nil)")
        guard let password = configuration.anytlsPassword, !password.isEmpty else {
            logger.warning("[AnyTLS] reject: password not set")
            completion(.failure(ProxyError.protocolError("AnyTLS password not set")))
            return
        }
        guard let tlsConfig = configuration.anytlsTLS else {
            logger.warning("[AnyTLS] reject: TLS configuration missing")
            completion(.failure(ProxyError.protocolError("AnyTLS requires TLS configuration")))
            return
        }
        if command == .mux {
            logger.warning("[AnyTLS] reject: mux not supported")
            completion(.failure(ProxyError.protocolError("Mux is not supported with AnyTLS")))
            return
        }
        logger.debug("[AnyTLS] sni=\(tlsConfig.serverName) alpn=\(tlsConfig.alpn?.joined(separator: ",") ?? "<none>") fp=\(tlsConfig.fingerprint.rawValue)")

        // Capture what the dial closure needs. We can't capture `self` long-
        // term because the AnyTLSClient persists across ProxyClient
        // instances; instead we snapshot the chain bits we need (tunnel,
        // host/port for the direct dial).
        let directHost = directDialHost
        let directPort = configuration.serverPort
        let tunnel = self.tunnel

        let dialOut: AnyTLSClient.DialOut = { dialCompletion in
            let tlsClient = TLSClient(configuration: tlsConfig)
            // CRITICAL: keep `tlsClient` alive until its completion fires.
            // TLSClient owns its `RawTCPSocket`; if it deallocates while the
            // async TCP connect is in flight, the write-source fires with a
            // [weak self] that is now nil, and `connectCompletion` is never
            // invoked — the dial silently hangs forever. We anchor by
            // referencing `tlsClient` inside the completion closure so the
            // closure capture extends its lifetime until the result arrives.
            let handleTLSResult: (Result<TLSRecordConnection, Error>) -> Void = { result in
                withExtendedLifetime(tlsClient) {
                    switch result {
                    case .success(let tlsConnection):
                        logger.info("[AnyTLS] TLS handshake ok, version=\(tlsConnection.tlsVersion)")
                        dialCompletion(.success(TLSProxyConnection(tlsConnection: tlsConnection)))
                    case .failure(let error):
                        logger.warning("[AnyTLS] TLS handshake failed: \(error.localizedDescription)")
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

        guard let client = AnyTLSManager.shared.client(for: configuration, dialOut: dialOut) else {
            logger.warning("[AnyTLS] AnyTLSManager returned nil client (outbound type mismatch?)")
            completion(.failure(ProxyError.connectionFailed("Failed to acquire AnyTLS client")))
            return
        }

        client.createStream { result in
            switch result {
            case .failure(let error):
                logger.warning("[AnyTLS] createStream failed: \(error.localizedDescription)")
                completion(.failure(error))

            case .success(let stream):
                logger.info("[AnyTLS] stream opened sid=\(stream.sid) cmd=\(command)")
                switch command {
                case .tcp:
                    // First cmdPSH on the stream is the destination address;
                    // appending `initialData` lets the caller's first bytes
                    // ride in the same TLS record (same trick Trojan uses).
                    var bootstrap = AnyTLSProtocol.encodeAddrPort(
                        host: destinationHost, port: destinationPort
                    )
                    if let initialData, !initialData.isEmpty {
                        bootstrap.append(initialData)
                    }
                    logger.debug("[AnyTLS] tcp bootstrap sid=\(stream.sid) bytes=\(bootstrap.count)")
                    stream.send(data: bootstrap) { error in
                        if let error {
                            logger.warning("[AnyTLS] tcp bootstrap failed sid=\(stream.sid): \(error.localizedDescription)")
                            stream.cancel()
                            completion(.failure(error))
                        } else {
                            completion(.success(stream))
                        }
                    }

                case .udp:
                    // Open a UoT stream: address points at the magic FQDN,
                    // followed by `[isConnect=1][SocksaddrSerializer(realDest)]`.
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
                            logger.warning("[AnyTLS] uot bootstrap failed sid=\(stream.sid): \(error.localizedDescription)")
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
