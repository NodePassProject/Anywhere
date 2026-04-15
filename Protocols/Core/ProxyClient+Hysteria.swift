//
//  ProxyClient+Hysteria.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/15/26.
//

import Foundation

extension ProxyClient {
    /// Connects through a Hysteria v2 server. Shares one authenticated
    /// QUIC session per (host, port, SNI, password) via ``HysteriaSessionPool``.
    func connectWithHysteria(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard let password = configuration.hysteriaPassword else {
            completion(.failure(ProxyError.protocolError("Hysteria password not set")))
            return
        }

        let hyConfig = HysteriaConfiguration(
            proxyHost: configuration.serverAddress,
            proxyPort: configuration.serverPort,
            password: password,
            sni: configuration.hysteriaSNI,
            clientRxBytesPerSec: 0, // "please probe" — server picks CC on its side
            uploadMbps: configuration.hysteriaUploadMbps ?? HysteriaUploadMbpsDefault
        )

        // RFC 3986 §3.2.2: IPv6 literals must be bracketed.
        let bracketedHost = destinationHost.contains(":") ? "[\(destinationHost)]" : destinationHost
        let destination = "\(bracketedHost):\(destinationPort)"

        HysteriaSessionPool.shared.acquireSession(configuration: hyConfig) { result in
            switch result {
            case .failure(let error):
                completion(.failure(error))
            case .success(let session):
                switch command {
                case .tcp, .mux:
                    let conn = HysteriaConnection(session: session, destination: destination)
                    conn.open { error in
                        if let error {
                            conn.cancel()
                            completion(.failure(error))
                        } else {
                            completion(.success(conn))
                        }
                    }
                case .udp:
                    let conn = HysteriaUDPConnection(session: session, destination: destination)
                    conn.open { error in
                        if let error {
                            conn.cancel()
                            completion(.failure(error))
                        } else {
                            completion(.success(conn))
                        }
                    }
                }
            }
        }
    }
}
