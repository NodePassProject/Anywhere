//
//  ProxyClient+VLESS.swift
//  Anywhere
//
//  Created by NodePassProject on 5/13/26.
//

import Foundation

extension ProxyClient {

    // MARK: - Vision flow

    /// Base Vision flow on the wire (suffix stripped).
    fileprivate static let visionFlow = "xtls-rprx-vision"

    var isVisionFlow: Bool {
        guard case .vless(_, _, let flow, _, _) = configuration.outbound else { return false }
        return flow == Self.visionFlow
    }

    var hasVLESSEncryption: Bool {
        guard case .vless(_, let encryption, _, _, _) = configuration.outbound else { return false }
        return !encryption.isEmpty && encryption != "none"
    }

    /// Vision needs TLS-1.3-record framing: VLESS encryption provides it over any
    /// transport; otherwise only raw TCP carrying TLS/REALITY qualifies.
    var transportSupportsVision: Bool {
        if hasVLESSEncryption { return true }
        if case .tcp = configuration.xrayTransportLayer { return true }
        return false
    }

    // MARK: - VLESS protocol handshake

    /// VLESS protocol handshake on top of an established transport; runs the
    /// `mlkem768x25519plus` handshake first when encryption is configured.
    func sendVLESSProtocolHandshake(
        over connection: ProxyConnection,
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        supportsVision: Bool,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        // A nil config means "none"/empty → plaintext VLESS. On iOS < 26 the encrypted
        // scheme must refuse, not silently downgrade and expose the plaintext UUID.
        let vlessEncryption: String
        if case .vless(_, let encryption, _, _, _) = configuration.outbound {
            vlessEncryption = encryption
        } else {
            vlessEncryption = "none"
        }
        let encryptionConfig: VLESSEncryptionConfig?
        do {
            encryptionConfig = try VLESSEncryptionConfig.parse(vlessEncryption)
        } catch {
            completion(.failure(ProxyError.protocolError(
                "Invalid VLESS encryption: \(error.localizedDescription)"
            )))
            return
        }
        if let encryptionConfig {
            guard #available(iOS 26.0, macOS 26.0, tvOS 26.0, *) else {
                completion(.failure(ProxyError.protocolError(
                    "VLESS encryption requires iOS 26 / macOS 26 / tvOS 26 or later"
                )))
                return
            }
            do {
                let client = try VLESSEncryptionClient(
                    config: encryptionConfig,
                    host: configuration.serverAddress,
                    port: configuration.serverPort
                )
                client.handshake(over: connection) { [weak self] result in
                    guard let self else {
                        completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                        return
                    }
                    switch result {
                    case .failure(let error):
                        completion(.failure(error))
                    case .success(let encryptedConnection):
                        self.continueVLESSHandshake(
                            over: encryptedConnection,
                            command: command,
                            destinationHost: destinationHost,
                            destinationPort: destinationPort,
                            initialData: initialData,
                            supportsVision: supportsVision,
                            completion: completion
                        )
                    }
                }
            } catch {
                completion(.failure(error))
            }
            return
        }

        continueVLESSHandshake(
            over: connection,
            command: command,
            destinationHost: destinationHost,
            destinationPort: destinationPort,
            initialData: initialData,
            supportsVision: supportsVision,
            completion: completion
        )
    }

    fileprivate func continueVLESSHandshake(
        over connection: ProxyConnection,
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        supportsVision: Bool,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        let vlessUUID: UUID
        if case .vless(let uuid, _, _, _, _) = configuration.outbound {
            vlessUUID = uuid
        } else {
            vlessUUID = configuration.id
        }
        let isVision = supportsVision && isVisionFlow && (command == .tcp || command == .mux)

        let requestHeader = VLESSProtocol.encodeRequestHeader(
            uuid: vlessUUID,
            command: command,
            destinationAddress: destinationHost,
            destinationPort: destinationPort,
            flow: isVision ? Self.visionFlow : nil
        )

        let vless = VLESSConnection(inner: connection)
        // For Vision flow, initial data needs separate padding — don't append to the header.
        let handshakeInitialData = isVision ? nil : initialData
        vless.sendHandshake(requestHeader: requestHeader, initialData: handshakeInitialData) { [weak self] error in
            if let error {
                completion(.failure(ProxyError.connectionFailed(error.localizedDescription)))
                return
            }
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }

            let proxyConnection: ProxyConnection = (command == .udp)
                ? VLESSUDPConnection(inner: vless)
                : vless

            if isVision {
                if let tlsError = self.validateOuterTLSForVision(proxyConnection) {
                    completion(.failure(tlsError))
                    return
                }
                let vision = self.wrapWithVision(proxyConnection)
                // Await the Vision-padded intro before signalling success; a racing
                // first send could otherwise precede it and corrupt the byte stream.
                let introCompletion: (Error?) -> Void = { error in
                    if let error {
                        completion(.failure(ProxyError.connectionFailed(error.localizedDescription)))
                    } else {
                        completion(.success(vision))
                    }
                }
                if let initialData {
                    vision.sendRaw(data: initialData, completion: introCompletion)
                } else {
                    vision.sendEmptyPadding(completion: introCompletion)
                }
            } else {
                completion(.success(proxyConnection))
            }
        }
    }

    // MARK: - Vision

    /// Vision requires outer TLS 1.3; VLESS encryption is exempt because its AEAD
    /// records already use TLS 1.3 `application_data` framing.
    fileprivate func validateOuterTLSForVision(_ connection: ProxyConnection) -> Error? {
        if hasVLESSEncryption {
            return nil
        }
        guard let version = connection.outerTLSVersion else {
            return ProxyError.protocolError("Vision requires outer TLS or REALITY transport")
        }
        if version != .tls13 {
            return ProxyError.protocolError("Vision requires outer TLS 1.3, found \(version)")
        }
        return nil
    }

    fileprivate func wrapWithVision(_ connection: ProxyConnection) -> VLESSVisionConnection {
        let vlessUUID: UUID
        if case .vless(let uuid, _, _, _, _) = configuration.outbound {
            vlessUUID = uuid
        } else {
            vlessUUID = configuration.id
        }
        let uuidBytes = vlessUUID.uuid
        let uuidData = Data([
            uuidBytes.0, uuidBytes.1, uuidBytes.2, uuidBytes.3,
            uuidBytes.4, uuidBytes.5, uuidBytes.6, uuidBytes.7,
            uuidBytes.8, uuidBytes.9, uuidBytes.10, uuidBytes.11,
            uuidBytes.12, uuidBytes.13, uuidBytes.14, uuidBytes.15
        ])
        return VLESSVisionConnection(connection: connection, userUUID: uuidData)
    }
}
