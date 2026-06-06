//
//  ProxyClient+VLESS.swift
//  Anywhere
//
//  Created by NodePassProject on 5/13/26.
//

import Foundation

extension ProxyClient {

    // MARK: - Vision flow

    /// The base Vision flow string sent on the wire (suffix stripped).
    fileprivate static let visionFlow = "xtls-rprx-vision"

    /// Whether the configured flow is the Vision flow.
    var isVisionFlow: Bool {
        guard case .vless(_, _, let flow, _, _, _, _) = configuration.outbound else { return false }
        return flow == Self.visionFlow
    }

    /// Whether a non-trivial VLESS `encryption` (the `mlkem768x25519plus`
    /// scheme) is configured. When set, the encryption layer is itself a
    /// TLS-1.3-equivalent secure channel, so Vision can run over it without an
    /// outer TLS/REALITY transport — see ``validateOuterTLSForVision(_:)``.
    var hasVLESSEncryption: Bool {
        guard case .vless(_, let encryption, _, _, _, _, _) = configuration.outbound else { return false }
        return !encryption.isEmpty && encryption != "none"
    }

    /// Whether the configured transport can carry the Vision flow. Vision needs
    /// a TLS-1.3-record-like layer to drive its padding / direct-copy state
    /// machine, which is provided by either of two cases:
    ///   1. VLESS Encryption — its AEAD records masquerade as TLS 1.3
    ///      `application_data`, so Vision works over *any* transport; or
    ///   2. a raw TCP transport carrying TLS / REALITY (the security layer is
    ///      validated separately by ``validateOuterTLSForVision(_:)``).
    /// Framed transports (WebSocket / HTTPUpgrade / gRPC / XHTTP) qualify only
    /// via case 1.
    var transportSupportsVision: Bool {
        if hasVLESSEncryption { return true }
        if case .tcp = configuration.transportLayer { return true }
        return false
    }

    // MARK: - VLESS protocol handshake

    /// VLESS protocol handshake on top of an established transport.
    ///
    /// - If the encryption field is `"none"` or empty: plaintext VLESS.
    /// - Otherwise: run the `mlkem768x25519plus` encryption handshake first,
    ///   then VLESS on top.
    func sendVLESSProtocolHandshake(
        over connection: ProxyConnection,
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        supportsVision: Bool,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        // Parse the encryption field upfront. `nil` means the legacy
        // `"none"` / empty value — proceed with plaintext VLESS as before.
        // Anything else means the new `mlkem768x25519plus` scheme: on
        // iOS < 26 we MUST refuse to dial. A silent downgrade would send
        // the plaintext request header — including UUID and destination —
        // to a server that expects the encrypted handshake.
        let vlessEncryption: String
        if case .vless(_, let encryption, _, _, _, _, _) = configuration.outbound {
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

    /// Per-command VLESS handshake on top of an already-prepared transport.
    /// Split out so the encryption-enabled path can chain into it after the
    /// `mlkem768x25519plus` handshake completes.
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
        if case .vless(let u, _, _, _, _, _, _) = configuration.outbound {
            vlessUUID = u
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
                // Wait for the introductory Vision-padded send (initial
                // payload or empty padding) to be accepted by the inner
                // transport before declaring the connect successful.
                // Otherwise fire-and-forget here would race with the
                // upload pipeline's first `send` issued from the caller's
                // success callback — the pump's bytes could reach the
                // framing layer before the padded intro and corrupt the
                // proxy-side byte stream.
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

    /// Validates that the outer TLS connection is TLS 1.3 when using Vision flow.
    /// Matches Xray-core `outbound.go` lines 346-355.
    ///
    /// VLESS Encryption is exempt: its AEAD records masquerade as TLS 1.3
    /// `application_data` (`0x17 0x03 0x03` framing), giving Vision the same
    /// record structure it keys off without a real outer TLS layer.
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

    /// Wraps a VLESS connection with the XTLS Vision layer.
    fileprivate func wrapWithVision(_ connection: ProxyConnection) -> VLESSVisionConnection {
        let vlessUUID: UUID
        if case .vless(let u, _, _, _, _, _, _) = configuration.outbound {
            vlessUUID = u
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
