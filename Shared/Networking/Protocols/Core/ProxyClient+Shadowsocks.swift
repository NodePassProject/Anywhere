//
//  ProxyClient+Shadowsocks.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/13/26.
//

import Foundation

extension ProxyClient {

    /// Whether this client is configured for Shadowsocks outbound.
    var isShadowsocks: Bool {
        configuration.outboundProtocol == .shadowsocks
    }

    /// Shadowsocks protocol handshake on top of an established transport.
    /// Shadowsocks owns its own wire encryption and address framing, so the
    /// "handshake" is just wrapping the inner connection with the right
    /// cipher/PSK; the result is delivered synchronously via `completion`.
    func sendShadowsocksProtocolHandshake(
        over connection: ProxyConnection,
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        completion(wrapWithShadowsocks(
            inner: connection,
            command: command,
            destinationHost: destinationHost,
            destinationPort: destinationPort
        ))
    }

    /// Wraps a bare transport connection with Shadowsocks AEAD encryption.
    fileprivate func wrapWithShadowsocks(
        inner: ProxyConnection,
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16
    ) -> Result<ProxyConnection, Error> {
        guard let method = configuration.ssMethod,
              let cipher = ShadowsocksCipher(method: method) else {
            return .failure(ProxyError.protocolError("Invalid Shadowsocks method: \(configuration.ssMethod ?? "nil")"))
        }
        guard let password = configuration.ssPassword else {
            return .failure(ProxyError.protocolError("Shadowsocks password not set"))
        }

        if cipher.isSS2022 {
            // Shadowsocks 2022: base64-encoded PSK(s), BLAKE3 key derivation
            guard let pskList = ShadowsocksKeyDerivation.decodePSKList(password: password, keySize: cipher.keySize) else {
                return .failure(ProxyError.protocolError("Invalid Shadowsocks 2022 PSK"))
            }

            if command == .udp {
                if cipher == .blake3chacha20poly1305 {
                    return .success(Shadowsocks2022ChaChaUDPConnection(
                        inner: inner, psk: pskList.last!, dstHost: destinationHost, dstPort: destinationPort
                    ))
                } else {
                    return .success(Shadowsocks2022AESUDPConnection(
                        inner: inner, cipher: cipher, pskList: pskList,
                        dstHost: destinationHost, dstPort: destinationPort
                    ))
                }
            } else {
                let addressHeader = ShadowsocksProtocol.buildAddressHeader(host: destinationHost, port: destinationPort)
                return .success(Shadowsocks2022Connection(
                    inner: inner, cipher: cipher, pskList: pskList,
                    addressHeader: addressHeader
                ))
            }
        } else {
            // Legacy Shadowsocks: password-based EVP_BytesToKey derivation
            let masterKey = ShadowsocksKeyDerivation.deriveKey(password: password, keySize: cipher.keySize)
            let addressHeader = ShadowsocksProtocol.buildAddressHeader(host: destinationHost, port: destinationPort)

            if command == .udp {
                return .success(ShadowsocksUDPConnection(
                    inner: inner, cipher: cipher, masterKey: masterKey,
                    dstHost: destinationHost, dstPort: destinationPort
                ))
            } else {
                return .success(ShadowsocksConnection(
                    inner: inner, cipher: cipher, masterKey: masterKey,
                    addressHeader: addressHeader
                ))
            }
        }
    }
}
