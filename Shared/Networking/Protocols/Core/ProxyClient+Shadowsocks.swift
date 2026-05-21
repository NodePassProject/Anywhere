//
//  ProxyClient+Shadowsocks.swift
//  Anywhere
//
//  Created by NodePassProject on 5/13/26.
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

    /// Opens a real-UDP path to the SS server (via a UDP-shaped chain tunnel
    /// or a kernel `SOCK_DGRAM`) and wraps with SS UDP encryption keyed for
    /// the final destination.
    func connectShadowsocksRealUDP(
        destinationHost: String,
        destinationPort: UInt16,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        let wrapAndComplete: (ProxyConnection) -> Void = { [weak self] udpInner in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("Client deallocated")))
                return
            }
            completion(self.wrapWithShadowsocks(
                inner: udpInner,
                command: .udp,
                destinationHost: destinationHost,
                destinationPort: destinationPort
            ))
        }

        if let tunnel = self.tunnel {
            // Standard SS UDP only runs over real datagrams. A TCP tunnel here
            // is a configuration error — fail rather than silently truncate.
            guard tunnel.deliversDatagrams else {
                completion(.failure(ProxyError.protocolError(
                    "Shadowsocks UDP requires the chain link above it to deliver UDP datagrams."
                )))
                return
            }
            self.tunnel = nil
            wrapAndComplete(tunnel)
        } else {
            let socket = RawUDPSocket()
            socket.connect(host: directDialHost,
                           port: configuration.serverPort,
                           completionQueue: .global()) { error in
                if let error {
                    completion(.failure(error))
                    return
                }
                wrapAndComplete(DirectUDPProxyConnection(socket: socket))
            }
        }
    }

    /// Wraps a bare transport connection with Shadowsocks AEAD encryption.
    fileprivate func wrapWithShadowsocks(
        inner: ProxyConnection,
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16
    ) -> Result<ProxyConnection, Error> {
        guard case .shadowsocks(let password, let method) = configuration.outbound else {
            return .failure(ProxyError.protocolError("Shadowsocks password not set"))
        }
        guard let cipher = ShadowsocksCipher(method: method) else {
            return .failure(ProxyError.protocolError("Invalid Shadowsocks method: \(method)"))
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
