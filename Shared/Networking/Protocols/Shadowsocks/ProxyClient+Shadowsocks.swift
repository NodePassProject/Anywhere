//
//  ProxyClient+Shadowsocks.swift
//  Anywhere
//
//  Created by NodePassProject on 5/13/26.
//

import Foundation

nonisolated extension ProxyClient {

    var isShadowsocks: Bool {
        configuration.outboundProtocol == .shadowsocks
    }

    /// No network round-trip — just wraps the transport with cipher/PSK. Native async.
    func sendShadowsocksProtocolHandshake(
        over connection: ProxyConnection,
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16
    ) async throws -> ProxyConnection {
        try wrapWithShadowsocks(
            inner: connection,
            command: command,
            destinationHost: destinationHost,
            destinationPort: destinationPort
        ).get()
    }

    /// Opens a real-UDP path to the SS server (chain-tunnel datagram or direct UDP transport)
    /// and wraps with SS UDP encryption keyed for the final destination. Native async.
    func connectShadowsocksRealUDP(
        destinationHost: String,
        destinationPort: UInt16
    ) async throws -> ProxyConnection {
        let udpInner: ProxyConnection
        if let tunnel = self.tunnel {
            // SS UDP needs real datagrams; a TCP tunnel here is a config error — fail rather than silently truncate.
            guard tunnel.deliversDatagrams else {
                throw AnywhereError.proxy(.shadowsocks, .protocolViolation(
                    detail: "Shadowsocks UDP requires the chain link above it to deliver UDP datagrams."
                ))
            }
            setChainTunnel(nil)
            udpInner = tunnel
        } else {
            let transport = UDPTransport(host: directDialHost, port: configuration.serverPort, resolvesViaProxyDNS: true)
            try await transport.connect()
            udpInner = DirectUDPProxyConnection(transport: transport)
        }
        return try wrapWithShadowsocks(
            inner: udpInner,
            command: .udp,
            destinationHost: destinationHost,
            destinationPort: destinationPort
        ).get()
    }

    fileprivate func wrapWithShadowsocks(
        inner: ProxyConnection,
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16
    ) -> Result<ProxyConnection, Error> {
        guard case .shadowsocks(let password, let method) = configuration.outbound else {
            return .failure(AnywhereError.proxy(.shadowsocks, .protocolViolation(detail: "Shadowsocks password not set")))
        }
        guard let cipher = ShadowsocksCipher(method: method) else {
            return .failure(AnywhereError.proxy(.shadowsocks, .protocolViolation(detail: "Invalid Shadowsocks method: \(method)")))
        }

        if cipher.isSS2022 {
            // Shadowsocks 2022: base64-encoded PSK(s), BLAKE3 key derivation
            guard let pskList = ShadowsocksKeyDerivation.decodePSKList(password: password, keySize: cipher.keySize) else {
                return .failure(AnywhereError.proxy(.shadowsocks, .protocolViolation(detail: "Invalid Shadowsocks 2022 PSK")))
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
