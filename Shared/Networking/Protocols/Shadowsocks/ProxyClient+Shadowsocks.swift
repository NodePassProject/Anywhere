//
//  ProxyClient+Shadowsocks.swift
//  Anywhere
//
//  Created by NodePassProject on 5/13/26.
//

import Foundation

nonisolated extension ProxyClient {

    func connectWithShadowsocks(_ request: ProxyRequest) async throws -> ProxyConnection {
        if request.network == .udp {
            return try await connectShadowsocksRealUDP(
                destinationHost: request.host, destinationPort: request.port
            )
        }
        let directProxyConnection = try await dialDirectProxyConnection()
        do {
            let connection = try await sendShadowsocksProtocolHandshake(over: directProxyConnection, request: request)
            try await connection.send(request.initialData ?? Data())
            return connection
        } catch {
            directProxyConnection.cancel()
            throw error
        }
    }

    func sendShadowsocksProtocolHandshake(
        over connection: ProxyConnection,
        request: ProxyRequest
    ) async throws -> ProxyConnection {
        try wrapWithShadowsocks(
            inner: connection,
            network: request.network,
            destinationHost: request.host,
            destinationPort: request.port
        ).get()
    }
    
    func connectShadowsocksRealUDP(
        destinationHost: String,
        destinationPort: UInt16
    ) async throws -> ProxyConnection {
        let udpInner: ProxyConnection
        if let tunnel = self.tunnel {
            guard tunnel.deliversDatagrams else {
                throw AnywhereError.proxy(.shadowsocks, .protocolViolation(
                    detail: "Shadowsocks UDP requires the chain link above it to deliver UDP datagrams."
                ))
            }
            setChainTunnel(nil)
            udpInner = tunnel
        } else {
            let transport = UDPTransport(host: directDialHost, port: configuration.serverPort, resolution: .proxies)
            try await transport.connect()
            udpInner = DirectUDPProxyConnection(transport: transport)
        }
        do {
            return try wrapWithShadowsocks(
                inner: udpInner,
                network: .udp,
                destinationHost: destinationHost,
                destinationPort: destinationPort
            ).get()
        } catch {
            udpInner.cancel()
            throw error
        }
    }

    fileprivate func wrapWithShadowsocks(
        inner: ProxyConnection,
        network: ProxyNetwork,
        destinationHost: String,
        destinationPort: UInt16
    ) -> Result<ProxyConnection, Error> {
        guard case .shadowsocks(let shadowsocks) = configuration.outbound else {
            return .failure(AnywhereError.proxy(.shadowsocks, .protocolViolation(detail: "Shadowsocks password not set")))
        }
        guard let cipher = shadowsocks.cipher else {
            return .failure(AnywhereError.proxy(.shadowsocks, .protocolViolation(detail: "Invalid Shadowsocks method: \(shadowsocks.method)")))
        }

        if cipher.isSS2022 {
            guard let pskList = ShadowsocksKeyDerivation.decodePSKList(password: shadowsocks.password, keySize: cipher.keySize) else {
                return .failure(AnywhereError.proxy(.shadowsocks, .protocolViolation(detail: "Invalid Shadowsocks 2022 PSK")))
            }

            if network == .udp {
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
            let masterKey = ShadowsocksKeyDerivation.deriveKey(password: shadowsocks.password, keySize: cipher.keySize)
            let addressHeader = ShadowsocksProtocol.buildAddressHeader(host: destinationHost, port: destinationPort)

            if network == .udp {
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
