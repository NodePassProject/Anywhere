//
//  LWIPUDPFlow.swift
//  Network Extension
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "LWIP-UDP")

class LWIPUDPFlow {
    let flowKey: String
    let srcHost: String
    let srcPort: UInt16
    let dstHost: String
    let dstPort: UInt16
    let isIPv6: Bool
    let configuration: ProxyConfiguration
    let lwipQueue: DispatchQueue

    // Raw IP bytes for lwip_bridge_udp_sendto (swapped src/dst for responses)
    let srcIPBytes: Data  // original source (becomes dst in response)
    let dstIPBytes: Data  // original destination (becomes src in response)

    var lastActivity: CFAbsoluteTime = CFAbsoluteTimeGetCurrent()

    // Direct bypass path
    private var directRelay: DirectUDPRelay?

    // Non-mux path
    private var proxyClient: ProxyClient?
    private var proxyConnection: ProxyConnection?

    // Shadowsocks direct UDP relay
    private var ssUDPRelay: ShadowsocksUDPRelay?

    // Mux path
    private var muxSession: MuxSession?

    private var proxyConnecting = false
    private var forceBypass = false
    private var pendingData: [Data] = []  // always raw payloads (framing deferred to send time)
    private var pendingBufferSize = 0      // current total size of pendingData
    private var closed = false

    /// Maximum buffer size for queued UDP datagrams (matches Xray-core's DiscardOverflow 16KB limit).
    /// Datagrams that would exceed this limit are silently dropped (standard UDP behavior).
    private static let maxUDPBufferSize = 16 * 1024  // 16 KB

    init(flowKey: String,
         srcHost: String, srcPort: UInt16,
         dstHost: String, dstPort: UInt16,
         srcIPData: Data, dstIPData: Data,
         isIPv6: Bool,
         configuration: ProxyConfiguration,
         forceBypass: Bool = false,
         lwipQueue: DispatchQueue) {
        self.flowKey = flowKey
        self.srcHost = srcHost
        self.srcPort = srcPort
        self.dstHost = dstHost
        self.dstPort = dstPort
        self.srcIPBytes = srcIPData
        self.dstIPBytes = dstIPData
        self.isIPv6 = isIPv6
        self.configuration = configuration
        self.forceBypass = forceBypass
        self.lwipQueue = lwipQueue
    }

    // MARK: - Data Handling (called on lwipQueue)

    func handleReceivedData(_ data: Data, payloadLength: Int) {
        guard !closed else { return }
        lastActivity = CFAbsoluteTimeGetCurrent()

        let payload = data.prefix(payloadLength)

        // Buffer data while the outbound connection is being established.
        // directRelay is set before its socket connects; sending to an
        // unconnected UDP socket silently drops the datagram.
        if proxyConnecting {
            bufferPayload(data: data, payloadLength: payloadLength)
            return
        }

        // Direct bypass path
        if let relay = directRelay {
            relay.send(data: Data(payload))
            return
        }

        // Shadowsocks direct UDP relay
        if let relay = ssUDPRelay {
            relay.send(data: Data(payload))
            return
        }

        // Mux path: send raw payload (mux framing handled by MuxSession)
        if let session = muxSession {
            session.send(data: Data(payload)) { [weak self] error in
                if let error {
                    logger.error("[UDP] Mux send error for \(self?.flowKey ?? "?", privacy: .public): \(error.localizedDescription, privacy: .public)")
                }
            }
            return
        }

        // Non-mux path: send payload through proxy connection
        if let connection = proxyConnection {
            if configuration.outboundProtocol == .shadowsocks {
                // SS connection handles encryption; send raw payload
                connection.send(data: Data(data.prefix(payloadLength))) { [weak self] error in
                    if let error {
                        logger.error("[UDP] SS send error for \(self?.flowKey ?? "?", privacy: .public): \(error.localizedDescription, privacy: .public)")
                    }
                }
            } else {
                sendUDPThroughProxy(connection: connection, payload: data, payloadLength: payloadLength)
            }
            return
        }

        // No connection yet — buffer and start connecting
        bufferPayload(data: data, payloadLength: payloadLength)
        connectProxy()
    }

    private func bufferPayload(data: Data, payloadLength: Int) {
        // Drop datagram if buffer limit would be exceeded (DiscardOverflow)
        if pendingBufferSize + payloadLength > Self.maxUDPBufferSize {
            return
        }

        // Always buffer raw payloads. Framing for VLESS non-mux is deferred
        // to send time so that bypass and mux paths receive unframed data.
        let payload = Data(data.prefix(payloadLength))
        pendingData.append(payload)
        pendingBufferSize += payload.count
    }

    private func sendUDPThroughProxy(connection: ProxyConnection, payload: Data, payloadLength: Int) {
        let framedLen = 2 + payloadLength
        var framedPayload = Data(count: framedLen)
        framedPayload.withUnsafeMutableBytes { outPtr in
            payload.withUnsafeBytes { srcPtr in
                frame_udp_payload(
                    outPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    srcPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    UInt16(payloadLength)
                )
            }
        }

        connection.sendRaw(data: framedPayload) { [weak self] error in
            if let error {
                logger.error("[UDP] Proxy send error for \(self?.flowKey ?? "?", privacy: .public): \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    // MARK: - Proxy Connection

    private func connectProxy() {
        guard !proxyConnecting && proxyConnection == nil && muxSession == nil && directRelay == nil && ssUDPRelay == nil && !closed else { return }

        if forceBypass || LWIPStack.shared?.shouldBypass(host: dstHost) == true {
            connectDirectUDP()
            return
        }

        proxyConnecting = true

        // Only use mux for VLESS with the default configuration (mux is tied to the default proxy's connection)
        // Shadowsocks does not support mux
        let isDefaultConfiguration = (LWIPStack.shared?.configuration?.id == configuration.id)
        if configuration.outboundProtocol == .vless, isDefaultConfiguration, let muxManager = LWIPStack.shared?.muxManager {
            // Mux path
            // Cone NAT: GlobalID = blake3("udp:srcHost:srcPort") matching Xray-core's
            // net.Destination.String() format. Non-zero GlobalID enables server-side
            // session persistence (Full Cone NAT). Nil = no GlobalID (Symmetric NAT).
            let globalID = configuration.xudpEnabled ? XUDP.generateGlobalID(sourceAddress: "udp:\(srcHost):\(srcPort)") : nil
            muxManager.dispatch(network: .udp, host: dstHost, port: dstPort, globalID: globalID) { [weak self] result in
                guard let self else { return }

                self.lwipQueue.async {
                    self.proxyConnecting = false
                    guard !self.closed else { return }

                    switch result {
                    case .success(let session):
                        // Guard against race: closeAll() may have already closed the
                        // session (via receive-loop error) before this handler ran.
                        // closeHandler was never set, so the flow won't be cleaned up
                        // unless we handle it here.
                        guard !session.closed else {
                            self.releaseProxy()
                            LWIPStack.shared?.udpFlows.removeValue(forKey: self.flowKey)
                            return
                        }

                        self.muxSession = session

                        // Set up receive handler
                        session.dataHandler = { [weak self] data in
                            self?.handleProxyData(data)
                        }
                        session.closeHandler = { [weak self] in
                            guard let self else { return }
                            self.lwipQueue.async {
                                self.close()
                                LWIPStack.shared?.udpFlows.removeValue(forKey: self.flowKey)
                            }
                        }

                        // Send buffered raw payloads
                        let buffered = self.pendingData
                        self.pendingData.removeAll()
                        self.pendingBufferSize = 0
                        for payload in buffered {
                            session.send(data: payload) { [weak self] error in
                                if let error {
                                    logger.error("[UDP] Mux initial send error for \(self?.flowKey ?? "?", privacy: .public): \(error.localizedDescription, privacy: .public)")
                                }
                            }
                        }

                    case .failure(let error):
                        if case .dropped = error as? ProxyError {} else {
                            logger.error("[UDP] Mux dispatch failed: \(self.flowKey, privacy: .public): \(error.localizedDescription, privacy: .public)")
                        }
                        self.releaseProxy()
                        LWIPStack.shared?.udpFlows.removeValue(forKey: self.flowKey)
                    }
                }
            }
        } else if configuration.outboundProtocol == .shadowsocks {
            // Shadowsocks UDP: direct UDP datagrams to the SS server with per-packet encryption
            connectShadowsocksUDP()
        } else {
            // Non-mux path (VLESS non-mux UDP)
            let client = ProxyClient(configuration: configuration)
            self.proxyClient = client

            client.connectUDP(to: dstHost, port: dstPort) { [weak self] result in
                guard let self else { return }

                self.lwipQueue.async {
                    self.proxyConnecting = false
                    guard !self.closed else { return }

                    switch result {
                    case .success(let proxyConnection):
                        self.proxyConnection = proxyConnection

                        // Send buffered raw payloads
                        if !self.pendingData.isEmpty {
                            if self.configuration.outboundProtocol == .shadowsocks {
                                // SS: send raw payloads (connection handles encryption)
                                for payload in self.pendingData {
                                    proxyConnection.send(data: payload) { [weak self] error in
                                        if let error {
                                            logger.error("[UDP] SS initial send error for \(self?.flowKey ?? "?", privacy: .public): \(error.localizedDescription, privacy: .public)")
                                        }
                                    }
                                }
                            } else {
                                // VLESS: frame each payload with 2-byte length prefix
                                var dataToSend = Data()
                                for payload in self.pendingData {
                                    var framedPayload = Data(count: 2 + payload.count)
                                    framedPayload.withUnsafeMutableBytes { outPtr in
                                        payload.withUnsafeBytes { srcPtr in
                                            frame_udp_payload(
                                                outPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                                srcPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                                UInt16(payload.count)
                                            )
                                        }
                                    }
                                    dataToSend.append(framedPayload)
                                }
                                proxyConnection.sendRaw(data: dataToSend) { [weak self] error in
                                    if let error {
                                        logger.error("[UDP] Proxy initial send error for \(self?.flowKey ?? "?", privacy: .public): \(error.localizedDescription, privacy: .public)")
                                    }
                                }
                            }
                            self.pendingData.removeAll()
                            self.pendingBufferSize = 0
                        }

                        // Start receiving proxy responses
                        self.startProxyReceiving(proxyConnection: proxyConnection)

                    case .failure(let error):
                        if case .dropped = error as? ProxyError {} else {
                            logger.error("[UDP] connect failed: \(self.flowKey, privacy: .public): \(error.localizedDescription, privacy: .public)")
                        }
                        self.releaseProxy()
                        LWIPStack.shared?.udpFlows.removeValue(forKey: self.flowKey)
                    }
                }
            }
        }
    }

    private func connectShadowsocksUDP() {
        guard ssUDPRelay == nil && !closed else { return }
        proxyConnecting = true

        guard let method = configuration.ssMethod,
              let cipher = ShadowsocksCipher(method: method),
              let password = configuration.ssPassword else {
            proxyConnecting = false
            close()
            LWIPStack.shared?.udpFlows.removeValue(forKey: flowKey)
            return
        }

        let mode: ShadowsocksUDPRelay.Mode
        if cipher.isSS2022 {
            guard let psk = ShadowsocksKeyDerivation.decodePSK(password: password, keySize: cipher.keySize) else {
                proxyConnecting = false
                close()
                LWIPStack.shared?.udpFlows.removeValue(forKey: flowKey)
                return
            }
            if cipher == .blake3chacha20poly1305 {
                mode = .ss2022ChaCha(psk: psk)
            } else {
                mode = .ss2022AES(cipher: cipher, psk: psk)
            }
        } else {
            let masterKey = ShadowsocksKeyDerivation.deriveKey(password: password, keySize: cipher.keySize)
            mode = .legacy(cipher: cipher, masterKey: masterKey)
        }

        let relay = ShadowsocksUDPRelay(mode: mode, dstHost: dstHost, dstPort: dstPort)
        self.ssUDPRelay = relay

        relay.connect(serverHost: configuration.connectAddress, serverPort: configuration.serverPort, lwipQueue: lwipQueue) { [weak self] error in
            guard let self else { return }

            self.lwipQueue.async {
                self.proxyConnecting = false
                guard !self.closed else { return }

                if let error {
                    logger.error("[UDP] SS UDP relay connect failed: \(self.flowKey, privacy: .public): \(error.localizedDescription, privacy: .public)")
                    self.close()
                    LWIPStack.shared?.udpFlows.removeValue(forKey: self.flowKey)
                    return
                }

                // Send buffered payloads
                for payload in self.pendingData {
                    relay.send(data: payload)
                }
                self.pendingData.removeAll()
                self.pendingBufferSize = 0

                // Start receiving responses
                relay.startReceiving { [weak self] data in
                    self?.handleProxyData(data)
                }
            }
        }
    }

    private func connectDirectUDP() {
        guard directRelay == nil && !closed else { return }
        proxyConnecting = true  // reuse flag to prevent re-entry

        let relay = DirectUDPRelay()
        self.directRelay = relay
        relay.connect(dstHost: dstHost, dstPort: dstPort, lwipQueue: lwipQueue) { [weak self] error in
            guard let self else { return }

            self.lwipQueue.async {
                self.proxyConnecting = false
                guard !self.closed else { return }

                if let error {
                    logger.error("[UDP] Direct connect failed: \(self.flowKey, privacy: .public): \(error.localizedDescription, privacy: .public)")
                    self.close()
                    LWIPStack.shared?.udpFlows.removeValue(forKey: self.flowKey)
                    return
                }

                // Send buffered payloads
                for payload in self.pendingData {
                    relay.send(data: payload)
                }
                self.pendingData.removeAll()
                self.pendingBufferSize = 0

                // Start receiving responses
                relay.startReceiving { [weak self] data in
                    self?.handleProxyData(data)
                }
            }
        }
    }

    private func startProxyReceiving(proxyConnection: ProxyConnection) {
        proxyConnection.startReceiving { [weak self] data in
            guard let self else { return }
            self.handleProxyData(data)
        } errorHandler: { [weak self] error in
            guard let self else { return }
            if let error {
                logger.error("[UDP] Proxy recv error: \(self.flowKey, privacy: .public): \(error.localizedDescription, privacy: .public)")
            }
            self.lwipQueue.async {
                self.close()
                LWIPStack.shared?.udpFlows.removeValue(forKey: self.flowKey)
            }
        }
    }

    private func handleProxyData(_ data: Data) {
        lwipQueue.async { [weak self] in
            guard let self, !self.closed else { return }
            self.lastActivity = CFAbsoluteTimeGetCurrent()

            // Send UDP response via lwIP (swap src/dst for the response packet)
            self.dstIPBytes.withUnsafeBytes { dstPtr in  // original dst = response src
                self.srcIPBytes.withUnsafeBytes { srcPtr in  // original src = response dst
                    data.withUnsafeBytes { dataPtr in
                        guard let dstBase = dstPtr.baseAddress,
                              let srcBase = srcPtr.baseAddress,
                              let dataBase = dataPtr.baseAddress else {
                            logger.error("[UDP] NULL base address in data pointers")
                            return
                        }
                        lwip_bridge_udp_sendto(
                            dstBase, self.dstPort,   // response source = original destination
                            srcBase, self.srcPort,   // response destination = original source
                            self.isIPv6 ? 1 : 0,
                            dataBase, Int32(data.count)
                        )
                    }
                }
            }
        }
    }

    // MARK: - Close

    func close() {
        guard !closed else { return }
        closed = true
        releaseProxy()
    }

    private func releaseProxy() {
        let relay = directRelay
        let ssRelay = ssUDPRelay
        let connection = proxyConnection
        let client = proxyClient
        let session = muxSession
        directRelay = nil
        ssUDPRelay = nil
        proxyConnection = nil
        proxyClient = nil
        muxSession = nil
        proxyConnecting = false
        pendingData.removeAll()
        pendingBufferSize = 0
        relay?.cancel()
        ssRelay?.cancel()
        connection?.cancel()
        client?.cancel()
        session?.close()
    }

    deinit {
        directRelay?.cancel()
        ssUDPRelay?.cancel()
        proxyConnection?.cancel()
        proxyClient?.cancel()
        muxSession?.close()
    }
}
