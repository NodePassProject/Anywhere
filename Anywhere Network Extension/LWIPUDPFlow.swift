//
//  LWIPUDPFlow.swift
//  Network Extension
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

private let logger = TunnelLogger(category: "LWIP-UDP")

class LWIPUDPFlow {
    let flowKey: LWIPStack.UDPFlowKey
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

    init(flowKey: LWIPStack.UDPFlowKey,
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

    private static func conciseErrorDescription(_ error: Error) -> String {
        var message = error.localizedDescription.trimmingCharacters(in: .whitespacesAndNewlines)
        let redundantPrefixes = [
            "Connection failed: ",
            "Send failed: ",
            "Receive failed: ",
            "DNS resolution failed: "
        ]

        for prefix in redundantPrefixes where message.hasPrefix(prefix) {
            message.removeFirst(prefix.count)
            break
        }

        return message
    }

    private func logTransportFailure(_ operation: String, error: Error, defaultLevel: LWIPStack.LogLevel) {
        let errorDescription = Self.conciseErrorDescription(error)

        if let interruption = LWIPStack.shared?.recentTunnelInterruptionContext() {
            if interruption.level == .info {
                logger.debug("[UDP] \(operation) ended after \(interruption.summary): \(flowKey): \(errorDescription)")
            } else {
                logger.warning("[UDP] \(operation) interrupted after \(interruption.summary): \(flowKey) (\(errorDescription))")
            }
            return
        }

        switch defaultLevel {
        case .info:
            logger.info("[UDP] \(operation) failed: \(flowKey): \(errorDescription)")
        case .warning:
            logger.warning("[UDP] \(operation) failed: \(flowKey): \(errorDescription)")
        case .error:
            logger.error("[UDP] \(operation) failed: \(flowKey): \(errorDescription)")
        }
    }

    // MARK: - Data Handling (called on lwipQueue)

    func handleReceivedData(_ data: Data, payloadLength: Int) {
        guard !closed else { return }
        lastActivity = CFAbsoluteTimeGetCurrent()

        // Buffer data while the outbound connection is being established.
        // directRelay is set before its socket connects; sending to an
        // unconnected UDP socket silently drops the datagram.
        if proxyConnecting {
            bufferPayload(data: data, payloadLength: payloadLength)
            return
        }

        let payload = data.prefix(payloadLength)

        // Direct bypass path
        if let relay = directRelay {
            relay.send(data: payload)
            return
        }

        // Shadowsocks direct UDP relay
        if let relay = ssUDPRelay {
            relay.send(data: payload)
            return
        }

        // Mux path: send raw payload (mux framing handled by MuxSession)
        if let session = muxSession {
            session.send(data: payload) { [weak self] error in
                if let error {
                    self?.logTransportFailure("Send", error: error, defaultLevel: .warning)
                }
            }
            return
        }

        // Non-mux path: send payload through proxy connection
        if let connection = proxyConnection {
            if configuration.outboundProtocol == .shadowsocks {
                // SS connection handles encryption; send raw payload
                connection.send(data: payload) { [weak self] error in
                    if let error {
                        self?.logTransportFailure("Send", error: error, defaultLevel: .warning)
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
        pendingData.append(data.prefix(payloadLength))
        pendingBufferSize += payloadLength
    }

    private func sendUDPThroughProxy(connection: ProxyConnection, payload: Data, payloadLength: Int) {
        let slice = payload.prefix(payloadLength)
        var framedPayload = Data(capacity: 2 + slice.count)
        framedPayload.append(UInt8(slice.count >> 8))
        framedPayload.append(UInt8(slice.count & 0xFF))
        framedPayload.append(slice)

        connection.sendRaw(data: framedPayload) { [weak self] error in
            if let error {
                self?.logTransportFailure("Send", error: error, defaultLevel: .warning)
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
        let hasChain = configuration.chain != nil && !configuration.chain!.isEmpty

        // ── Direct fast paths (no chain only) ──────────────────────────────
        //
        // Protocol-specific helpers (MuxManager, ShadowsocksUDPRelay) create
        // their own network connections and bypass ProxyClient, so they do NOT
        // go through connectThroughChainIfNeeded(). They must only be used
        // when the configuration has no chain. When a chain IS configured,
        // we always fall through to the ProxyClient path at the bottom, which
        // builds the chain tunnel before connecting to the exit proxy.

        if !hasChain {
            // Mux: only for VLESS with the default configuration (mux is tied to the default proxy)
            let isDefaultConfiguration = (LWIPStack.shared?.configuration?.id == configuration.id)
            if configuration.outboundProtocol == .vless, isDefaultConfiguration, let muxManager = LWIPStack.shared?.muxManager {
                connectViaMux(muxManager: muxManager)
                return
            }

            // Shadowsocks: direct UDP datagrams with per-packet encryption
            if configuration.outboundProtocol == .shadowsocks {
                connectShadowsocksUDP()
                return
            }
        }

        // Shadowsocks UDP: always use direct datagrams, even with a chain.
        // SS per-packet AEAD is designed for UDP datagrams, not TCP streams,
        // and the SS protocol has no UDP command byte for TCP tunneling.
        if hasChain && configuration.outboundProtocol == .shadowsocks {
            connectShadowsocksUDP()
            return
        }

        // ── General path: ProxyClient (chain-aware) ────────────────────────
        //
        // ProxyClient.connectUDP() calls connectThroughChainIfNeeded(), which
        // builds the chain tunnel when needed. This is the ONLY path used when
        // a chain is configured, ensuring intermediate proxies are never skipped.
        connectViaProxyClient()
    }

    // MARK: - Connection Strategies

    /// Mux path: dispatch through MuxManager (no chain — mux handles its own connections).
    private func connectViaMux(muxManager: MuxManager) {
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
                                self?.logTransportFailure("Send", error: error, defaultLevel: .warning)
                            }
                        }
                    }

                case .failure(let error):
                    if case .dropped = error as? ProxyError {} else {
                        self.logTransportFailure("Connect", error: error, defaultLevel: .error)
                    }
                    self.releaseProxy()
                    LWIPStack.shared?.udpFlows.removeValue(forKey: self.flowKey)
                }
            }
        }
    }

    /// ProxyClient path: handles chain building + all protocols (VLESS, Shadowsocks, etc.).
    private func connectViaProxyClient() {
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
                                        self?.logTransportFailure("Send", error: error, defaultLevel: .warning)
                                    }
                                }
                            }
                        } else {
                            // VLESS: frame each payload with 2-byte length prefix
                            let totalSize = self.pendingData.reduce(0) { $0 + 2 + $1.count }
                            var dataToSend = Data(capacity: totalSize)
                            for payload in self.pendingData {
                                dataToSend.append(UInt8(payload.count >> 8))
                                dataToSend.append(UInt8(payload.count & 0xFF))
                                dataToSend.append(payload)
                            }
                            proxyConnection.sendRaw(data: dataToSend) { [weak self] error in
                                if let error {
                                    self?.logTransportFailure("Send", error: error, defaultLevel: .warning)
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
                        self.logTransportFailure("Connect", error: error, defaultLevel: .error)
                    }
                    self.releaseProxy()
                    LWIPStack.shared?.udpFlows.removeValue(forKey: self.flowKey)
                }
            }
        }
    }

    private func connectShadowsocksUDP() {
        guard ssUDPRelay == nil && !closed else { return }

        guard let method = configuration.ssMethod,
              let cipher = ShadowsocksCipher(method: method),
              let password = configuration.ssPassword else {
            logger.error("[UDP] Invalid Shadowsocks config for \(flowKey)")
            proxyConnecting = false
            close()
            LWIPStack.shared?.udpFlows.removeValue(forKey: flowKey)
            return
        }

        let mode: ShadowsocksUDPRelay.Mode
        if cipher.isSS2022 {
            guard let psk = ShadowsocksKeyDerivation.decodePSK(password: password, keySize: cipher.keySize) else {
                logger.error("[UDP] Invalid SS2022 key for \(flowKey)")
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

        relay.connect(serverHost: configuration.serverAddress, serverPort: configuration.serverPort, lwipQueue: lwipQueue) { [weak self] error in
            guard let self else { return }

            self.lwipQueue.async {
                self.proxyConnecting = false
                guard !self.closed else { return }

                if let error {
                    self.logTransportFailure("Connect", error: error, defaultLevel: .error)
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
                    self.logTransportFailure("Connect", error: error, defaultLevel: .error)
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
                self.logTransportFailure("Recv", error: error, defaultLevel: .error)
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
                            logger.debug("[UDP] NULL base address in data pointers")
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
