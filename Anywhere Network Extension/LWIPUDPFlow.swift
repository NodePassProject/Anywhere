//
//  LWIPUDPFlow.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

private let logger = AnywhereLogger(category: "LWIP-UDP")

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
    private var directSocket: RawUDPSocket?

    // Non-mux path
    private var proxyClient: ProxyClient?
    private var proxyConnection: ProxyConnection?

    // Shadowsocks shared UDP session + our registration token into it.
    // The session is owned by LWIPStack and shared across every flow for
    // this configuration; we only hold a borrowed reference until close().
    private weak var ssUDPSession: ShadowsocksUDPSession?
    private var ssUDPSessionToken: ShadowsocksUDPSession.Token?

    // Mux path
    private var muxSession: MuxSession?

    private var proxyConnecting = false
    private var forceBypass = false
    private var pendingData: [Data] = []  // always raw payloads (framing deferred to send time)
    private var pendingBufferSize = 0      // current total size of pendingData
    private var didWarnPendingOverflow = false
    private var closed = false

    /// One-shot reporter that logs this flow's terminal failure at most once.
    /// All terminal-error paths funnel through it so the LWIP boundary emits
    /// exactly one error line per dead flow.
    private let failureReporter = ConnectionFailureReporter(prefix: "[UDP]", logger: logger)


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

    private func reportFailure(_ operation: String, error: Error) {
        failureReporter.report(operation: operation, endpoint: "\(flowKey)", error: error)
    }

    private func logTransientSendFailure(_ error: Error) {
        TransportErrorLogger.logTransientSend(
            endpoint: "\(flowKey)",
            error: error,
            logger: logger,
            prefix: "[UDP]"
        )
    }

    // MARK: - Data Handling (called on lwipQueue)

    func handleReceivedData(_ data: Data, payloadLength: Int) {
        guard !closed else { return }
        lastActivity = CFAbsoluteTimeGetCurrent()

        // Buffer data while the outbound connection is being established.
        // directSocket is set before its socket connects; sending to an
        // unconnected UDP socket silently drops the datagram.
        if proxyConnecting {
            bufferPayload(data: data, payloadLength: payloadLength)
            return
        }

        let payload = data.prefix(payloadLength)

        // Direct bypass path
        if let socket = directSocket {
            socket.send(data: payload) { [weak self] error in
                if let error {
                    self?.logTransientSendFailure(error)
                }
            }
            return
        }

        // Shadowsocks shared UDP session
        if let session = ssUDPSession, let token = ssUDPSessionToken {
            session.send(token: token, dstHost: dstHost, dstPort: dstPort, payload: payload) { [weak self] error in
                if let error {
                    self?.logTransientSendFailure(error)
                }
            }
            return
        }

        // Mux path: send raw payload (mux framing handled by MuxSession)
        if let session = muxSession {
            session.send(data: payload) { [weak self] error in
                if let error {
                    self?.logTransientSendFailure(error)
                }
            }
            return
        }

        // Non-mux path: hand the raw payload to the proxy connection. Each
        // protocol's UDP connection class applies its own per-packet wire
        // framing (VLESSUDPConnection adds the 2-byte length prefix,
        // ShadowsocksUDPConnection encrypts, HysteriaUDPConnection emits a
        // QUIC DATAGRAM, …).
        if let connection = proxyConnection {
            connection.send(data: payload) { [weak self] error in
                if let error {
                    self?.logTransientSendFailure(error)
                }
            }
            return
        }

        // No connection yet — buffer and start connecting
        bufferPayload(data: data, payloadLength: payloadLength)
        connectProxy()
    }

    private func bufferPayload(data: Data, payloadLength: Int) {
        // Drop datagram if buffer limit would be exceeded (DiscardOverflow)
        if pendingBufferSize + payloadLength > TunnelConstants.udpMaxBufferSize {
            if !didWarnPendingOverflow {
                didWarnPendingOverflow = true
                logger.warning("[UDP] Pending buffer overflow for \(flowKey); dropping datagrams until proxy connects")
            }
            return
        }
        pendingData.append(data.prefix(payloadLength))
        pendingBufferSize += payloadLength
    }

    // MARK: - Proxy Connection

    private func connectProxy() {
        guard !proxyConnecting && proxyConnection == nil && muxSession == nil && directSocket == nil && ssUDPSession == nil && !closed else { return }

        if forceBypass {
            connectDirectUDP()
            return
        }

        let hasChain = configuration.chain != nil && !configuration.chain!.isEmpty

        // ── Direct fast paths (no chain only) ──────────────────────────────
        //
        // Protocol-specific helpers (MuxManager, ShadowsocksUDPSession) manage
        // their own connections and bypass ProxyClient. They must only be
        // used when the configuration has no chain. When a chain IS
        // configured, we fall through to the ProxyClient path at the bottom,
        // which builds the chain tunnel before connecting to the exit proxy.

        if !hasChain {
            // Mux: only for VLESS with the default configuration (mux is tied to the default proxy)
            let isDefaultConfiguration = (LWIPStack.shared?.configuration?.id == configuration.id)
            if configuration.outboundProtocol == .vless, isDefaultConfiguration, let muxManager = LWIPStack.shared?.muxManager {
                proxyConnecting = true
                connectViaMux(muxManager: muxManager)
                return
            }

            // Shadowsocks: register with the shared per-configuration UDP
            // session (synchronous — session handles its own connect).
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
        proxyConnecting = true
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
                    // Set up handlers BEFORE checking closed state to prevent
                    // a race where close fires between the check and handler
                    // registration, which would leak the flow.
                    session.dataHandler = { [weak self] data in
                        self?.handleProxyData(data)
                    }
                    session.closeHandler = { [weak self] error in
                        guard let self else { return }
                        self.lwipQueue.async {
                            if let error {
                                self.reportFailure("Mux", error: error)
                            }
                            self.close()
                            LWIPStack.shared?.udpFlows.removeValue(forKey: self.flowKey)
                        }
                    }

                    // Guard against race: closeAll() may have already closed the
                    // session (via receive-loop error) before this handler ran.
                    guard !session.closed else {
                        self.close()
                        LWIPStack.shared?.udpFlows.removeValue(forKey: self.flowKey)
                        return
                    }

                    self.muxSession = session

                    // Send buffered raw payloads
                    let buffered = self.pendingData
                    self.pendingData.removeAll()
                    self.pendingBufferSize = 0
                    for payload in buffered {
                        session.send(data: payload) { [weak self] error in
                            if let error {
                                self?.logTransientSendFailure(error)
                            }
                        }
                    }

                case .failure(let error):
                    if case .dropped = error as? ProxyError {} else {
                        self.reportFailure("Connect", error: error)
                    }
                    self.close()
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

                    // Drain buffered payloads. `send` preserves packet
                    // boundaries — each protocol's UDP connection applies its
                    // own wire framing.
                    for payload in self.pendingData {
                        proxyConnection.send(data: payload) { [weak self] error in
                            if let error {
                                self?.logTransientSendFailure(error)
                            }
                        }
                    }
                    self.pendingData.removeAll()
                    self.pendingBufferSize = 0

                    // Start receiving proxy responses
                    self.startProxyReceiving(proxyConnection: proxyConnection)

                case .failure(let error):
                    if case .dropped = error as? ProxyError {} else {
                        self.reportFailure("Connect", error: error)
                    }
                    self.close()
                    LWIPStack.shared?.udpFlows.removeValue(forKey: self.flowKey)
                }
            }
        }
    }

    private func connectShadowsocksUDP() {
        guard ssUDPSession == nil && !closed else { return }

        guard let stack = LWIPStack.shared else {
            close()
            return
        }

        let sessionResult = stack.shadowsocksUDPSession(for: configuration)
        let session: ShadowsocksUDPSession
        switch sessionResult {
        case .success(let s):
            session = s
        case .failure(let error):
            reportFailure("SS session", error: error)
            close()
            stack.udpFlows.removeValue(forKey: flowKey)
            return
        }

        // Register against the shared session. The shared session handles
        // connect + pending-send buffering internally; no `proxyConnecting`
        // dance needed here.
        //
        // Seed response-address hints with whatever's already in the DNS
        // cache. Fresh resolutions aren't forced here because the cache
        // lookup is synchronous and lwipQueue is performance-critical; the
        // async prewarm below handles cache misses.
        let cachedHints = ProxyDNSCache.shared.cachedIPs(for: dstHost) ?? []

        let token = session.register(
            dstHost: dstHost,
            dstPort: dstPort,
            responseHostHints: cachedHints,
            handler: { [weak self] data in
                self?.handleProxyData(data)
            },
            errorHandler: { [weak self] error in
                guard let self else { return }
                self.lwipQueue.async {
                    self.reportFailure("Receive", error: error)
                    self.close()
                    LWIPStack.shared?.udpFlows.removeValue(forKey: self.flowKey)
                }
            }
        )

        self.ssUDPSession = session
        self.ssUDPSessionToken = token

        // Drain anything buffered while we were deciding how to connect.
        // The session itself buffers again if its socket isn't ready yet.
        let host = dstHost
        let port = dstPort
        for payload in pendingData {
            session.send(token: token, dstHost: host, dstPort: port, payload: payload) { [weak self] error in
                if let error {
                    self?.logTransientSendFailure(error)
                }
            }
        }
        pendingData.removeAll()
        pendingBufferSize = 0

        // If the destination is a domain that's not yet in the DNS cache,
        // kick off an async resolve so subsequent replies can route by
        // exact IP match instead of relying on the port-only fallback
        // (which misroutes when multiple flows share a destination port —
        // e.g. concurrent QUIC connections on 443).
        if cachedHints.isEmpty, Self.isDomainName(host) {
            let weakSession = session
            let localQueue = lwipQueue
            DispatchQueue.global(qos: .userInitiated).async {
                let ips = ProxyDNSCache.shared.resolveAll(host)
                guard !ips.isEmpty else { return }
                localQueue.async { [weak weakSession] in
                    weakSession?.addResponseHints(token: token, hints: ips)
                }
            }
        }
    }

    /// True when `host` looks like a domain name (not an IPv4/IPv6 literal).
    /// Used to decide whether an async DNS resolve is worth attempting for
    /// response-address hinting.
    private static func isDomainName(_ host: String) -> Bool {
        let bare: String
        if host.hasPrefix("[") && host.hasSuffix("]") {
            bare = String(host.dropFirst().dropLast())
        } else {
            bare = host
        }
        var v4 = in_addr()
        if inet_pton(AF_INET, bare, &v4) == 1 { return false }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, bare, &v6) == 1 { return false }
        return !bare.isEmpty
    }

    private func connectDirectUDP() {
        guard directSocket == nil && !closed else { return }
        proxyConnecting = true  // reuse flag to prevent re-entry

        let socket = RawUDPSocket()
        self.directSocket = socket
        socket.connect(host: dstHost, port: dstPort, completionQueue: lwipQueue) { [weak self] error in
            guard let self else { return }

            self.lwipQueue.async {
                self.proxyConnecting = false
                guard !self.closed else { return }

                if let error {
                    self.reportFailure("Connect", error: error)
                    self.close()
                    LWIPStack.shared?.udpFlows.removeValue(forKey: self.flowKey)
                    return
                }

                // Send buffered payloads
                for payload in self.pendingData {
                    socket.send(data: payload) { [weak self] error in
                        if let error {
                            self?.logTransientSendFailure(error)
                        }
                    }
                }
                self.pendingData.removeAll()
                self.pendingBufferSize = 0

                // Start receiving responses. Non-EAGAIN recv errors close the
                // flow so we don't sit on a dead socket.
                socket.startReceiving(handler: { [weak self] data in
                    self?.handleProxyData(data)
                }, errorHandler: { [weak self] error in
                    guard let self else { return }
                    self.lwipQueue.async {
                        self.reportFailure("Receive", error: error)
                        self.close()
                        LWIPStack.shared?.udpFlows.removeValue(forKey: self.flowKey)
                    }
                })
            }
        }
    }

    private func startProxyReceiving(proxyConnection: ProxyConnection) {
        proxyConnection.startReceiving { [weak self] data in
            guard let self else { return }
            self.handleProxyData(data)
        } errorHandler: { [weak self] error in
            guard let self else { return }
            self.lwipQueue.async {
                if let error {
                    self.reportFailure("Receive", error: error)
                }
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
        let socket = directSocket
        let ssSession = ssUDPSession
        let ssToken = ssUDPSessionToken
        let connection = proxyConnection
        let client = proxyClient
        let session = muxSession
        directSocket = nil
        ssUDPSession = nil
        ssUDPSessionToken = nil
        proxyConnection = nil
        proxyClient = nil
        muxSession = nil
        proxyConnecting = false
        pendingData.removeAll()
        pendingBufferSize = 0
        socket?.cancel()
        // The SS session is owned by LWIPStack and shared across every flow
        // for this configuration; unregister but never cancel the session.
        if let ssSession, let ssToken {
            ssSession.unregister(token: ssToken)
        }
        connection?.cancel()
        client?.cancel()
        session?.close()
    }
}
