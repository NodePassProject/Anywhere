//
//  UDPFlow.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

private let logger = AnywhereLogger(category: "UDP")

class UDPFlow {
    let flowKey: TunnelStack.UDPFlowKey
    let srcHost: String
    let srcPort: UInt16
    let dstHost: String
    let dstPort: UInt16
    let isIPv6: Bool
    let configuration: ProxyConfiguration
    /// The stack's ``TunnelStack/udpQueue``. This flow's mutable state is
    /// confined to it; every async I/O callback hops back here before touching
    /// that state, so the flow needs no internal locking.
    let flowQueue: DispatchQueue

    // Raw IP bytes for building the response packet (swapped src/dst).
    let srcIPBytes: Data  // original source (becomes dst in response)
    let dstIPBytes: Data  // original destination (becomes src in response)

    var lastActivity: TimeInterval = MonotonicClock.now

    /// Count of downlink datagrams the destination has sent back. Every downlink
    /// path funnels through ``handleProxyData``, so that's the single place it
    /// increments. While it is below ``TunnelConstants/udpStreamMinReplies`` the
    /// flow is treated as one-way/speculative or a one-shot request/response
    /// probe (STUN binding, a single DNS lookup) and uses the shorter
    /// ``TunnelConstants/udpIdleTimeoutUnreplied``; once it reaches the threshold
    /// it is an established bidirectional **stream** on the longer
    /// ``TunnelConstants/udpIdleTimeoutStream``.
    var replyCount = 0

    /// Monotonic timestamp (``MonotonicClock``) at which this flow goes idle
    /// given its current state: last activity plus the unreplied (30s) or stream
    /// (120s) timeout. The cleanup reaper drops a flow once `now` passes this,
    /// and global-cap eviction picks the flow with the smallest deadline (least
    /// time left) — so unreplied probes are shed before established flows.
    var idleDeadline: TimeInterval {
        lastActivity + (replyCount >= TunnelConstants.udpStreamMinReplies
                        ? TunnelConstants.udpIdleTimeoutStream
                        : TunnelConstants.udpIdleTimeoutUnreplied)
    }

    // Direct bypass path
    private var directSocket: RawUDPSocket?

    // Non-mux path
    private var proxyClient: ProxyClient?
    private var proxyConnection: ProxyConnection?

    // Shadowsocks shared UDP session + our registration token into it.
    // The session is owned by TunnelStack and shared across every flow for
    // this configuration; we only hold a borrowed reference until close().
    private weak var ssUDPSession: ShadowsocksUDPSession?
    private var ssUDPSessionToken: ShadowsocksUDPSession.Token?

    // Mux path
    private var muxSession: MuxSession?

    private var proxyConnecting = false

    /// Committed routing identity for this flow — the single source of truth for
    /// traffic accounting and the dial path. Fixed at creation (UDP has no SNI
    /// re-routing).
    private let routeTarget: RouteTarget

    /// Dial straight out iff the committed route is ``RouteTarget/direct``.
    private var bypass: Bool {
        if case .direct = routeTarget { return true }
        return false
    }

    private var pendingData: [Data] = []  // always raw payloads (framing deferred to send time)
    private var pendingBufferSize = 0      // current total size of pendingData
    private var didWarnPendingOverflow = false
    private var closed = false

    /// One-shot reporter that logs this flow's terminal failure at most once.
    /// All terminal-error paths funnel through it, so a dead flow emits exactly
    /// one error line however many of them trip.
    private let failureReporter = ConnectionFailureReporter(prefix: "[UDP]", logger: logger)


    init(flowKey: TunnelStack.UDPFlowKey,
         srcHost: String, srcPort: UInt16,
         dstHost: String, dstPort: UInt16,
         srcIPData: Data, dstIPData: Data,
         isIPv6: Bool,
         configuration: ProxyConfiguration,
         routeTarget: RouteTarget,
         flowQueue: DispatchQueue) {
        self.flowKey = flowKey
        self.srcHost = srcHost
        self.srcPort = srcPort
        self.dstHost = dstHost
        self.dstPort = dstPort
        self.srcIPBytes = srcIPData
        self.dstIPBytes = dstIPData
        self.isIPv6 = isIPv6
        self.configuration = configuration
        self.routeTarget = routeTarget
        self.flowQueue = flowQueue
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

    /// Routes a send-side error from the proxy connection: terminal errors
    /// (connection gone for good — peer rejected, session closed, outer QUIC
    /// torn down) close the flow so the consumer doesn't keep funneling
    /// packets into a black hole until the receive side independently
    /// discovers the break. Transient errors (per-packet MTU collapses,
    /// queue overflows, fragmentation refusals) just log; UDP is lossy and
    /// the flow stays alive.
    ///
    /// Must be called on `flowQueue`.
    private func handleProxySendError(_ error: Error, connection: ProxyConnection) {
        if Self.isTerminalProxySendError(error, connection: connection) {
            reportFailure("Send", error: error)
            close()
            TunnelStack.shared?.removeUDPFlow(self)
        } else {
            logTransientSendFailure(error)
        }
    }

    /// Classifies a proxy-connection send error. Terminal = the connection
    /// is gone for good (matches the receive-side teardown path the inner
    /// connection's error handler will eventually trip too). Transient =
    /// this datagram didn't fit / didn't make it, but the connection is
    /// still usable.
    private static func isTerminalProxySendError(_ error: Error, connection: ProxyConnection) -> Bool {
        if let hErr = error as? HysteriaError {
            switch hErr {
            case .streamClosed, .authRejected, .udpNotSupported,
                 .destinationTooLargeForDatagram:
                // `destinationTooLargeForDatagram` is permanent for the
                // flow's destination — the address (and therefore the
                // header size) never shrinks. Closing the flow here
                // surfaces the failure as one log line; otherwise the
                // send-side classifier would log "transient" on every
                // packet until the receive side independently failed.
                return true
            case .notReady, .connectionFailed, .tunnelFailed:
                return false
            }
        }
        if let nErr = error as? NowhereError {
            switch nErr {
            case .streamClosed, .authFailed, .invalidTargetLength,
                 .destinationTooLargeForDatagram:
                return true
            case .notReady, .connectionFailed:
                return false
            }
        }
        if let qErr = error as? QUICConnection.QUICError {
            switch qErr {
            case .closed, .streamReset, .streamClosedWithError, .handshakeFailed:
                return true
            case .datagramTooLarge, .connectionFailed, .streamError, .timeout:
                return false
            }
        }
        // Unknown error types: fall back to the connection's own liveness
        // signal. `isConnected` is cheap on the protocols we care about
        // (HysteriaUDPConnection is a direct read of state on its session
        // queue; the others read in-memory flags). When the connection
        // says it's gone, treat the send error as terminal.
        return !connection.isConnected
    }

    // MARK: - Data Handling (called on flowQueue)

    func handleReceivedData(_ data: Data, payloadLength: Int) {
        guard !closed else { return }
        lastActivity = MonotonicClock.now
        
        TunnelStack.shared?.addBytesOut(Int64(payloadLength), target: routeTarget)

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
                guard let self, let error else { return }
                self.flowQueue.async {
                    guard !self.closed else { return }
                    self.handleProxySendError(error, connection: connection)
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

        if bypass {
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
            let isDefaultConfiguration = TunnelStack.shared?.isDefaultConfiguration(configuration.id) ?? false
            if configuration.outboundProtocol == .vless, isDefaultConfiguration, let muxManager = TunnelStack.shared?.muxManager {
                proxyConnecting = true
                connectViaMux(muxManager: muxManager)
                return
            }
            
            if configuration.outboundProtocol == .shadowsocks {
                connectShadowsocksUDP()
                return
            }
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

            self.flowQueue.async {
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
                        self.flowQueue.async {
                            if let error {
                                self.reportFailure("Mux", error: error)
                            }
                            self.close()
                            TunnelStack.shared?.removeUDPFlow(self)
                        }
                    }

                    // Guard against race: closeAll() may have already closed the
                    // session (via receive-loop error) before this handler ran.
                    guard !session.closed else {
                        self.close()
                        TunnelStack.shared?.removeUDPFlow(self)
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
                    TunnelStack.shared?.removeUDPFlow(self)
                }
            }
        }
    }

    /// ProxyClient path: handles chain building + all protocols (VLESS, Shadowsocks, etc.).
    private func connectViaProxyClient() {
        let client = ProxyClient(
            configuration: configuration,
            isDefaultProxy: TunnelStack.shared?.isDefaultConfiguration(configuration.id) ?? false
        )
        self.proxyClient = client

        client.connectUDP(to: dstHost, port: dstPort) { [weak self] result in
            guard let self else { return }

            self.flowQueue.async {
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
                            guard let self, let error else { return }
                            self.flowQueue.async {
                                guard !self.closed else { return }
                                self.handleProxySendError(error, connection: proxyConnection)
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
                    TunnelStack.shared?.removeUDPFlow(self)
                }
            }
        }
    }

    private func connectShadowsocksUDP() {
        guard ssUDPSession == nil && !closed else { return }

        guard let stack = TunnelStack.shared else {
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
            stack.removeUDPFlow(self)
            return
        }

        // Register against the shared session. The shared session handles
        // connect + pending-send buffering internally; no `proxyConnecting`
        // dance needed here.
        //
        // Seed response-address hints with whatever's already in the DNS
        // cache. Fresh resolutions aren't forced here because the cache
        // lookup is synchronous and flowQueue is performance-critical; the
        // async prewarm below handles cache misses.
        let cachedHints = DNSResolver.shared.cachedIPs(for: dstHost) ?? []

        let token = session.register(
            dstHost: dstHost,
            dstPort: dstPort,
            responseHostHints: cachedHints,
            handler: { [weak self] data in
                self?.handleProxyData(data)
            },
            errorHandler: { [weak self] error in
                guard let self else { return }
                self.flowQueue.async {
                    self.reportFailure("Receive", error: error)
                    self.close()
                    TunnelStack.shared?.removeUDPFlow(self)
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
            let localQueue = flowQueue
            DispatchQueue.global(qos: .userInitiated).async {
                let ips = DNSResolver.shared.resolveAll(host)
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

        // Direct bypass is one socket per peer 5-tuple; size its kernel buffers
        // modestly so a NAT-traversal storm of these can't blow the extension's
        // memory cap. The 4 MB default is reserved for the proxy-relay
        // transports. See ``SocketHelpers/directDatagramSocketBufferSize``.
        let socket = RawUDPSocket(socketBufferSize: SocketHelpers.directDatagramSocketBufferSize)
        self.directSocket = socket
        socket.connect(host: dstHost, port: dstPort, completionQueue: flowQueue) { [weak self] error in
            guard let self else { return }

            self.flowQueue.async {
                self.proxyConnecting = false
                guard !self.closed else { return }

                if let error {
                    self.reportFailure("Connect", error: error)
                    self.close()
                    TunnelStack.shared?.removeUDPFlow(self)
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
                    self.flowQueue.async {
                        self.reportFailure("Receive", error: error)
                        self.close()
                        TunnelStack.shared?.removeUDPFlow(self)
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
            self.flowQueue.async {
                if let error {
                    self.reportFailure("Receive", error: error)
                }
                self.close()
                TunnelStack.shared?.removeUDPFlow(self)
            }
        }
    }

    private func handleProxyData(_ data: Data) {
        flowQueue.async { [weak self] in
            guard let self, !self.closed else { return }
            self.lastActivity = MonotonicClock.now
            // Count this reply. The flow promotes from the 30s unreplied timeout
            // to the 120s established one only after ``udpStreamMinReplies``
            // replies — a single answer (STUN binding, one-shot DNS) is a probe,
            // not a stream (see ``replyCount`` / ``idleDeadline``).
            self.replyCount += 1
            
            TunnelStack.shared?.addBytesIn(Int64(data.count), target: self.routeTarget)

            // Emit the UDP response back to the app, swapping the 5-tuple:
            // response source = original destination, dest = original source.
            TunnelStack.shared?.writeOutboundUDP(
                srcIP: self.dstIPBytes, srcPort: self.dstPort,
                dstIP: self.srcIPBytes, dstPort: self.srcPort,
                isIPv6: self.isIPv6, payload: data
            )
        }
    }

    /// True if this flow currently owns a direct-bypass POSIX UDP FD that
    /// can be cleanly released. Direct flows are the only flows eligible
    /// for FD-pressure eviction — proxied flows either hold TCP FDs (kept
    /// under the TCP-first relief policy) or share mux/SS sockets where
    /// closing the flow doesn't free a per-flow FD.
    ///
    /// Mid-connect flows (`proxyConnecting == true`) are excluded: their
    /// `RawUDPSocket.ioQueue` may be blocked inside `getaddrinfo`, which
    /// would stall the relief path's synchronous `cancelSync` cross-hop.
    var holdsDirectFD: Bool { directSocket != nil && !proxyConnecting }

    // MARK: - Close

    func close() {
        guard !closed else { return }
        closed = true
        releaseProxy(syncSocket: false)
    }

    /// Synchronous variant of ``close`` used by the FD-pressure relief
    /// path: closes the underlying direct UDP socket before returning so
    /// the FD is actually freed (not just `async`-scheduled for close) by
    /// the time the caller retries `socket(2)`.
    func closeSync() {
        guard !closed else { return }
        closed = true
        releaseProxy(syncSocket: true)
    }

    private func releaseProxy(syncSocket: Bool) {
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
        if syncSocket {
            socket?.cancelSync()
        } else {
            socket?.cancel()
        }
        // The SS session is owned by TunnelStack and shared across every flow
        // for this configuration; unregister but never cancel the session.
        if let ssSession, let ssToken {
            ssSession.unregister(token: ssToken)
        }
        connection?.cancel()
        client?.cancel()
        session?.close()
    }
}
