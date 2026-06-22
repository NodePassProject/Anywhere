//
//  UDPFlow.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "UDPFlow")

class UDPFlow {
    let flowKey: TunnelStack.UDPFlowKey
    let srcHost: String
    let srcPort: UInt16
    let dstHost: String
    let dstPort: UInt16
    let isIPv6: Bool
    let configuration: ProxyConfiguration
    /// All mutable state is confined to this queue, so the flow needs no locking.
    let flowQueue: DispatchQueue

    // Raw IP bytes for building the response packet (swapped src/dst).
    let srcIPBytes: Data
    let dstIPBytes: Data

    var lastActivity: TimeInterval = MonotonicClock.now

    /// Downlink datagrams received; at udpStreamMinReplies the flow graduates
    /// from the short unreplied timeout to the longer stream timeout.
    var replyCount = 0

    /// Monotonic expiry instant; eviction picks the smallest deadline, so
    /// unreplied probes are shed before established streams.
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

    // Shared SS UDP session owned by TunnelStack; borrowed only.
    private weak var ssUDPSession: ShadowsocksUDPSession?
    private var ssUDPSessionToken: ShadowsocksUDPSession.Token?

    // Mux path
    private var udpStream: VLESSVisionUDPStream?

    private var proxyConnecting = false

    /// Routing identity for accounting and dialing; fixed at creation (UDP has no SNI re-routing).
    private let routeTarget: RouteTarget

    private var bypass: Bool {
        if case .direct = routeTarget { return true }
        return false
    }

    private var pendingData: [Data] = []  // always raw payloads (framing applied at send time)
    private var pendingBufferSize = 0
    private var didWarnPendingOverflow = false
    private var closed = false

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

    /// Terminal send errors close the flow; transient ones just log (UDP is lossy). Call on flowQueue.
    private func handleProxySendError(_ error: Error, connection: ProxyConnection) {
        if Self.isTerminalProxySendError(error, connection: connection) {
            reportFailure("Send", error: error)
            close()
            TunnelStack.shared?.removeUDPFlow(self)
        } else {
            logTransientSendFailure(error)
        }
    }

    /// Terminal = the connection is gone for good; transient = the connection is still usable.
    private static func isTerminalProxySendError(_ error: Error, connection: ProxyConnection) -> Bool {
        if let quicError = error as? QUICConnection.QUICError {
            switch quicError {
            case .handshakeFailed, .streamReset, .streamClosedWithError, .closed, .closedOK:
                return true
            case .datagramTooLarge, .connectionFailed, .streamError, .timeout:
                return false
            }
        }
        if let hysteriaError = error as? HysteriaError {
            switch hysteriaError {
            case .authRejected, .udpNotSupported, .destinationTooLargeForDatagram, .streamClosed:
                return true
            case .notReady, .connectionFailed, .tunnelFailed:
                return false
            }
        }
        if let nowhereError = error as? NowhereError {
            switch nowhereError {
            case .authFailed, .invalidTargetLength, .destinationTooLargeForDatagram, .streamClosed:
                return true
            case .notReady, .connectionFailed:
                return false
            }
        }
        // Unknown error types: fall back to the connection's own liveness signal.
        return !connection.isConnected
    }

    // MARK: - Data Handling (called on flowQueue)

    func handleReceivedData(_ data: Data, payloadLength: Int) {
        guard !closed else { return }
        lastActivity = MonotonicClock.now
        
        TunnelStack.shared?.addBytesOut(Int64(payloadLength), target: routeTarget)

        // Buffer while connecting: sends on an unconnected UDP socket are silently dropped.
        if proxyConnecting {
            bufferPayload(data: data, payloadLength: payloadLength)
            return
        }

        let payload = data.prefix(payloadLength)

        if let socket = directSocket {
            socket.send(data: payload) { [weak self] error in
                if let error {
                    self?.logTransientSendFailure(error)
                }
            }
            return
        }

        if let session = ssUDPSession, let token = ssUDPSessionToken {
            session.send(token: token, dstHost: dstHost, dstPort: dstPort, payload: payload) { [weak self] error in
                if let error {
                    self?.logTransientSendFailure(error)
                }
            }
            return
        }

        if let session = udpStream {
            session.send(data: payload) { [weak self] error in
                if let error {
                    self?.logTransientSendFailure(error)
                }
            }
            return
        }

        // Raw payload; each protocol's UDP connection applies its own per-packet wire framing.
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

        bufferPayload(data: data, payloadLength: payloadLength)
        connectProxy()
    }

    private func bufferPayload(data: Data, payloadLength: Int) {
        // Bound the buffer against a stalled connect; dropping is fine since UDP is lossy.
        if pendingBufferSize + payloadLength > TunnelConstants.udpMaxBufferSize {
            PerformanceMonitor.event(.udpBufferOverflow)
            if !didWarnPendingOverflow {
                didWarnPendingOverflow = true
                logger.warning("[UDP] Pending buffer overflow for \(flowKey); dropping datagrams until proxy connects")
            }
            return
        }
        pendingData.append(data.prefix(payloadLength))
        pendingBufferSize += payloadLength
        PerformanceMonitor.gauge(.udpFlowPendingBytes, pendingBufferSize, highWater: TunnelConstants.udpMaxBufferSize)
    }

    // MARK: - Proxy Connection

    private func connectProxy() {
        guard !proxyConnecting && proxyConnection == nil && udpStream == nil && directSocket == nil && ssUDPSession == nil && !closed else { return }

        if bypass {
            connectDirectUDP()
            return
        }

        let hasChain = configuration.chain != nil && !configuration.chain!.isEmpty

        // Fast paths bypass ProxyClient, so they must only run when no chain is configured.
        if !hasChain {
            let isDefaultConfiguration = TunnelStack.shared?.isDefaultConfiguration(configuration.id) ?? false
            if configuration.outboundProtocol == .vless, isDefaultConfiguration, let udpMultiplexerPool = TunnelStack.shared?.udpMultiplexerPool {
                proxyConnecting = true
                connectViaMultiplexer(udpMultiplexerPool: udpMultiplexerPool)
                return
            }
            
            if configuration.outboundProtocol == .shadowsocks {
                connectShadowsocksUDP()
                return
            }
        }

        // ProxyClient builds the chain tunnel when needed — the only valid path with a chain.
        proxyConnecting = true
        connectViaProxyClient()
    }

    // MARK: - Connection Strategies

    private func connectViaMultiplexer(udpMultiplexerPool: VLESSVisionUDPMultiplexerPool) {
        // Stable per-source globalID lets the server pin one upstream session (Full Cone NAT).
        let globalID = VLESSVisionUDPGlobalID.generateGlobalID(sourceAddress: "udp:\(srcHost):\(srcPort)")
        udpMultiplexerPool.acquireStream(network: .udp, host: dstHost, port: dstPort, globalID: globalID) { [weak self] result in
            guard let self else { return }

            self.flowQueue.async {
                self.proxyConnecting = false
                guard !self.closed else { return }

                switch result {
                case .success(let session):
                    // Install handlers before the closed check; close firing between them would leak the flow.
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

                    // closeAll() may have already closed the session before this ran.
                    guard !session.closed else {
                        self.close()
                        TunnelStack.shared?.removeUDPFlow(self)
                        return
                    }

                    self.udpStream = session

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

                    // Drain buffered payloads; `send` preserves packet boundaries.
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

        // The shared session buffers sends until its socket connects, so no `proxyConnecting`
        // dance is needed. Hints use the synchronous DNS cache only (flowQueue is
        // performance-critical); the async prewarm below handles misses.
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

        // Drain what buffered meanwhile; the session re-buffers if its socket isn't ready yet.
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

        // Async-resolve uncached domains so replies route by exact IP; the port-only
        // fallback misroutes flows sharing a destination port (e.g. QUIC on 443).
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

    /// True when `host` is not an IPv4/IPv6 literal.
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
        proxyConnecting = true  // reuse the flag so datagrams buffer until the socket connects

        // One socket per peer 5-tuple; modest kernel buffers keep a NAT-traversal
        // storm under the extension's memory cap.
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

                for payload in self.pendingData {
                    socket.send(data: payload) { [weak self] error in
                        if let error {
                            self?.logTransientSendFailure(error)
                        }
                    }
                }
                self.pendingData.removeAll()
                self.pendingBufferSize = 0

                // Non-EAGAIN recv errors close the flow so we don't sit on a dead socket.
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
            self.replyCount += 1
            
            TunnelStack.shared?.addBytesIn(Int64(data.count), target: self.routeTarget)

            // Swap the 5-tuple: response source = original destination, and vice versa.
            TunnelStack.shared?.writeOutboundUDP(
                srcIP: self.dstIPBytes, srcPort: self.dstPort,
                dstIP: self.srcIPBytes, dstPort: self.srcPort,
                isIPv6: self.isIPv6, payload: data
            )
        }
    }

    /// True when this flow owns a per-flow UDP FD eligible for FD-pressure eviction.
    /// Mid-connect flows are excluded: their ioQueue may be blocked in getaddrinfo,
    /// which would stall the relief path's synchronous cancelSync.
    var holdsDirectFD: Bool { directSocket != nil && !proxyConnecting }

    // MARK: - Close

    func close() {
        guard !closed else { return }
        closed = true
        releaseProxy(syncSocket: false)
    }

    /// Synchronous close for the FD-pressure relief path: the direct socket's FD
    /// is freed before returning, so the caller can retry `socket(2)`.
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
        let session = udpStream
        directSocket = nil
        ssUDPSession = nil
        ssUDPSessionToken = nil
        proxyConnection = nil
        proxyClient = nil
        udpStream = nil
        proxyConnecting = false
        pendingData.removeAll()
        pendingBufferSize = 0
        if syncSocket {
            socket?.cancelSync()
        } else {
            socket?.cancel()
        }
        // The SS session is shared and owned by TunnelStack; unregister, never cancel.
        if let ssSession, let ssToken {
            ssSession.unregister(token: ssToken)
        }
        connection?.cancel()
        client?.cancel()
        session?.close()
    }
}
