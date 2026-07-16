//
//  UDPFlow.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "UDPFlow")

class UDPFlow {
    /// The owning stack, for the flow registry, traffic accounting, shared
    /// sessions, and the TUN write-back. Weak: the stack can stop while late
    /// transport completions are still in flight.
    private weak var stack: TunnelStack?

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
    private var directTransport: UDPTransport?

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


    init(stack: TunnelStack,
         flowKey: TunnelStack.UDPFlowKey,
         srcHost: String, srcPort: UInt16,
         dstHost: String, dstPort: UInt16,
         srcIPData: Data, dstIPData: Data,
         isIPv6: Bool,
         configuration: ProxyConfiguration,
         routeTarget: RouteTarget,
         flowQueue: DispatchQueue) {
        self.stack = stack
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
            self.stack?.removeUDPFlow(self)
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
            case .datagramTooLarge, .datagramQueueFull, .connectionFailed, .streamError, .timeout:
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
            case .authFailed, .invalidTargetLength, .destinationTooLargeForDatagram, .streamClosed,
                    .flowRejected, .flowOpenTimeout:
                return true
            case .notReady, .connectionFailed, .udpPacketTooLarge:
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
        
        stack?.addBytesOut(Int64(payloadLength), target: routeTarget)

        // Buffer while connecting: sends on an unconnected UDP transport are silently dropped.
        if proxyConnecting {
            bufferPayload(data: data, payloadLength: payloadLength)
            return
        }

        let payload = data.prefix(payloadLength)

        if let transport = directTransport {
            // Datagrams are independent, so each send is its own task (no ordering pump).
            Task { [weak self] in
                do {
                    try await transport.send(payload)
                } catch {
                    self?.logTransientSendFailure(error)
                }
            }
            return
        }

        if let session = ssUDPSession, let token = ssUDPSessionToken {
            let host = dstHost
            let port = dstPort
            // Datagrams are independent; each send is its own task. The session serializes
            // its own state, so concurrent tasks can't corrupt packetID allocation.
            Task { [weak self] in
                do {
                    try await session.send(token: token, dstHost: host, dstPort: port, payload: payload)
                } catch {
                    self?.logTransientSendFailure(error)
                }
            }
            return
        }

        if let session = udpStream {
            Task { [weak self] in
                do {
                    try await session.send(data: payload)
                } catch {
                    self?.logTransientSendFailure(error)
                }
            }
            return
        }

        // Raw payload; each protocol's UDP connection applies its own per-packet wire framing.
        if let connection = proxyConnection {
            sendToProxyConnection(payload, connection: connection)
            return
        }

        bufferPayload(data: data, payloadLength: payloadLength)
        connectProxy()
    }

    /// Fire-and-forget async send to the proxy connection. Datagrams are independent, so
    /// each send is its own task; the connection serializes its own framed writes, so
    /// concurrent tasks can't interleave frames on a stream transport. A terminal send
    /// error closes the flow; transient ones just log (UDP is lossy).
    private func sendToProxyConnection(_ payload: Data, connection: ProxyConnection) {
        Task { [weak self] in
            do {
                try await connection.send(payload)
            } catch {
                guard let self else { return }
                self.flowQueue.async {
                    guard !self.closed else { return }
                    self.handleProxySendError(error, connection: connection)
                }
            }
        }
    }

    private func bufferPayload(data: Data, payloadLength: Int) {
        // Bound the buffer against a stalled connect; dropping is fine since UDP is lossy.
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
        guard !proxyConnecting && proxyConnection == nil && udpStream == nil && directTransport == nil && ssUDPSession == nil && !closed else { return }

        if bypass {
            connectDirectUDP()
            return
        }

        let hasChain = configuration.chain != nil && !configuration.chain!.isEmpty

        // Fast paths bypass ProxyClient, so they must only run when no chain is configured.
        if !hasChain {
            let isDefaultConfiguration = stack?.isDefaultConfiguration(configuration.id) ?? false
            if configuration.outboundProtocol == .vless, isDefaultConfiguration, let udpMultiplexerPool = stack?.udpMultiplexerPool {
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
        let host = dstHost
        let port = dstPort
        Task { [weak self] in
            let result: Result<VLESSVisionUDPStream, Error>
            do {
                result = .success(try await udpMultiplexerPool.acquireStream(
                    network: .udp, host: host, port: port, globalID: globalID))
            } catch {
                result = .failure(error)
            }
            guard let self else {
                if case .success(let session) = result { session.close() }
                return
            }

            self.flowQueue.async { [self] in
                self.proxyConnecting = false
                guard !self.closed else {
                    if case .success(let session) = result { session.close() }
                    return
                }

                switch result {
                case .success(let session):
                    // closeAll() may have already closed the session before this ran.
                    guard !session.closed else {
                        self.close()
                        self.stack?.removeUDPFlow(self)
                        return
                    }

                    self.udpStream = session
                    // Consume the stream's inbound channel: data pushes to the flow, EOF is a
                    // clean close, a thrown error is a transport failure.
                    self.startMuxReceiving(session: session)

                    let buffered = self.pendingData
                    self.pendingData.removeAll()
                    self.pendingBufferSize = 0
                    if !buffered.isEmpty {
                        // Drain in order in a single task so the XUDP New frame precedes Keeps.
                        Task { [weak self] in
                            for payload in buffered {
                                do {
                                    try await session.send(data: payload)
                                } catch {
                                    self?.logTransientSendFailure(error)
                                }
                            }
                        }
                    }

                case .failure(let error):
                    if case .dropped = error as? ProxyError {} else {
                        self.reportFailure("Connect", error: error)
                    }
                    self.close()
                    self.stack?.removeUDPFlow(self)
                }
            }
        }
    }

    /// Drives the mux stream's inbound `AsyncByteChannel`: EOF closes cleanly, an error
    /// reports and closes. Replaces the old `dataHandler`/`closeHandler` callbacks.
    private func startMuxReceiving(session: VLESSVisionUDPStream) {
        let inbox = session.inbox
        Task { [weak self] in
            do {
                while let data = try await inbox.next() {
                    self?.handleProxyData(data)
                }
                // Clean EOF (End frame / normal close): close without reporting a failure.
                guard let self else { return }
                self.flowQueue.async {
                    guard !self.closed else { return }
                    self.close()
                    self.stack?.removeUDPFlow(self)
                }
            } catch {
                guard let self else { return }
                self.flowQueue.async {
                    guard !self.closed else { return }
                    self.reportFailure("Mux", error: error)
                    self.close()
                    self.stack?.removeUDPFlow(self)
                }
            }
        }
    }

    private func connectViaProxyClient() {
        let client = ProxyClient(
            configuration: configuration,
            isDefaultProxy: stack?.isDefaultConfiguration(configuration.id) ?? false
        )
        self.proxyClient = client
        
        let host = dstHost
        let port = dstPort
        Task { [weak self] in
            let result: Result<ProxyConnection, Error>
            do {
                result = .success(try await client.connectUDP(to: host, port: port))
            } catch {
                result = .failure(error)
            }
            guard let self else {
                if case .success(let connection) = result { connection.cancel() }
                return
            }

            self.flowQueue.async { [self] in
                self.proxyConnecting = false
                guard !self.closed else {
                    if case .success(let connection) = result { connection.cancel() }
                    return
                }

                switch result {
                case .success(let proxyConnection):
                    self.proxyConnection = proxyConnection

                    // Drain buffered payloads; `send` preserves packet boundaries.
                    for payload in self.pendingData {
                        self.sendToProxyConnection(payload, connection: proxyConnection)
                    }
                    self.pendingData.removeAll()
                    self.pendingBufferSize = 0

                    self.startProxyReceiving(proxyConnection: proxyConnection)

                case .failure(let error):
                    if case .dropped = error as? ProxyError {} else {
                        self.reportFailure("Connect", error: error)
                    }
                    self.close()
                    self.stack?.removeUDPFlow(self)
                }
            }
        }
    }

    private func connectShadowsocksUDP() {
        guard ssUDPSession == nil && !closed else { return }

        guard let stack else {
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

        // Registration is now async (the session is an actor). Buffer datagrams and block
        // re-entry via `proxyConnecting` until the token + inbox land on flowQueue. Hints use
        // the synchronous DNS cache only (flowQueue is performance-critical); the async
        // prewarm below handles misses.
        proxyConnecting = true
        let cachedHints = DNSResolver.shared.cachedIPs(for: dstHost) ?? []
        let host = dstHost
        let port = dstPort

        Task { [weak self] in
            let (token, inbox) = await session.register(
                dstHost: host, dstPort: port, responseHostHints: cachedHints
            )
            guard let self else {
                await session.unregister(token: token)
                return
            }
            self.flowQueue.async {
                self.proxyConnecting = false
                guard !self.closed else {
                    Task { await session.unregister(token: token) }
                    return
                }

                self.ssUDPSession = session
                self.ssUDPSessionToken = token
                self.startShadowsocksReceiving(inbox: inbox)

                // Drain what buffered meanwhile, preserving order in a single task.
                let buffered = self.pendingData
                self.pendingData.removeAll()
                self.pendingBufferSize = 0
                if !buffered.isEmpty {
                    Task { [weak self] in
                        for payload in buffered {
                            do {
                                try await session.send(token: token, dstHost: host, dstPort: port, payload: payload)
                            } catch {
                                self?.logTransientSendFailure(error)
                            }
                        }
                    }
                }

                // Async-resolve uncached domains so replies route by exact IP; the port-only
                // fallback misroutes flows sharing a destination port (e.g. QUIC on 443).
                if cachedHints.isEmpty, Self.isDomainName(host) {
                    // Hold `session` weakly so a torn-down flow isn't pinned open across the
                    // blocking DNS resolve below.
                    DispatchQueue.global(qos: .userInitiated).async { [weak session] in
                        let ips = DNSResolver.shared.resolveAll(host)
                        guard !ips.isEmpty, let session else { return }
                        Task { await session.addResponseHints(token: token, hints: ips) }
                    }
                }
            }
        }
    }

    /// Drives the SS session's per-flow inbound `AsyncByteChannel`: data pushes to the flow,
    /// a thrown error reports and closes. Replaces the old `handler`/`errorHandler` callbacks.
    private func startShadowsocksReceiving(inbox: AsyncByteChannel) {
        Task { [weak self] in
            do {
                while let data = try await inbox.next() {
                    self?.handleProxyData(data)
                }
                // Clean EOF (unregister) — the flow is already tearing down; nothing to do.
            } catch {
                guard let self else { return }
                self.flowQueue.async {
                    guard !self.closed else { return }
                    self.reportFailure("Receive", error: error)
                    self.close()
                    self.stack?.removeUDPFlow(self)
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
        guard directTransport == nil && !closed else { return }
        proxyConnecting = true  // reuse the flag so datagrams buffer until the transport connects

        // One connection per peer 5-tuple.
        let transport = UDPTransport(host: dstHost, port: dstPort)
        self.directTransport = transport
        Task { [weak self] in
            let connectError: Error?
            do {
                try await transport.connect()
                connectError = nil
            } catch {
                connectError = error
            }
            guard let self else { return }

            self.flowQueue.async { [self] in
                self.proxyConnecting = false
                // A close during the dial already cancelled the transport via releaseProxy.
                guard !self.closed else { return }

                if let connectError {
                    self.reportFailure("Connect", error: connectError)
                    self.close()
                    self.stack?.removeUDPFlow(self)
                    return
                }

                for payload in self.pendingData {
                    Task { [weak self] in
                        do {
                            try await transport.send(payload)
                        } catch {
                            self?.logTransientSendFailure(error)
                        }
                    }
                }
                self.pendingData.removeAll()
                self.pendingBufferSize = 0

                // Drive the datagram downlink with a native `for await` receive loop;
                // a non-EAGAIN recv error closes the flow so we don't sit on a dead transport.
                Task { [weak self] in
                    do {
                        while true {
                            let datagram = try await transport.receive()
                            self?.handleProxyData(datagram)
                        }
                    } catch {
                        guard let self else { return }
                        self.flowQueue.async {
                            guard !self.closed else { return }
                            self.reportFailure("Receive", error: error)
                            self.close()
                            self.stack?.removeUDPFlow(self)
                        }
                    }
                }
            }
        }
    }

    private func startProxyReceiving(proxyConnection: ProxyConnection) {
        Task { [weak self] in
            do {
                while let data = try await proxyConnection.receive() {
                    self?.handleProxyData(data)
                }
                // Clean EOF: close without reporting a failure.
                guard let self else { return }
                self.flowQueue.async {
                    guard !self.closed else { return }
                    self.close()
                    self.stack?.removeUDPFlow(self)
                }
            } catch {
                guard let self else { return }
                self.flowQueue.async {
                    guard !self.closed else { return }
                    self.reportFailure("Receive", error: error)
                    self.close()
                    self.stack?.removeUDPFlow(self)
                }
            }
        }
    }

    private func handleProxyData(_ data: Data) {
        flowQueue.async { [weak self] in
            guard let self, !self.closed else { return }
            self.lastActivity = MonotonicClock.now
            self.replyCount += 1
            
            self.stack?.addBytesIn(Int64(data.count), target: self.routeTarget)

            // Swap the 5-tuple: response source = original destination, and vice versa.
            self.stack?.writeOutboundUDP(
                srcIP: self.dstIPBytes, srcPort: self.dstPort,
                dstIP: self.srcIPBytes, dstPort: self.srcPort,
                isIPv6: self.isIPv6, payload: data
            )
        }
    }

    // MARK: - Close

    func close() {
        guard !closed else { return }
        closed = true
        releaseProxy()
    }

    private func releaseProxy() {
        let transport = directTransport
        let ssSession = ssUDPSession
        let ssToken = ssUDPSessionToken
        let connection = proxyConnection
        let client = proxyClient
        let session = udpStream
        directTransport = nil
        ssUDPSession = nil
        ssUDPSessionToken = nil
        proxyConnection = nil
        proxyClient = nil
        udpStream = nil
        proxyConnecting = false
        pendingData.removeAll()
        pendingBufferSize = 0
        transport?.cancel()
        // The SS session is shared and owned by TunnelStack; unregister, never cancel.
        // Actor-isolated now — fire-and-forget; it EOFs this flow's inbox so its reader unwinds.
        if let ssSession, let ssToken {
            Task { await ssSession.unregister(token: ssToken) }
        }
        connection?.cancel()
        client?.cancel()
        session?.close()
    }
}
