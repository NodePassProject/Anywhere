//
//  UDPFlow.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "UDPFlow")

actor UDPFlow {

    /// The owning stack, for traffic accounting and the TUN write-back. Weak: the stack can stop
    /// while late transport completions are still in flight.
    private weak var stack: TunnelStack?

    /// The UDP plane that owns this flow, for deregistration and the shared session / mux pool.
    /// Weak for the same reason as ``stack``.
    private weak var plane: UDPPlane?

    nonisolated let flowKey: TunnelStack.UDPFlowKey
    nonisolated let srcHost: String
    nonisolated let srcPort: UInt16
    nonisolated let dstHost: String
    nonisolated let dstPort: UInt16
    nonisolated let isIPv6: Bool
    nonisolated let configuration: ProxyConfiguration

    // Raw IP bytes for building the response packet (swapped src/dst).
    nonisolated let srcIPBytes: Data
    nonisolated let dstIPBytes: Data

    /// Activity counters read cross-actor by the stack's idle eviction, so they live in a
    /// `Mutex` rather than the actor's isolated state.
    private struct Activity {
        var lastActivity: TimeInterval
        /// Downlink datagrams received; at udpStreamMinReplies the flow graduates from the short
        /// unreplied timeout to the longer stream timeout.
        var replyCount: Int
    }
    private let activity = Mutex(Activity(lastActivity: MonotonicClock.now, replyCount: 0))

    /// Monotonic expiry instant; eviction picks the smallest deadline, so
    /// unreplied probes are shed before established streams.
    nonisolated var idleDeadline: TimeInterval {
        activity.withLock { a in
            a.lastActivity + (a.replyCount >= TunnelConstants.udpStreamMinReplies
                              ? TunnelConstants.udpIdleTimeoutStream
                              : TunnelConstants.udpIdleTimeoutUnreplied)
        }
    }

    // Direct bypass path
    private var directTransport: UDPTransport?

    // Non-mux path
    private var proxyClient: ProxyClient?
    private var proxyConnection: ProxyConnection?
    /// The in-flight dial (proxy / mux / SS register / direct). Teardown cancels it so a
    /// still-connecting handshake unwinds (its `CancellationError` runs the connect path's
    /// cleanup) instead of lingering until it completes — `client.cancel()` alone only tears
    /// down an already-delivered connection. Every dial task captures the flow strongly; a
    /// close racing the dial is resolved by the finish handlers' `closed` guards.
    private var proxyDialTask: Task<Void, Never>?

    // Shared SS UDP session owned by TunnelStack; borrowed only.
    private weak var ssUDPSession: ShadowsocksUDPSession?
    private var ssUDPSessionToken: ShadowsocksUDPSession.Token?

    // Mux path
    private var udpStream: VLESSVisionUDPStream?

    /// The single downlink receive loop (mux / SS / proxy / direct — one per flow). Strong self:
    /// the loop owns the flow while receiving; ``releaseProxy`` cancels it and tears down the
    /// underlying transport, which ends the iteration and lets ARC reclaim the flow.
    private var receiveTask: Task<Void, Never>?

    private var proxyConnecting = false

    /// Routing identity for accounting and dialing; fixed at creation (UDP has no SNI re-routing).
    nonisolated let routeTarget: RouteTarget

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
         plane: UDPPlane,
         flowKey: TunnelStack.UDPFlowKey,
         srcHost: String, srcPort: UInt16,
         dstHost: String, dstPort: UInt16,
         srcIPData: Data, dstIPData: Data,
         isIPv6: Bool,
         configuration: ProxyConfiguration,
         routeTarget: RouteTarget) {
        self.stack = stack
        self.plane = plane
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
    }

    private func reportFailure(_ operation: String, error: Error) {
        failureReporter.report(operation: operation, endpoint: "\(flowKey)", error: error)
    }

    nonisolated private func logTransientSendFailure(_ error: Error) {
        TransportErrorLogger.logTransientSend(
            endpoint: "\(flowKey)",
            error: error,
            logger: logger,
            prefix: "[UDP]"
        )
    }

    /// Terminal send errors close the flow; transient ones just log (UDP is lossy).
    private func handleProxySendError(_ error: Error, connection: ProxyConnection) async {
        guard !closed else { return }
        if Self.isTerminalProxySendError(error, connection: connection) {
            reportFailure("Send", error: error)
            close()
            await plane?.remove(self)
        } else {
            logTransientSendFailure(error)
        }
    }

    /// Terminal = the connection is gone for good; transient = the connection is still usable.
    nonisolated private static func isTerminalProxySendError(_ error: Error, connection: ProxyConnection) -> Bool {
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

    // MARK: - Data Handling

    func handleReceivedData(_ data: Data, payloadLength: Int) async {
        guard !closed else { return }
        activity.withLock { $0.lastActivity = MonotonicClock.now }

        stack?.addBytesOut(Int64(payloadLength), target: routeTarget)

        // Buffer while connecting: sends on an unconnected UDP transport are silently dropped.
        if proxyConnecting {
            bufferPayload(data: data, payloadLength: payloadLength)
            return
        }

        let payload = data.prefix(payloadLength)

        if let transport = directTransport {
            // Datagrams are independent, so each send is its own task (no ordering pump).
            Task {
                do {
                    try await transport.send(payload)
                } catch {
                    self.logTransientSendFailure(error)
                }
            }
            return
        }

        if let session = ssUDPSession, let token = ssUDPSessionToken {
            let host = dstHost
            let port = dstPort
            // Datagrams are independent; each send is its own task. The session serializes
            // its own state, so concurrent tasks can't corrupt packetID allocation.
            Task {
                do {
                    try await session.send(token: token, dstHost: host, dstPort: port, payload: payload)
                } catch {
                    self.logTransientSendFailure(error)
                }
            }
            return
        }

        if let session = udpStream {
            Task {
                do {
                    try await session.send(data: payload)
                } catch {
                    self.logTransientSendFailure(error)
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
        await connectProxy()
    }

    /// Fire-and-forget async send to the proxy connection. Datagrams are independent, so
    /// each send is its own task; the connection serializes its own framed writes, so
    /// concurrent tasks can't interleave frames on a stream transport. A terminal send
    /// error closes the flow; transient ones just log (UDP is lossy). Strong self: the
    /// short-lived send task owns the flow until the send settles, then ARC releases it.
    private func sendToProxyConnection(_ payload: Data, connection: ProxyConnection) {
        Task {
            do {
                try await connection.send(payload)
            } catch {
                await self.handleProxySendError(error, connection: connection)
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

    private func connectProxy() async {
        guard !proxyConnecting && proxyConnection == nil && udpStream == nil && directTransport == nil && ssUDPSession == nil && !closed else { return }
        // Claim before the first `await` (the mux read) so a reentrant datagram buffers via the
        // `proxyConnecting` guard in `handleReceivedData` instead of racing a second dial.
        proxyConnecting = true

        if bypass {
            connectDirectUDP()
            return
        }

        let hasChain = configuration.chain != nil && !configuration.chain!.isEmpty

        // Fast paths bypass ProxyClient, so they must only run when no chain is configured.
        if !hasChain {
            let isDefaultConfiguration = stack?.isDefaultConfiguration(configuration.id) ?? false
            if configuration.outboundProtocol == .vless, isDefaultConfiguration, let udpMultiplexerPool = await plane?.multiplexerPool {
                guard !closed else { return }
                connectViaMultiplexer(udpMultiplexerPool: udpMultiplexerPool)
                return
            }

            if configuration.outboundProtocol == .shadowsocks {
                await connectShadowsocksUDP()
                return
            }
        }

        // ProxyClient builds the chain tunnel when needed — the only valid path with a chain.
        connectViaProxyClient()
    }

    // MARK: - Connection Strategies

    private func connectViaMultiplexer(udpMultiplexerPool: VLESSVisionUDPMultiplexerPool) {
        // Stable per-source globalID lets the server pin one upstream session (Full Cone NAT).
        let globalID = VLESSVisionUDPGlobalID.generateGlobalID(sourceAddress: "udp:\(srcHost):\(srcPort)")
        let host = dstHost
        let port = dstPort
        // Strong self: the dial task owns the flow until the finish handler settles; a close
        // during the dial cancels this task and the finish handler's `closed` guard releases
        // whatever the dial delivered.
        proxyDialTask = Task {
            let result: Result<VLESSVisionUDPStream, Error>
            do {
                result = .success(try await udpMultiplexerPool.acquireStream(
                    network: .udp, host: host, port: port, globalID: globalID))
            } catch {
                result = .failure(error)
            }
            await self.finishMultiplexerConnect(result)
        }
    }

    private func finishMultiplexerConnect(_ result: Result<VLESSVisionUDPStream, Error>) async {
        proxyConnecting = false
        proxyDialTask = nil
        guard !closed else {
            if case .success(let session) = result { session.close() }
            return
        }

        switch result {
        case .success(let session):
            // closeAll() may have already closed the session before this ran.
            guard !session.closed else {
                close()
                await plane?.remove(self)
                return
            }

            udpStream = session
            // Consume the stream's inbound channel: data pushes to the flow, EOF is a
            // clean close, a thrown error is a transport failure.
            startMuxReceiving(session: session)

            let buffered = pendingData
            pendingData.removeAll()
            pendingBufferSize = 0
            if !buffered.isEmpty {
                // Drain in order in a single task so the XUDP New frame precedes Keeps.
                Task {
                    for payload in buffered {
                        do {
                            try await session.send(data: payload)
                        } catch {
                            self.logTransientSendFailure(error)
                        }
                    }
                }
            }

        case .failure(let error):
            if case .dropped = error as? ProxyError {} else {
                reportFailure("Connect", error: error)
            }
            close()
            await plane?.remove(self)
        }
    }

    /// Drives the mux stream's inbound datagrams: EOF closes cleanly, an error reports and closes.
    /// Strong self: the loop owns the flow while receiving; `releaseProxy` cancels the task and
    /// closes the stream, ending the iteration so ARC reclaims the flow.
    private func startMuxReceiving(session: VLESSVisionUDPStream) {
        receiveTask = Task {
            do {
                while let data = try await session.receive() {
                    handleProxyData(data)
                }
                // Clean EOF (End frame / normal close): close without reporting a failure.
                await receiveClosed(operation: "Mux", error: nil)
            } catch {
                await receiveClosed(operation: "Mux", error: error)
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
        // Strong self: as in `connectViaMultiplexer`, the finish handler's `closed` guard
        // releases a connection delivered after a mid-dial close.
        proxyDialTask = Task {
            let result: Result<ProxyConnection, Error>
            do {
                result = .success(try await client.connectUDP(to: host, port: port))
            } catch {
                result = .failure(error)
            }
            await self.finishProxyClientConnect(result)
        }
    }

    private func finishProxyClientConnect(_ result: Result<ProxyConnection, Error>) async {
        proxyConnecting = false
        proxyDialTask = nil
        guard !closed else {
            if case .success(let connection) = result { connection.cancel() }
            return
        }

        switch result {
        case .success(let proxyConnection):
            self.proxyConnection = proxyConnection

            // Drain buffered payloads; `send` preserves packet boundaries.
            for payload in pendingData {
                sendToProxyConnection(payload, connection: proxyConnection)
            }
            pendingData.removeAll()
            pendingBufferSize = 0

            startProxyReceiving(proxyConnection: proxyConnection)

        case .failure(let error):
            if case .dropped = error as? ProxyError {} else {
                reportFailure("Connect", error: error)
            }
            close()
            await plane?.remove(self)
        }
    }

    private func connectShadowsocksUDP() async {
        guard ssUDPSession == nil && !closed else { return }

        guard let plane else {
            close()
            return
        }

        let sessionResult = await plane.shadowsocksSession(for: configuration)
        guard !closed else { return }
        let session: ShadowsocksUDPSession
        switch sessionResult {
        case .success(let s):
            session = s
        case .failure(let error):
            reportFailure("SS session", error: error)
            close()
            await plane.remove(self)
            return
        }

        // Registration is now async (the session is an actor). Buffer datagrams and block
        // re-entry via `proxyConnecting` until the token + inbox land. Hints use the
        // synchronous DNS cache only (the UDP path is performance-critical); the async
        // prewarm below handles misses.
        proxyConnecting = true
        let cachedHints = DNSResolver.shared.cachedIPs(for: dstHost) ?? []
        let host = dstHost
        let port = dstPort

        // Strong self: registration is a short actor call; a close racing it is handled by the
        // finish handler's `closed` guard, which unregisters the just-delivered token.
        proxyDialTask = Task {
            let (token, stream) = await session.register(
                dstHost: host, dstPort: port, responseHostHints: cachedHints
            )
            self.finishShadowsocksConnect(session: session, token: token, stream: stream,
                                          host: host, port: port, cachedHints: cachedHints)
        }
    }

    private func finishShadowsocksConnect(session: ShadowsocksUDPSession,
                                          token: ShadowsocksUDPSession.Token,
                                          stream: AsyncThrowingStream<Data, Error>,
                                          host: String, port: UInt16, cachedHints: [String]) {
        proxyConnecting = false
        proxyDialTask = nil
        guard !closed else {
            Task { await session.unregister(token: token) }
            return
        }

        ssUDPSession = session
        ssUDPSessionToken = token
        startShadowsocksReceiving(stream: stream)

        // Drain what buffered meanwhile, preserving order in a single task.
        let buffered = pendingData
        pendingData.removeAll()
        pendingBufferSize = 0
        if !buffered.isEmpty {
            Task {
                for payload in buffered {
                    do {
                        try await session.send(token: token, dstHost: host, dstPort: port, payload: payload)
                    } catch {
                        self.logTransientSendFailure(error)
                    }
                }
            }
        }

        // Async-resolve uncached domains so replies route by exact IP; the port-only
        // fallback misroutes flows sharing a destination port (e.g. QUIC on 443).
        if cachedHints.isEmpty, Self.isDomainName(host) {
            // Hold `session` weakly so a torn-down flow isn't pinned open across the
            // resolve; the async overload hops to the resolver's own worker queue.
            Task { [weak session] in
                let ips = await DNSResolver.shared.resolveAll(host)
                guard !ips.isEmpty, let session else { return }
                await session.addResponseHints(token: token, hints: ips)
            }
        }
    }

    /// Drives the SS session's per-flow inbound datagram stream: data pushes to the flow,
    /// a thrown error reports and closes. Strong self: `releaseProxy` cancels the task and
    /// unregisters the token, which EOFs this flow's inbox and ends the iteration.
    private func startShadowsocksReceiving(stream: AsyncThrowingStream<Data, Error>) {
        receiveTask = Task {
            do {
                for try await data in stream {
                    handleProxyData(data)
                }
                // Clean EOF (unregister) — the flow is already tearing down; nothing to do.
            } catch {
                await receiveClosed(operation: "Receive", error: error)
            }
        }
    }

    /// True when `host` is not an IPv4/IPv6 literal.
    nonisolated private static func isDomainName(_ host: String) -> Bool {
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
        // Strong self: a close during the dial cancels the transport via releaseProxy, which
        // makes `connect()` throw and the finish handler's `closed` guard end the task.
        proxyDialTask = Task {
            let connectError: Error?
            do {
                try await transport.connect()
                connectError = nil
            } catch {
                connectError = error
            }
            await self.finishDirectConnect(transport: transport, connectError: connectError)
        }
    }

    private func finishDirectConnect(transport: UDPTransport, connectError: Error?) async {
        proxyConnecting = false
        proxyDialTask = nil
        // A close during the dial already cancelled the transport via releaseProxy.
        guard !closed else { return }

        if let connectError {
            reportFailure("Connect", error: connectError)
            close()
            await plane?.remove(self)
            return
        }

        for payload in pendingData {
            Task {
                do {
                    try await transport.send(payload)
                } catch {
                    self.logTransientSendFailure(error)
                }
            }
        }
        pendingData.removeAll()
        pendingBufferSize = 0

        // Drive the datagram downlink with a native `for await` receive loop;
        // a non-EAGAIN recv error closes the flow so we don't sit on a dead transport.
        // Strong self: `releaseProxy` cancels the task and the transport, ending the loop.
        receiveTask = Task {
            do {
                while true {
                    let datagram = try await transport.receive()
                    handleProxyData(datagram)
                }
            } catch {
                await receiveClosed(operation: "Receive", error: error)
            }
        }
    }

    /// Strong self: `releaseProxy` cancels the task and the connection, ending the loop.
    private func startProxyReceiving(proxyConnection: ProxyConnection) {
        receiveTask = Task {
            do {
                while let data = try await proxyConnection.receive() {
                    handleProxyData(data)
                }
                // Clean EOF: close without reporting a failure.
                await receiveClosed(operation: "Receive", error: nil)
            } catch {
                await receiveClosed(operation: "Receive", error: error)
            }
        }
    }

    private func handleProxyData(_ data: Data) {
        guard !closed else { return }
        activity.withLock {
            $0.lastActivity = MonotonicClock.now
            $0.replyCount += 1
        }

        stack?.addBytesIn(Int64(data.count), target: routeTarget)

        // Swap the 5-tuple: response source = original destination, and vice versa.
        stack?.writeOutboundUDP(
            srcIP: dstIPBytes, srcPort: dstPort,
            dstIP: srcIPBytes, dstPort: srcPort,
            isIPv6: isIPv6, payload: data
        )
    }

    /// A downlink receive loop ended: report an error if any, then close and deregister.
    private func receiveClosed(operation: String, error: Error?) async {
        guard !closed else { return }
        if let error {
            reportFailure(operation, error: error)
        }
        close()
        await plane?.remove(self)
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
        let dial = proxyDialTask
        let receive = receiveTask
        let session = udpStream
        directTransport = nil
        ssUDPSession = nil
        ssUDPSessionToken = nil
        proxyConnection = nil
        proxyClient = nil
        proxyDialTask = nil
        receiveTask = nil
        udpStream = nil
        proxyConnecting = false
        pendingData.removeAll()
        pendingBufferSize = 0
        // Cancel the downlink loop first, then tear down its transport below so the
        // iteration it is parked on ends; the task's strong self dies with it.
        receive?.cancel()
        transport?.cancel()
        // The SS session is shared and owned by TunnelStack; unregister, never cancel.
        // Actor-isolated now — fire-and-forget; it EOFs this flow's inbox so its reader unwinds.
        if let ssSession, let ssToken {
            Task { await ssSession.unregister(token: ssToken) }
        }
        // Cancel a still-connecting dial so its handshake unwinds now; `client.cancel()` then marks
        // the client so a dial that completes in the race tears its own connection down via deliver().
        dial?.cancel()
        connection?.cancel()
        client?.cancel()
        session?.close()
    }
}
