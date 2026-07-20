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

    // Shared SS UDP session owned by TunnelStack; borrowed only.
    private weak var ssUDPSession: ShadowsocksUDPSession?
    private var ssUDPSessionToken: ShadowsocksUDPSession.Token?

    // Mux path
    private var udpStream: VLESSVisionUDPStream?
    
    private var rootTask: Task<Void, Never>?
    
    private var establishing = false
    
    nonisolated let routeTarget: RouteTarget

    private var bypass: Bool {
        if case .direct = routeTarget { return true }
        return false
    }

    private var pendingData: [Data] = []
    private var pendingBufferSize = 0
    private var didWarnPendingOverflow = false
    private var closed = false
    
    private enum Job: Sendable {
        case send(Data)
        case drain([Data])
    }
    private let jobs: AsyncStream<Job>
    private nonisolated let jobContinuation: AsyncStream<Job>.Continuation

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
        (self.jobs, self.jobContinuation) = AsyncStream.makeStream(of: Job.self)
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

    private func noteTransientSendFailure(_ error: Error) {
        guard !closed, !(error is CancellationError) else { return }
        logTransientSendFailure(error)
    }

    private func handleProxySendError(_ error: Error, connection: ProxyConnection) async {
        guard !closed else { return }
        if Self.isTerminalProxySendError(error, connection: connection) {
            reportFailure("Send", error: error)
            await closeAndRemove()
        } else {
            logTransientSendFailure(error)
        }
    }

    nonisolated private static func isTerminalProxySendError(_ error: Error, connection: ProxyConnection) -> Bool {
        if case AnywhereError.quic(let quicError) = error {
            switch quicError {
            case .handshakeFailed, .streamReset, .streamClosedWithError, .closed:
                return true
            case .datagramTooLarge, .datagramQueueFull, .connectionFailed, .streamFailed, .timedOut:
                return false
            }
        }
        if case AnywhereError.proxy(.hysteria, let failure) = error {
            switch failure {
            case .authenticationRejected, .unsupported, .datagramTooLarge, .streamClosed:
                return true
            case .notReady, .connectionClosed, .tunnelRejected:
                return false
            default:
                return !connection.isConnected
            }
        }
        if case AnywhereError.proxy(.nowhere, let failure) = error {
            switch failure {
            case .authenticationRejected, .protocolViolation, .datagramTooLarge, .streamClosed,
                    .flowRejected, .openTimeout:
                return true
            case .notReady, .connectionClosed, .packetTooLarge:
                return false
            default:
                return !connection.isConnected
            }
        }
        return !connection.isConnected
    }

    // MARK: - Uplink

    func handleReceivedData(_ data: Data, payloadLength: Int) async {
        guard !closed else { return }
        activity.withLock { $0.lastActivity = MonotonicClock.now }

        stack?.addBytesOut(Int64(payloadLength), target: routeTarget)
        
        if establishing {
            bufferPayload(data: data, payloadLength: payloadLength)
            return
        }
        
        if rootTask == nil {
            bufferPayload(data: data, payloadLength: payloadLength)
            establishing = true
            rootTask = Task { await self.run() }
            return
        }
        
        jobContinuation.yield(.send(data.prefix(payloadLength)))
    }

    private func bufferPayload(data: Data, payloadLength: Int) {
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
    
    private func flushBuffered() {
        guard !pendingData.isEmpty else { return }
        let buffered = pendingData
        pendingData.removeAll()
        pendingBufferSize = 0
        jobContinuation.yield(.drain(buffered))
    }

    // MARK: - Root task / nursery

    private func run() async {
        await withDiscardingTaskGroup { group in
            group.addTask { await self.runLifecycle() }
            for await job in self.jobs {
                switch job {
                case .send(let payload):
                    group.addTask { await self.runSend(payload) }
                case .drain(let payloads):
                    group.addTask { await self.runDrain(payloads) }
                }
            }
        }
    }
    
    private func runSend(_ payload: Data) async {
        guard !closed else { return }
        if let transport = directTransport {
            do { try await transport.send(payload) } catch { noteTransientSendFailure(error) }
        } else if let session = ssUDPSession, let token = ssUDPSessionToken {
            do {
                try await session.send(token: token, dstHost: dstHost, dstPort: dstPort, payload: payload)
            } catch {
                noteTransientSendFailure(error)
            }
        } else if let session = udpStream {
            do { try await session.send(data: payload) } catch { noteTransientSendFailure(error) }
        } else if let connection = proxyConnection {
            do { try await connection.send(payload) } catch { await handleProxySendError(error, connection: connection) }
        }
    }

    private func runDrain(_ payloads: [Data]) async {
        for payload in payloads {
            await runSend(payload)
        }
    }

    // MARK: - Lifecycle (dial → receive)

    private func runLifecycle() async {
        if bypass {
            await runDirectLifecycle()
            return
        }

        let hasChain = configuration.chain != nil && !configuration.chain!.isEmpty
        
        if !hasChain {
            let isDefaultConfiguration = stack?.isDefaultConfiguration(configuration.id) ?? false
            if configuration.outboundProtocol == .vless, isDefaultConfiguration,
               let pool = await plane?.multiplexerPool {
                guard !closed else { return }
                await runMuxLifecycle(pool: pool)
                return
            }
            if configuration.outboundProtocol == .shadowsocks {
                await runShadowsocksLifecycle()
                return
            }
        }
        
        await runProxyClientLifecycle()
    }
    
    private func markEstablishedAndDrain() {
        flushBuffered()
        establishing = false
    }

    // MARK: Direct (bypass)

    private func runDirectLifecycle() async {
        let transport = UDPTransport(host: dstHost, port: dstPort)
        self.directTransport = transport

        let connectError: Error?
        do {
            try await transport.connect()
            connectError = nil
        } catch {
            connectError = error
        }
        guard !closed else { return }

        if let connectError {
            reportFailure("Connect", error: connectError)
            await closeAndRemove()
            return
        }

        markEstablishedAndDrain()
        
        do {
            while true {
                let datagram = try await transport.receive()
                handleProxyData(datagram)
            }
        } catch {
            await receiveClosed(operation: "Receive", error: error)
        }
    }

    // MARK: Mux

    private func runMuxLifecycle(pool: VLESSVisionUDPMultiplexerPool) async {
        let globalID = VLESSVisionUDPGlobalID.generateGlobalID(sourceAddress: "udp:\(srcHost):\(srcPort)")

        let result: Result<VLESSVisionUDPStream, Error>
        do {
            result = .success(try await pool.acquireStream(
                network: .udp, host: dstHost, port: dstPort, globalID: globalID))
        } catch {
            result = .failure(error)
        }
        guard !closed else {
            if case .success(let session) = result { session.close() }
            return
        }

        switch result {
        case .success(let session):
            guard !session.closed else {
                await closeAndRemove()
                return
            }
            udpStream = session
            markEstablishedAndDrain()
            
            do {
                while let data = try await session.receive() {
                    handleProxyData(data)
                }
                await receiveClosed(operation: "Mux", error: nil)
            } catch {
                await receiveClosed(operation: "Mux", error: error)
            }

        case .failure(let error):
            if case AnywhereError.routing(.dropped) = error {} else {
                reportFailure("Connect", error: error)
            }
            await closeAndRemove()
        }
    }

    // MARK: Shadowsocks (shared session)

    private func runShadowsocksLifecycle() async {
        guard let plane else {
            await closeAndRemove()
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
            await closeAndRemove()
            return
        }
        
        let cachedHints = DNSResolver.shared.cachedIPs(for: dstHost) ?? []
        let (token, stream) = await session.register(
            dstHost: dstHost, dstPort: dstPort, responseHostHints: cachedHints
        )
        guard !closed else {
            await session.unregister(token: token)
            return
        }

        ssUDPSession = session
        ssUDPSessionToken = token
        markEstablishedAndDrain()
        
        if cachedHints.isEmpty, Self.isDomainName(dstHost) {
            let host = dstHost
            Task { [weak session] in
                let ips = await DNSResolver.shared.resolveAll(host)
                guard !ips.isEmpty, let session else { return }
                await session.addResponseHints(token: token, hints: ips)
            }
        }

        do {
            for try await data in stream {
                handleProxyData(data)
            }
        } catch {
            await receiveClosed(operation: "Receive", error: error)
        }
    }
    
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

    // MARK: ProxyClient (chain-capable)

    private func runProxyClientLifecycle() async {
        let client = ProxyClient(
            configuration: configuration,
            isDefaultProxy: stack?.isDefaultConfiguration(configuration.id) ?? false
        )
        self.proxyClient = client

        let result: Result<ProxyConnection, Error>
        do {
            result = .success(try await client.connectUDP(to: dstHost, port: dstPort))
        } catch {
            result = .failure(error)
        }
        guard !closed else {
            if case .success(let connection) = result { connection.cancel() }
            return
        }

        switch result {
        case .success(let proxyConnection):
            self.proxyConnection = proxyConnection
            markEstablishedAndDrain()

            do {
                while let data = try await proxyConnection.receive() {
                    handleProxyData(data)
                }
                await receiveClosed(operation: "Receive", error: nil)
            } catch {
                await receiveClosed(operation: "Receive", error: error)
            }

        case .failure(let error):
            if case AnywhereError.routing(.dropped) = error {} else {
                reportFailure("Connect", error: error)
            }
            await closeAndRemove()
        }
    }

    // MARK: - Downlink

    private func handleProxyData(_ data: Data) {
        guard !closed else { return }
        activity.withLock {
            $0.lastActivity = MonotonicClock.now
            $0.replyCount += 1
        }

        stack?.addBytesIn(Int64(data.count), target: routeTarget)
        
        stack?.writeOutboundUDP(
            srcIP: dstIPBytes, srcPort: dstPort,
            dstIP: srcIPBytes, dstPort: srcPort,
            isIPv6: isIPv6, payload: data
        )
    }
    
    private func receiveClosed(operation: String, error: Error?) async {
        guard !closed else { return }
        if let error {
            reportFailure(operation, error: error)
        }
        await closeAndRemove()
    }

    // MARK: - Close / teardown

    private func closeAndRemove() async {
        close()
        await plane?.remove(self)
    }

    func close() {
        guard !closed else { return }
        closed = true
        teardown()
    }
    
    private func teardown() {
        jobContinuation.finish()

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
        establishing = false
        pendingData.removeAll()
        pendingBufferSize = 0
        
        transport?.cancel()
        if let ssSession, let ssToken {
            Task { await ssSession.unregister(token: ssToken) }
        }
        connection?.cancel()
        client?.cancel()
        session?.close()
        
        rootTask?.cancel()
        rootTask = nil
    }
}
