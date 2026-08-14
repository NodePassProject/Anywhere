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
    private weak var stack: TunnelStack?

    private weak var plane: UDPPlane?

    nonisolated let flowKey: TunnelStack.UDPFlowKey
    nonisolated let srcHost: String
    nonisolated let srcPort: UInt16
    nonisolated let dstHost: String
    nonisolated let dstPort: UInt16
    nonisolated let isIPv6: Bool
    nonisolated let configuration: ProxyConfiguration

    nonisolated let srcIPBytes: Data
    nonisolated let dstIPBytes: Data

    private struct Activity {
        var lastActivity: TimeInterval
        var replyCount: Int
    }
    private let activity = Mutex(Activity(lastActivity: MonotonicClock.now, replyCount: 0))

    nonisolated var idleDeadline: TimeInterval {
        activity.withLock { a in
            a.lastActivity + (a.replyCount >= TunnelConstants.udpStreamMinReplies
                              ? TunnelConstants.udpIdleTimeoutStream
                              : TunnelConstants.udpIdleTimeoutUnreplied)
        }
    }

    private enum Phase: PhaseTransitionable {
        case idle
        case dialing
        case established
        case closed

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.idle, .dialing),
                 (.dialing, .established):
                return true
            case (_, .closed):
                return old != .closed
            default:
                return false
            }
        }
    }
    private var phase: Phase = .idle

    @discardableResult
    private func transition(to new: Phase) -> Bool {
        guard Phase.transition(&phase, to: new) else { return false }
        if new == .closed { _closed.store(true, ordering: .relaxed) }
        return true
    }

    private enum Outbound {
        case direct(UDPTransport)
        case shadowsocks(session: ShadowsocksUDPSession, token: ShadowsocksUDPSession.Token)
        case mux(VLESSVisionUDPStream)
        case proxy(ProxyConnection)
    }
    private var outbound: Outbound?

    private var proxyClient: ProxyClient?

    private var rootTask: Task<Void, Never>?

    private nonisolated let _closed = Atomic<Bool>(false)
    nonisolated var isClosed: Bool { _closed.load(ordering: .relaxed) }

    nonisolated let routeTarget: RouteTarget

    private var bypass: Bool {
        if case .direct = routeTarget { return true }
        return false
    }

    private var pendingData: [Data] = []
    private var pendingBufferSize = 0
    private var didWarnPendingOverflow = false

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
        guard phase != .closed, !AnywhereError.isTermination(error) else { return }
        logTransientSendFailure(error)
    }

    private func handleProxySendError(_ error: Error, connection: ProxyConnection) async {
        guard phase != .closed else { return }
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
        guard phase != .closed else { return }
        activity.withLock { $0.lastActivity = MonotonicClock.now }
        stack?.addBytesOut(Int64(payloadLength), target: routeTarget)

        switch phase {
        case .idle:
            bufferPayload(data: data, payloadLength: payloadLength)
            transition(to: .dialing)
            rootTask = Task { await self.run() }
        case .dialing:
            bufferPayload(data: data, payloadLength: payloadLength)
        case .established:
            jobContinuation.yield(.send(data.prefix(payloadLength)))
        case .closed:
            return
        }
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
            group.addTask { await self.runSendLoop() }
        }
    }

    private func runSendLoop() async {
        for await job in self.jobs {
            switch job {
            case .send(let payload):
                await runSend(payload)
            case .drain(let payloads):
                for payload in payloads {
                    await runSend(payload)
                }
            }
        }
    }

    private func runSend(_ payload: Data) async {
        guard phase != .closed, let outbound else { return }
        switch outbound {
        case .direct(let transport):
            do { try await transport.send(payload) } catch { noteTransientSendFailure(error) }
        case .shadowsocks(let session, let token):
            do {
                try await session.send(token: token, dstHost: dstHost, dstPort: dstPort, payload: payload)
            } catch {
                noteTransientSendFailure(error)
            }
        case .mux(let stream):
            do { try await stream.send(data: payload) } catch { noteTransientSendFailure(error) }
        case .proxy(let connection):
            do { try await connection.send(payload) } catch { await handleProxySendError(error, connection: connection) }
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
                guard phase != .closed else { return }
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

    private func establish(_ newOutbound: Outbound) -> Bool {
        guard transition(to: .established) else { return false }
        outbound = newOutbound
        flushBuffered()
        return true
    }

    // MARK: Direct (bypass)

    private func runDirectLifecycle() async {
        let transport = UDPTransport(host: dstHost, port: dstPort)

        let connectError: Error?
        do {
            try await transport.connect()
            connectError = nil
        } catch {
            connectError = error
        }
        guard phase != .closed else {
            transport.cancel()
            return
        }

        if let connectError {
            reportFailure("Connect", error: connectError)
            await closeAndRemove()
            return
        }

        guard establish(.direct(transport)) else {
            transport.cancel()
            return
        }

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
        guard phase != .closed else {
            if case .success(let session) = result { session.close() }
            return
        }

        switch result {
        case .success(let session):
            guard !session.closed else {
                await closeAndRemove()
                return
            }
            guard establish(.mux(session)) else {
                session.close()
                return
            }

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
        guard phase != .closed else { return }
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
        guard establish(.shadowsocks(session: session, token: token)) else {
            await session.unregister(token: token)
            return
        }

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

    // MARK: ProxyClient

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
        guard phase != .closed else {
            if case .success(let connection) = result { connection.cancel() }
            return
        }

        switch result {
        case .success(let proxyConnection):
            guard establish(.proxy(proxyConnection)) else {
                proxyConnection.cancel()
                return
            }

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
        guard phase != .closed else { return }
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
        guard phase != .closed else { return }
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
        guard transition(to: .closed) else { return }
        teardown()
    }

    private func teardown() {
        jobContinuation.finish()

        let doomed = outbound
        outbound = nil
        let client = proxyClient
        proxyClient = nil
        pendingData.removeAll()
        pendingBufferSize = 0

        switch doomed {
        case .direct(let transport):
            transport.cancel()
        case .shadowsocks(let session, let token):
            Task { await session.unregister(token: token) }
        case .mux(let stream):
            stream.close()
        case .proxy(let connection):
            connection.cancel()
        case nil:
            break
        }
        client?.cancel()

        rootTask?.cancel()
        rootTask = nil
    }
}
