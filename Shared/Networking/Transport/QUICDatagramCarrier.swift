//
//  QUICDatagramCarrier.swift
//  Anywhere
//
//  Created by NodePassProject on 5/21/26.
//

import Foundation
import Network
import Darwin
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "QUICDatagramCarrier")

nonisolated final class QUICInboundMailbox: Sendable {
    private static let capacity = 256

    private struct State {
        var packets: [Data] = []
        var drainScheduled = false
        var didWarnOverflow = false
    }
    private let state = Mutex(State())
    
    func push(_ packet: Data) -> Bool {
        state.withLock { state in
            guard state.packets.count < Self.capacity else {
                // A full backlog implies a drain is already scheduled, so dropping never
                // strands the queue.
                if !state.didWarnOverflow {
                    state.didWarnOverflow = true
                    logger.warning("[QUIC] Inbound backlog full; dropping datagrams until the bridge queue drains")
                }
                return false
            }
            state.packets.append(packet)
            if state.drainScheduled { return false }
            state.drainScheduled = true
            return true
        }
    }
    
    func take() -> [Data] {
        state.withLock { state in
            state.drainScheduled = false
            let batch = state.packets
            state.packets.removeAll(keepingCapacity: true)
            return batch
        }
    }
}

actor QUICDatagramCarrier {
    nonisolated var unownedExecutor: UnownedSerialExecutor {
        bridge.executor.asUnownedSerialExecutor()
    }

    private typealias QUICError = QUICConnection.QUICError
    
    private let bridge: NGTCP2ConcurrencyBridge
    
    private let obfuscator: QUICPacketObfuscator?
    
    private let inbound = QUICInboundMailbox()
    
    private var driverTask: Task<Void, Never>?
    private var sendContinuation: AsyncStream<Data>.Continuation?

    private var packetHandler: (@Sendable (Data) -> Void)?
    private var recvErrorHandler: (@Sendable (Int32) -> Void)?
    
    var onPathDown: (@Sendable () -> Void)?
    var onBetterPath: (@Sendable () -> Void)?
    var onReady: (() -> Void)?

    private var ready = false
    private var closed = false
    private var flowCounted = false
    
    private var cachedInterfaceType: NWInterface.InterfaceType?

    init(bridge: NGTCP2ConcurrencyBridge, obfuscator: QUICPacketObfuscator?) {
        self.bridge = bridge
        self.obfuscator = obfuscator
    }

    deinit {
        driverTask?.cancel()
        guard flowCounted else { return }
        flowCounted = false
        FlowGauge.decrementUDP()
        logger.error("[QUIC] Datagram carrier deallocated without close() — recovered the FlowGauge count in deinit; a close() path has regressed.")
    }
    
    var currentInterfaceType: NWInterface.InterfaceType? {
        cachedInterfaceType
    }

    // MARK: - Connect
    
    func connect(remoteAddr: sockaddr_storage, localAddr: inout sockaddr_storage) throws {
        guard let endpoint = Self.nwEndpoint(from: remoteAddr) else {
            throw QUICError.connectionFailed("invalid remote address")
        }
        Self.fillAnyLocalAddr(&localAddr, family: remoteAddr.ss_family)

        FlowGauge.incrementUDP()
        flowCounted = true

        let (sendStream, sendCont) = AsyncStream.makeStream(of: Data.self)
        sendContinuation = sendCont
        
        let carrier = WeakCarrier(value: self)
        driverTask = Task { [bridge, obfuscator, inbound] in
            await Self.runDriver(endpoint: endpoint, sendStream: sendStream, bridge: bridge,
                                 carrier: carrier, obfuscator: obfuscator, mailbox: inbound)
        }
    }

    // MARK: - Receive
    
    func startReceiving(onPacket: @escaping @Sendable (Data) -> Void,
                        onError: @escaping @Sendable (Int32) -> Void) {
        packetHandler = onPacket
        recvErrorHandler = onError
    }

    // MARK: - Send
    
    func send(_ datagram: Data) {
        guard !datagram.isEmpty, let sendContinuation else { return }
        sendContinuation.yield(datagram)
    }

    // MARK: - Close
    
    func close() {
        guard !closed else { return }
        closed = true
        releaseFlowCount()
        sendContinuation?.finish()
        sendContinuation = nil
        driverTask?.cancel()
        driverTask = nil
        packetHandler = nil
        recvErrorHandler = nil
        onPathDown = nil
        onBetterPath = nil
        onReady = nil
        ready = false
    }

    // MARK: - Driver
    
    private struct WeakCarrier: Sendable {
        weak var value: QUICDatagramCarrier?
    }
    
    @concurrent
    private static func runDriver(
        endpoint: NWEndpoint,
        sendStream: AsyncStream<Data>,
        bridge: NGTCP2ConcurrencyBridge,
        carrier: WeakCarrier,
        obfuscator: QUICPacketObfuscator?,
        mailbox: QUICInboundMailbox
    ) async {
        do {
            try await withNetworkConnection(to: endpoint, using: { UDP() }) { connection in
                connection.onStateUpdate { connection, state in
                    switch state {
                    case .ready:
                        let interfaceType = connection.currentPath?.availableInterfaces.first?.type
                        bridge.enqueue { carrier.value?.assumeIsolated { $0.handleReady(interfaceType: interfaceType) } }
                    case .failed(let error):
                        let code = TransportError.errnoCode(from: error)
                        bridge.enqueue { carrier.value?.assumeIsolated { $0.deliverError(code) } }
                    case .waiting(let error):
                        let code = TransportError.errnoCode(from: error)
                        bridge.enqueue { carrier.value?.assumeIsolated { $0.handleWaiting(code) } }
                    default:
                        break  // .setup, .preparing, .cancelled
                    }
                }
                connection.onViabilityUpdate { _, viable in
                    guard !viable else { return }
                    bridge.enqueue { carrier.value?.assumeIsolated { $0.handleViabilityLost() } }
                }
                connection.onBetterPathUpdate { _, better in
                    guard better else { return }
                    bridge.enqueue { carrier.value?.assumeIsolated { $0.handleBetterPath() } }
                }
                connection.onPathUpdate { _, path in
                    let interfaceType = path.availableInterfaces.first?.type
                    bridge.enqueue { carrier.value?.assumeIsolated { $0.cachedInterfaceType = interfaceType } }
                }

                try await withThrowingTaskGroup(of: Void.self) { group in
                    group.addTask { try await Self.runSendLoop(connection, stream: sendStream, obfuscator: obfuscator) }
                    group.addTask { try await Self.runReceiveLoop(connection, bridge: bridge, carrier: carrier,
                                                                  obfuscator: obfuscator, mailbox: mailbox) }
                    _ = try await group.next()
                    group.cancelAll()
                }
            }
        } catch {
            // Connection ended (cancelled or failed).
        }
        bridge.enqueue { carrier.value?.assumeIsolated { $0.releaseFlowCount() } }
    }
    
    private static func runSendLoop(_ connection: NetworkConnection<UDP>, stream: AsyncStream<Data>,
                                    obfuscator: QUICPacketObfuscator?) async throws {
        for await datagram in stream {
            guard let obfuscator else {
                try? await connection.send(datagram)
                continue
            }
            // One QUIC packet may seal into several wire datagrams (Gecko fragmentation).
            let wireDatagrams = datagram.withUnsafeBytes { obfuscator.seal($0) }
            for wire in wireDatagrams {
                try? await connection.send(wire)
            }
        }
    }
    
    private static func runReceiveLoop(
        _ connection: NetworkConnection<UDP>,
        bridge: NGTCP2ConcurrencyBridge,
        carrier: WeakCarrier,
        obfuscator: QUICPacketObfuscator?,
        mailbox: QUICInboundMailbox
    ) async throws {
        do {
            while true {
                let message = try await connection.receive()
                var packet = message.content
                guard !packet.isEmpty else { continue }
                if let obfuscator {
                    guard let opened = obfuscator.open(packet) else { continue }
                    packet = opened
                }
                if mailbox.push(packet) {
                    bridge.enqueue { carrier.value?.assumeIsolated { $0.drainInbound() } }
                }
            }
        } catch {
            let code = TransportError.errnoCode(from: error)
            bridge.enqueue { carrier.value?.assumeIsolated { $0.deliverError(code) } }
            throw error
        }
    }

    // MARK: - State handling
    
    private func handleReady(interfaceType: NWInterface.InterfaceType?) {
        guard !closed, !ready else { return }
        ready = true
        cachedInterfaceType = interfaceType
        if let onReady {
            self.onReady = nil
            onReady()
        }
    }
    
    private func handleWaiting(_ code: Int32) {
        guard !closed else { return }
        if ready, let onPathDown {
            onPathDown()
        } else {
            deliverError(code)
        }
    }
    
    private func handleViabilityLost() {
        guard !closed, ready else { return }
        if let onPathDown {
            onPathDown()
        } else {
            deliverError(POSIXErrorCode.ENETDOWN.rawValue)
        }
    }
    
    private func handleBetterPath() {
        guard !closed, ready else { return }
        onBetterPath?()
    }

    // MARK: - Delivery
    
    private func drainInbound() {
        let batch = inbound.take()
        guard !closed, let packetHandler else { return }
        for packet in batch { packetHandler(packet) }
    }
    
    private func deliverError(_ code: Int32) {
        guard !closed, let handler = recvErrorHandler else { return }
        recvErrorHandler = nil
        handler(code)
    }
    
    private func releaseFlowCount() {
        guard flowCounted else { return }
        flowCounted = false
        FlowGauge.decrementUDP()
    }

    // MARK: - Address conversion
    
    private static func nwEndpoint(from storage: sockaddr_storage) -> NWEndpoint? {
        var storage = storage
        switch Int32(storage.ss_family) {
        case AF_INET:
            return withUnsafePointer(to: &storage) { pointer in
                pointer.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                    let rawPort = UInt16(bigEndian: sin.pointee.sin_port)
                    var address = sin.pointee.sin_addr
                    let bytes = withUnsafeBytes(of: &address) { Data($0) }
                    guard let ip = IPv4Address(bytes),
                          let port = NWEndpoint.Port(rawValue: rawPort) else { return nil }
                    return NWEndpoint.hostPort(host: .ipv4(ip), port: port)
                }
            }
        case AF_INET6:
            return withUnsafePointer(to: &storage) { pointer in
                pointer.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                    let rawPort = UInt16(bigEndian: sin6.pointee.sin6_port)
                    var address = sin6.pointee.sin6_addr
                    let bytes = withUnsafeBytes(of: &address) { Data($0) }
                    guard let ip = IPv6Address(bytes),
                          let port = NWEndpoint.Port(rawValue: rawPort) else { return nil }
                    return NWEndpoint.hostPort(host: .ipv6(ip), port: port)
                }
            }
        default:
            return nil
        }
    }
    
    private static func fillAnyLocalAddr(_ localAddr: inout sockaddr_storage, family: sa_family_t) {
        if Int32(family) == AF_INET {
            withUnsafeMutablePointer(to: &localAddr) { storage in
                storage.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                    sin.pointee = sockaddr_in()
                    sin.pointee.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                    sin.pointee.sin_family = sa_family_t(AF_INET)
                    sin.pointee.sin_addr.s_addr = INADDR_ANY
                }
            }
        } else {
            withUnsafeMutablePointer(to: &localAddr) { storage in
                storage.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                    sin6.pointee = sockaddr_in6()
                    sin6.pointee.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
                    sin6.pointee.sin6_family = sa_family_t(AF_INET6)
                    sin6.pointee.sin6_addr = in6addr_any
                }
            }
        }
    }
}
