//
//  QUICDatagramCarrier.swift
//  Anywhere
//
//  Created by NodePassProject on 5/21/26.
//

import Foundation
import Network
import Darwin

nonisolated private let logger = AnywhereLogger(category: "QUICDatagramCarrier")

actor QUICDatagramCarrier {
    nonisolated var unownedExecutor: UnownedSerialExecutor {
        bridge.executor.asUnownedSerialExecutor()
    }

    private let bridge: NGTCP2ConcurrencyBridge

    private let obfuscator: QUICPacketObfuscator?

    private var driverTask: Task<Void, Never>?
    
    private var udpConnection: NetworkConnection<UDP>?

    private var packetHandler: (@Sendable (Data) -> Void)?
    private var reveiceErrorHandler: (@Sendable (Int32) -> Void)?
    
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
            throw AnywhereError.quic(.connectionFailed(detail: "invalid remote address"))
        }
        Self.fillAnyLocalAddr(&localAddr, family: remoteAddr.ss_family)

        FlowGauge.incrementUDP()
        flowCounted = true

        let connection = NetworkConnection(to: endpoint) { UDP() }
        let bridge = bridge
        let carrier = WeakCarrier(value: self)

        connection.onStateUpdate { connection, state in
            switch state {
            case .ready:
                let interfaceType = connection.currentPath?.availableInterfaces.first?.type
                bridge.enqueue { carrier.value?.assumeIsolated { $0.handleReady(interfaceType: interfaceType) } }
            case .failed(let error):
                let code = AnywhereError.errnoCode(from: error)
                bridge.enqueue { carrier.value?.assumeIsolated { $0.deliverError(code) } }
            case .waiting(let error):
                let code = AnywhereError.errnoCode(from: error)
                bridge.enqueue { carrier.value?.assumeIsolated { $0.handleWaiting(code) } }
            default:
                break
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

        udpConnection = connection
        driverTask = Task { [bridge, obfuscator] in
            await Self.runDriver(
                connection: connection,
                bridge: bridge,
                carrier: carrier,
                obfuscator: obfuscator
            )
        }
    }

    // MARK: - Receive

    func startReceiving(
        onPacket: @escaping @Sendable (Data) -> Void,
        onError: @escaping @Sendable (Int32) -> Void
    ) {
        packetHandler = onPacket
        reveiceErrorHandler = onError
    }

    // MARK: - Send
    
    func send(_ datagram: Data) {
        guard !datagram.isEmpty, let udpConnection else { return }
        Task { [obfuscator] in
            await Self.transmit(datagram, over: udpConnection, obfuscator: obfuscator)
        }
    }

    @concurrent
    private static func transmit(
        _ datagram: Data,
        over connection: NetworkConnection<UDP>,
        obfuscator: QUICPacketObfuscator?
    ) async {
        if let obfuscator {
            let wireDatagrams = datagram.withUnsafeBytes { obfuscator.seal($0) }
            for wire in wireDatagrams {
                try? await connection.send(wire)
            }
        } else {
            try? await connection.send(datagram)
        }
    }

    // MARK: - Close
    
    func close() {
        guard !closed else { return }
        closed = true
        releaseFlowCount()
        udpConnection = nil
        driverTask?.cancel()
        driverTask = nil
        packetHandler = nil
        reveiceErrorHandler = nil
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
        connection: NetworkConnection<UDP>,
        bridge: NGTCP2ConcurrencyBridge,
        carrier: WeakCarrier,
        obfuscator: QUICPacketObfuscator?
    ) async {
        do {
            try await Self.runReceiveLoop(
                connection,
                bridge: bridge,
                carrier: carrier,
                obfuscator: obfuscator
            )
        } catch {
            
        }
        bridge.enqueue { carrier.value?.assumeIsolated {
            $0.udpConnection = nil
            $0.releaseFlowCount()
        } }
    }

    private static func runReceiveLoop(
        _ connection: NetworkConnection<UDP>,
        bridge: NGTCP2ConcurrencyBridge,
        carrier: WeakCarrier,
        obfuscator: QUICPacketObfuscator?
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
                let datagram = packet
                bridge.enqueue { carrier.value?.assumeIsolated { $0.deliverPacket(datagram) } }
            }
        } catch {
            let code = AnywhereError.errnoCode(from: error)
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
    
    private func deliverPacket(_ packet: Data) {
        guard !closed, let packetHandler else { return }
        packetHandler(packet)
    }
    
    private func deliverError(_ code: Int32) {
        guard !closed, let handler = reveiceErrorHandler else { return }
        reveiceErrorHandler = nil
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
