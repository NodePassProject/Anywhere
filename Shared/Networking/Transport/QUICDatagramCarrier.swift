//
//  QUICDatagramCarrier.swift
//  Anywhere
//
//  Created by NodePassProject on 5/21/26.
//

import Foundation
import Synchronization
import Darwin
import Network

nonisolated private let logger = AnywhereLogger(category: "QUICDatagramCarrier")

nonisolated struct QUICDatagramEngineSink: Sendable {
    fileprivate weak var carrier: QUICDatagramCarrier?

    func ready(interfaceType: NWInterface.InterfaceType?) {
        carrier?.update { $0.handleReady(interfaceType: interfaceType) }
    }

    func waiting(_ code: Int32) {
        carrier?.update { $0.handleWaiting(code) }
    }

    func failed(_ code: Int32) {
        carrier?.update { $0.deliverError(code) }
    }

    func viabilityLost() {
        carrier?.update { $0.handleViabilityLost() }
    }

    func betterPath() {
        carrier?.update { $0.handleBetterPath() }
    }

    func pathChanged(interfaceType: NWInterface.InterfaceType?) {
        carrier?.update { $0.handlePathUpdate(interfaceType: interfaceType) }
    }

    func packet(_ datagram: Data) {
        carrier?.deliverPacket(datagram)
    }

    func finished() {
        carrier?.update { $0.handleEngineFinished() }
    }
}

nonisolated final class QUICDatagramCarrier: Sendable {
    private let state: QUICState<QUICDatagramCarrierCore>

    init(obfuscator: QUICPacketObfuscator?, executor: BridgeExecutor) {
        state = QUICState(QUICDatagramCarrierCore(obfuscator: obfuscator, executor: executor), queue: executor.queue)
        state.update { $0.owner = self }
    }

    fileprivate func update<T: Sendable>(_ body: (QUICDatagramCarrierCore) -> T) -> T { state.update(body) }
    var currentInterfaceType: NWInterface.InterfaceType? { state.read { $0.currentInterfaceType } }
    var isUsable: Bool { state.read { $0.isUsable } }
    var onPathDown: (@Sendable () -> Void)? {
        get { state.read { $0.onPathDown } }
        set { update { $0.onPathDown = newValue } }
    }
    var onBetterPath: (@Sendable () -> Void)? {
        get { state.read { $0.onBetterPath } }
        set { update { $0.onBetterPath = newValue } }
    }
    var onReady: (@Sendable () -> Void)? {
        get { state.read { $0.onReady } }
        set {
            update { core in
                if core.isReady, let newValue { core.publish(newValue) }
                else { core.onReady = newValue }
            }
        }
    }
    func connect(remoteAddr: sockaddr_storage, localAddr: inout sockaddr_storage) throws {
        let result: Result<sockaddr_storage, Error> = update { core in
            Result {
                var local = sockaddr_storage()
                try core.connect(remoteAddr: remoteAddr, localAddr: &local)
                return local
            }
        }
        localAddr = try result.get()
    }
    func startReceiving(onPacket: @escaping @Sendable (Data) -> Void, onError: @escaping @Sendable (Int32) -> Void) {
        update { $0.startReceiving(onPacket: onPacket, onError: onError) }
    }
    func send(_ datagrams: [Data]) {
        guard !datagrams.isEmpty else { return }
        state.read { $0.sendingEngine }?.send(datagrams)
    }
    func close() { update { $0.close() } }

    fileprivate func deliverPacket(_ packet: Data) {
        state.read { $0.receivingPacketHandler }?(packet)
    }
}

nonisolated final class QUICDatagramCarrierCore: QUICPublishingState {
    weak var owner: QUICDatagramCarrier?
    var publications: [@Sendable () -> Void] = []
    func publish(_ action: @escaping @Sendable () -> Void) { publications.append(action) }

    private let obfuscator: QUICPacketObfuscator?
    private let executor: BridgeExecutor

    private enum Phase: PhaseTransitionable {
        case idle
        case connecting(QUICDatagramEngine)
        case ready(QUICDatagramEngine)
        case failed(Int32)
        case finished
        case closed

        var engine: QUICDatagramEngine? {
            switch self {
            case .connecting(let engine), .ready(let engine): engine
            case .idle, .failed, .finished, .closed: nil
            }
        }

        var label: String {
            switch self {
            case .idle: "idle"
            case .connecting: "connecting"
            case .ready: "ready"
            case .failed(let code): "failed(\(code))"
            case .finished: "finished"
            case .closed: "closed"
            }
        }

        var isTerminal: Bool {
            switch self {
            case .failed, .finished, .closed: true
            case .idle, .connecting, .ready: false
            }
        }

        var isClosed: Bool {
            if case .closed = self { true } else { false }
        }

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.idle, .connecting),
                 (.connecting, .ready):
                return true
            case (_, .failed), (_, .finished):
                return !old.isTerminal
            case (_, .closed):
                return !old.isClosed
            default:
                return false
            }
        }
    }
    private var phase: Phase = .idle

    private var packetHandler: (@Sendable (Data) -> Void)?
    private var receiveErrorHandler: (@Sendable (Int32) -> Void)?

    var onPathDown: (@Sendable () -> Void)?
    var onBetterPath: (@Sendable () -> Void)?
    var onReady: (@Sendable () -> Void)?

    private var flowSlot: FlowSlot?

    private var cachedInterfaceType: NWInterface.InterfaceType?

    init(obfuscator: QUICPacketObfuscator?, executor: BridgeExecutor) {
        self.obfuscator = obfuscator
        self.executor = executor
    }

    deinit {
        phase.engine?.close()
    }

    var currentInterfaceType: NWInterface.InterfaceType? {
        cachedInterfaceType
    }

    var isReady: Bool { if case .ready = phase { true } else { false } }

    var isUsable: Bool {
        switch phase {
        case .connecting, .ready: true
        case .idle, .failed, .finished, .closed: false
        }
    }

    var sendingEngine: QUICDatagramEngine? { phase.engine }

    var receivingPacketHandler: (@Sendable (Data) -> Void)? {
        switch phase {
        case .connecting, .ready: packetHandler
        case .idle, .failed, .finished, .closed: nil
        }
    }

    // MARK: - Connect

    func connect(remoteAddr: sockaddr_storage, localAddr: inout sockaddr_storage) throws {
        guard case .idle = phase else {
            throw AnywhereError.quic(.connectionFailed(detail: "carrier is \(phase.label)"))
        }
        guard let endpoint = Self.nwEndpoint(from: remoteAddr) else {
            throw AnywhereError.quic(.connectionFailed(detail: "invalid remote address"))
        }
        Self.fillAnyLocalAddr(&localAddr, family: remoteAddr.ss_family)

        flowSlot = FlowSlot(context: "[QUIC] Datagram carrier")

        let sink = QUICDatagramEngineSink(carrier: owner)
        Phase.transition(
            &phase,
            to: .connecting(QUICDatagramEngine(endpoint: endpoint, obfuscator: obfuscator, executor: executor, sink: sink))
        )
    }

    // MARK: - Receive

    func startReceiving(
        onPacket: @escaping @Sendable (Data) -> Void,
        onError: @escaping @Sendable (Int32) -> Void
    ) {
        let deadCode: Int32?
        switch phase {
        case .failed(let code):
            deadCode = code
        case .finished, .closed:
            deadCode = POSIXErrorCode.ECONNABORTED.rawValue
        case .idle, .connecting, .ready:
            deadCode = nil
        }
        if let deadCode {
            publish { onError(deadCode) }
            return
        }
        packetHandler = onPacket
        receiveErrorHandler = onError
    }

    // MARK: - Close

    func close() {
        if case .closed = phase { return }
        releaseFlowSlot()
        phase.engine?.close()
        Phase.transition(&phase, to: .closed)
        packetHandler = nil
        receiveErrorHandler = nil
        onPathDown = nil
        onBetterPath = nil
        onReady = nil
    }

    // MARK: - State handling

    fileprivate func handleReady(interfaceType: NWInterface.InterfaceType?) {
        guard case .connecting(let engine) = phase,
              Phase.transition(&phase, to: .ready(engine)) else { return }
        cachedInterfaceType = interfaceType
        if let onReady {
            self.onReady = nil
            publish { onReady() }
        }
    }

    fileprivate func handleWaiting(_ code: Int32) {
        switch phase {
        case .ready:
            if let onPathDown {
                publish { onPathDown() }
            } else {
                enterFailed(code)
            }
        case .connecting:
            enterFailed(code)
        case .idle, .failed, .finished, .closed:
            break
        }
    }

    fileprivate func handleViabilityLost() {
        guard case .ready = phase else { return }
        if let onPathDown {
            publish { onPathDown() }
        } else {
            enterFailed(POSIXErrorCode.ENETDOWN.rawValue)
        }
    }

    fileprivate func handleBetterPath() {
        guard case .ready = phase else { return }
        let handler = onBetterPath
        publish { handler?() }
    }

    fileprivate func handlePathUpdate(interfaceType: NWInterface.InterfaceType?) {
        cachedInterfaceType = interfaceType
    }

    fileprivate func handleEngineFinished() {
        releaseFlowSlot()
        switch phase {
        case .idle, .failed, .finished, .closed:
            return
        case .connecting, .ready:
            if case .ready(let engine) = phase, let onPathDown {
                engine.close()
                Phase.transition(&phase, to: .finished)
                publish { onPathDown() }
            } else {
                enterFailed(POSIXErrorCode.ECONNABORTED.rawValue)
            }
        }
    }

    // MARK: - Errors

    fileprivate func deliverError(_ code: Int32) {
        enterFailed(code)
    }

    private func enterFailed(_ code: Int32) {
        switch phase {
        case .failed, .finished, .closed:
            return
        case .idle, .connecting, .ready:
            break
        }
        phase.engine?.close()
        Phase.transition(&phase, to: .failed(code))
        releaseFlowSlot()
        if let handler = receiveErrorHandler {
            receiveErrorHandler = nil
            publish { handler(code) }
        }
    }

    private func releaseFlowSlot() {
        flowSlot?.release()
        flowSlot = nil
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

// MARK: - Engine

nonisolated final class QUICDatagramEngine: Sendable {
    private static let receiveConcurrency = 16

    private let connection: NWConnection
    private let obfuscator: QUICPacketObfuscator?
    private let executor: BridgeExecutor

    private let terminated = OneShotLatch()

    init(endpoint: NWEndpoint, obfuscator: QUICPacketObfuscator?, executor: BridgeExecutor, sink: QUICDatagramEngineSink) {
        let connection = NWConnection(to: endpoint, using: .udp)
        self.connection = connection
        self.obfuscator = obfuscator
        self.executor = executor

        connection.stateUpdateHandler = { [weak connection] state in
            switch state {
            case .ready:
                sink.ready(interfaceType: connection?.currentPath?.availableInterfaces.first?.type)
            case .failed(let error):
                sink.failed(AnywhereError.errnoCode(from: error))
            case .waiting(let error):
                sink.waiting(AnywhereError.errnoCode(from: error))
            default:
                break
            }
        }
        connection.viabilityUpdateHandler = { viable in
            guard !viable else { return }
            sink.viabilityLost()
        }
        connection.betterPathUpdateHandler = { better in
            guard better else { return }
            sink.betterPath()
        }
        connection.pathUpdateHandler = { path in
            sink.pathChanged(interfaceType: path.availableInterfaces.first?.type)
        }

        connection.start(queue: executor.queue)
        for _ in 0..<Self.receiveConcurrency {
            Self.armReceive(on: connection, obfuscator: obfuscator, sink: sink, terminated: terminated)
        }
    }

    deinit {
        connection.cancel()
    }
    
    func send(_ datagrams: [Data]) {
        if executor.isOnQueue {
            transmit(datagrams)
        } else {
            executor.queue.async { [self] in transmit(datagrams) }
        }
    }

    private func transmit(_ datagrams: [Data]) {
        connection.batch {
            for datagram in datagrams {
                if let obfuscator {
                    let wireDatagrams = datagram.withUnsafeBytes { obfuscator.seal($0) }
                    for wire in wireDatagrams {
                        connection.send(content: wire, completion: .contentProcessed { _ in })
                    }
                } else {
                    connection.send(content: datagram, completion: .contentProcessed { _ in })
                }
            }
        }
    }

    func close() {
        terminated.claim()
        let connection = connection
        executor.queue.async { connection.cancel() }
    }

    private static func armReceive(
        on connection: NWConnection,
        obfuscator: QUICPacketObfuscator?,
        sink: QUICDatagramEngineSink,
        terminated: OneShotLatch
    ) {
        connection.receiveMessage { content, _, _, error in
            if let error {
                if terminated.claim() {
                    sink.failed(AnywhereError.errnoCode(from: error))
                    sink.finished()
                }
                return
            }
            if let content, !content.isEmpty {
                if let obfuscator {
                    if let opened = obfuscator.open(content) {
                        sink.packet(opened)
                    }
                } else {
                    sink.packet(content)
                }
            }
            guard !terminated.isClaimed else { return }
            Self.armReceive(on: connection, obfuscator: obfuscator, sink: sink, terminated: terminated)
        }
    }
}
