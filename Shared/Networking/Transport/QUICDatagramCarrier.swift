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

nonisolated protocol QUICDatagramEngine: AnyObject, Sendable {
    func send(_ datagrams: [Data])
    func close()
}

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
        carrier?.update { $0.deliverPacket(datagram) }
    }

    func finished() {
        carrier?.update { $0.handleEngineFinished() }
    }
}

nonisolated final class QUICDatagramCarrier: Sendable {
    private let state: QUICState<QUICDatagramCarrierCore>

    init(obfuscator: QUICPacketObfuscator?) {
        state = QUICState(QUICDatagramCarrierCore(obfuscator: obfuscator))
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
    func startReceiving(onPacket: @escaping @Sendable ([Data]) -> Void, onError: @escaping @Sendable (Int32) -> Void) {
        update { $0.startReceiving(onPacket: onPacket, onError: onError) }
    }
    func send(_ datagrams: [Data]) { update { $0.send(datagrams) } }
    func close() { update { $0.close() } }

    fileprivate func deliverPendingPackets() {
        let (handler, packets) = update { $0.takePendingPackets() }
        guard let handler, !packets.isEmpty else { return }
        handler(packets)
    }
}

nonisolated final class QUICDatagramCarrierCore: QUICPublishingState {
    weak var owner: QUICDatagramCarrier?
    var publications: [@Sendable () -> Void] = []
    func publish(_ action: @escaping @Sendable () -> Void) { publications.append(action) }

    private let obfuscator: QUICPacketObfuscator?

    private enum Phase: PhaseTransitionable {
        case idle
        case connecting(any QUICDatagramEngine)
        case ready(any QUICDatagramEngine)
        case failed(Int32)
        case finished
        case closed

        var engine: (any QUICDatagramEngine)? {
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

    private var packetHandler: (@Sendable ([Data]) -> Void)?
    private var receiveErrorHandler: (@Sendable (Int32) -> Void)?
    private var pendingPackets: [Data] = []
    private static let maxPacketBatch = 16

    var onPathDown: (@Sendable () -> Void)?
    var onBetterPath: (@Sendable () -> Void)?
    var onReady: (@Sendable () -> Void)?

    private var flowSlot: FlowSlot?

    private var cachedInterfaceType: NWInterface.InterfaceType?

    init(obfuscator: QUICPacketObfuscator?) {
        self.obfuscator = obfuscator
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
        if #available(iOS 26.0, macOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *) {
            Phase.transition(&phase, to: .connecting(ModernQUICDatagramEngine(endpoint: endpoint, obfuscator: obfuscator, sink: sink)))
        } else {
            Phase.transition(&phase, to: .connecting(LegacyQUICDatagramEngine(endpoint: endpoint, obfuscator: obfuscator, sink: sink)))
        }
    }

    // MARK: - Receive

    func startReceiving(
        onPacket: @escaping @Sendable ([Data]) -> Void,
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

    // MARK: - Send

    func send(_ datagrams: [Data]) {
        guard !datagrams.isEmpty else { return }
        switch phase {
        case .connecting(let engine), .ready(let engine):
            engine.send(datagrams)
        case .idle, .failed, .finished, .closed:
            return
        }
    }

    // MARK: - Close

    func close() {
        if case .closed = phase { return }
        releaseFlowSlot()
        phase.engine?.close()
        Phase.transition(&phase, to: .closed)
        packetHandler = nil
        receiveErrorHandler = nil
        pendingPackets = []
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

    // MARK: - Delivery

    fileprivate func deliverPacket(_ packet: Data) {
        switch phase {
        case .connecting, .ready:
            pendingPackets.append(packet)
            guard pendingPackets.count == 1 else { return }
            publish { [weak owner] in owner?.deliverPendingPackets() }
        case .idle, .failed, .finished, .closed:
            break
        }
    }

    fileprivate func takePendingPackets() -> ((@Sendable ([Data]) -> Void)?, [Data]) {
        let batch: [Data]
        if pendingPackets.count > Self.maxPacketBatch {
            batch = Array(pendingPackets.prefix(Self.maxPacketBatch))
            pendingPackets.removeFirst(Self.maxPacketBatch)
            publish { [weak owner] in owner?.deliverPendingPackets() }
        } else {
            batch = pendingPackets
            pendingPackets = []
        }
        return (packetHandler, batch)
    }

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
        pendingPackets = []
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

// MARK: - Modern engine

@available(iOS 26.0, macOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *)
nonisolated final class ModernQUICDatagramEngine: QUICDatagramEngine, Sendable {
    private static let receiveConcurrency = 16
    private static let maxQueuedSendBatches = 512

    private let connection: NetworkConnection<UDP>
    private let obfuscator: QUICPacketObfuscator?
    private let driverTask: Task<Void, Never>
    private let sendTask: Task<Void, Never>
    private let outbound: AsyncStream<[Data]>.Continuation

    init(endpoint: NWEndpoint, obfuscator: QUICPacketObfuscator?, sink: QUICDatagramEngineSink) {
        let connection = NetworkConnection(to: endpoint) { UDP() }

        connection.onStateUpdate { connection, state in
            switch state {
            case .ready:
                sink.ready(interfaceType: connection.currentPath?.availableInterfaces.first?.type)
            case .failed(let error):
                sink.failed(AnywhereError.errnoCode(from: error))
            case .waiting(let error):
                sink.waiting(AnywhereError.errnoCode(from: error))
            default:
                break
            }
        }
        connection.onViabilityUpdate { _, viable in
            guard !viable else { return }
            sink.viabilityLost()
        }
        connection.onBetterPathUpdate { _, better in
            guard better else { return }
            sink.betterPath()
        }
        connection.onPathUpdate { _, path in
            sink.pathChanged(interfaceType: path.availableInterfaces.first?.type)
        }

        self.connection = connection
        self.obfuscator = obfuscator
        self.driverTask = Task { [obfuscator] in
            await Self.runDriver(connection: connection, sink: sink, obfuscator: obfuscator)
        }
        let (batches, outbound) = AsyncStream.makeStream(
            of: [Data].self,
            bufferingPolicy: .bufferingOldest(Self.maxQueuedSendBatches)
        )
        self.outbound = outbound
        self.sendTask = Task { [obfuscator] in
            await Self.runSendLoop(batches, over: connection, obfuscator: obfuscator)
        }
    }

    deinit {
        driverTask.cancel()
        outbound.finish()
        sendTask.cancel()
    }

    func send(_ datagrams: [Data]) {
        outbound.yield(datagrams)
    }

    func close() {
        driverTask.cancel()
        outbound.finish()
    }
    
    @concurrent
    private static func runSendLoop(
        _ batches: AsyncStream<[Data]>,
        over connection: NetworkConnection<UDP>,
        obfuscator: QUICPacketObfuscator?
    ) async {
        for await batch in batches {
            for datagram in batch {
                await transmit(datagram, over: connection, obfuscator: obfuscator)
            }
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

    // MARK: - Driver

    @concurrent
    private static func runDriver(
        connection: NetworkConnection<UDP>,
        sink: QUICDatagramEngineSink,
        obfuscator: QUICPacketObfuscator?
    ) async {
        do {
            try await Self.runReceiveLoop(
                connection,
                sink: sink,
                obfuscator: obfuscator
            )
        } catch {

        }
        sink.finished()
    }

    private static func runReceiveLoop(
        _ connection: NetworkConnection<UDP>,
        sink: QUICDatagramEngineSink,
        obfuscator: QUICPacketObfuscator?
    ) async throws {
        do {
            try await withThrowingTaskGroup(of: Void.self) { group in
                for _ in 0..<receiveConcurrency {
                    group.addTask {
                        try await Self.drainReceives(
                            connection,
                            sink: sink,
                            obfuscator: obfuscator
                        )
                    }
                }
                try await group.next()
            }
        } catch {
            sink.failed(AnywhereError.errnoCode(from: error))
            throw error
        }
    }

    @concurrent
    private static func drainReceives(
        _ connection: NetworkConnection<UDP>,
        sink: QUICDatagramEngineSink,
        obfuscator: QUICPacketObfuscator?
    ) async throws {
        while true {
            let message = try await connection.receive()
            var packet = message.content
            guard !packet.isEmpty else { continue }
            if let obfuscator {
                guard let opened = obfuscator.open(packet) else { continue }
                packet = opened
            }
            sink.packet(packet)
        }
    }
}
