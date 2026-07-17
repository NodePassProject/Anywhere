//
//  QUICDatagramCarrier.swift
//  Anywhere
//
//  Created by NodePassProject on 5/21/26.
//

import Foundation
import Network
import Darwin
import Dispatch

nonisolated private let logger = AnywhereLogger(category: "QUICDatagramCarrier")

/// Carries QUIC's UDP datagrams for ngtcp2, backed by iOS 26's `NetworkConnection`.
///
/// The public surface is synchronous and runs on the owner-provided `queue`, while
/// a driver `Task` owns the connection inside `withNetworkConnection`. The path
/// callbacks (`onPathDown`/`onBetterPath`/`onReady`) map to
/// `onViabilityUpdate`/`onBetterPathUpdate`/`onStateUpdate`; `currentInterfaceType`
/// is cached from the path so it stays synchronously readable on `queue`.
nonisolated final class QUICDatagramCarrier: @unchecked Sendable {

    private typealias QUICError = QUICConnection.QUICError

    /// The ngtcp2 concurrency boundary; every method and callback hops onto its serial queue via
    /// `bridge.enqueue`, so the raw queue never leaks for unguarded access.
    private let bridge: NGTCP2ConcurrencyBridge

    /// Owns the `NetworkConnection` for its whole lifetime; cancelling it tears
    /// the connection down. `queue`-confined.
    private var driverTask: Task<Void, Never>?
    /// Datagrams are sent in order by the driver's send loop. `queue`-confined.
    private var sendContinuation: AsyncStream<Data>.Continuation?

    private var packetHandler: ((Data) -> Void)?
    /// Fires once with the `errno` on terminal failure.
    private var recvErrorHandler: ((Int32) -> Void)?
    /// A failure seen before `startReceiving` armed the handler.
    private var pendingError: Int32?
    /// Datagrams received before `startReceiving` armed the handler.
    private var pendingPackets: [Data] = []
    private var didWarnPendingOverflow = false

    /// When set, a viability drop calls this instead of surfacing a terminal error,
    /// letting the owner attempt QUIC migration first. Fires on `queue`.
    var onPathDown: (() -> Void)?
    /// Fires (on `queue`) when a better path is reported — the cue for a
    /// proactive migration while still healthy.
    var onBetterPath: (() -> Void)?
    /// Fires once (on `queue`) when the connection first reaches `.ready`; lets a
    /// proactive migration wait for the target path before switching.
    var onReady: (() -> Void)?

    private var ready = false
    /// Set once `close()` has run; guards the async callbacks against acting
    /// after teardown.
    private var closed = false
    /// One kernel socket per carrier; balanced exactly once by `releaseFlowCount`.
    private var flowCounted = false

    /// Cached egress interface type, refreshed from the connection's path so it
    /// stays synchronously readable. `queue`-confined.
    private var cachedInterfaceType: NWInterface.InterfaceType?

    /// Bounds the pre-handler datagram buffer.
    private static let maxPendingPackets = 1024

    init(bridge: NGTCP2ConcurrencyBridge) {
        self.bridge = bridge
    }

    deinit {
        driverTask?.cancel()
        guard flowCounted else { return }
        flowCounted = false
        FlowGauge.decrementUDP()
        logger.error("[QUIC] Datagram carrier deallocated without close() — recovered the FlowGauge count in deinit; a close() path has regressed.")
    }

    /// The egress interface type in use, or nil before `.ready`. Lets the owner
    /// confirm a migration target is a *different* interface. Read on `queue`.
    var currentInterfaceType: NWInterface.InterfaceType? {
        cachedInterfaceType
    }

    // MARK: - Connect

    /// Creates a connected UDP `NetworkConnection` to `remoteAddr` and fills `localAddr`
    /// with a family-matched placeholder. The connection becomes ready
    /// asynchronously; sends issued before then are buffered by the framework.
    /// Must run on `queue`.
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
        driverTask = Task { [bridge] in
            await Self.runDriver(endpoint: endpoint, sendStream: sendStream, bridge: bridge, carrier: carrier)
        }
    }

    // MARK: - Receive

    /// Arms the per-datagram handler. `onPacket` fires with a fresh `Data`;
    /// `onError` fires once on terminal failure. Must run on `queue`.
    func startReceiving(onPacket: @escaping (Data) -> Void,
                        onError: @escaping (Int32) -> Void) {
        packetHandler = onPacket
        recvErrorHandler = onError
        if let pendingError {
            self.pendingError = nil
            onError(pendingError)
            return
        }
        let drained = pendingPackets
        pendingPackets.removeAll()
        for data in drained {
            onPacket(data)
        }
    }

    // MARK: - Send

    /// Sends `length` bytes; errors drop the packet (ngtcp2's loss recovery
    /// retransmits). Copies out of ngtcp2's reused buffer. Must run on `queue`.
    func send(_ bytes: UnsafePointer<UInt8>, length: Int) {
        guard length > 0, let sendContinuation else { return }
        let datagram = Data(bytes: bytes, count: length)
        sendContinuation.yield(datagram)
    }

    // MARK: - Close

    /// Cancels the connection. Idempotent; must run on `queue`.
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
        pendingError = nil
        pendingPackets.removeAll()
        didWarnPendingOverflow = false
        onPathDown = nil
        onBetterPath = nil
        onReady = nil
        ready = false
    }

    // MARK: - Driver

    /// Weak handle the driver task and its loops hold instead of the carrier itself.
    private struct WeakCarrier: @unchecked Sendable {
        weak var value: QUICDatagramCarrier?
    }

    /// Owns the `NetworkConnection` for the whole session. `withNetworkConnection`
    /// tears the connection down deterministically when this task is cancelled or
    /// returns. Runs off `queue`; all state mutation hops back onto `queue`.
    private static func runDriver(
        endpoint: NWEndpoint,
        sendStream: AsyncStream<Data>,
        bridge: NGTCP2ConcurrencyBridge,
        carrier: WeakCarrier
    ) async {
        do {
            try await withNetworkConnection(to: endpoint, using: { UDP() }) { connection in
                connection.onStateUpdate { connection, state in
                    switch state {
                    case .ready:
                        // Capture the interface here so it's cached before `onReady`
                        // fires (proactive migration reads it immediately).
                        let interfaceType = connection.currentPath?.availableInterfaces.first?.type
                        bridge.enqueue { carrier.value?.handleReady(interfaceType: interfaceType) }
                    case .failed(let error):
                        let code = TransportError.errnoCode(from: error)
                        bridge.enqueue { carrier.value?.deliverError(code) }
                    case .waiting(let error):
                        let code = TransportError.errnoCode(from: error)
                        bridge.enqueue { carrier.value?.handleWaiting(code) }
                    default:
                        break  // .setup, .preparing, .cancelled
                    }
                }
                // Egress under a ready connection went away: hand off to `onPathDown`
                // if set (the owner migrates), else deliver a network error so ngtcp2
                // tears down instead of waiting on its PTO/idle timers.
                connection.onViabilityUpdate { _, viable in
                    guard !viable else { return }
                    bridge.enqueue { carrier.value?.handleViabilityLost() }
                }
                // A better path exists (e.g. Wi-Fi returns while on cellular) — cue a
                // proactive migration before the current path degrades.
                connection.onBetterPathUpdate { _, better in
                    guard better else { return }
                    bridge.enqueue { carrier.value?.handleBetterPath() }
                }
                connection.onPathUpdate { _, path in
                    let interfaceType = path.availableInterfaces.first?.type
                    bridge.enqueue { carrier.value?.cachedInterfaceType = interfaceType }
                }

                try await withThrowingTaskGroup(of: Void.self) { group in
                    group.addTask { try await Self.runSendLoop(connection, stream: sendStream) }
                    group.addTask { try await Self.runReceiveLoop(connection, bridge: bridge, carrier: carrier) }
                    _ = try await group.next()
                    group.cancelAll()
                }
            }
        } catch {
            // Connection ended (cancelled or failed).
        }
        bridge.enqueue { carrier.value?.releaseFlowCount() }
    }

    /// Drains ordered datagram sends; errors drop the packet (ngtcp2 retransmits).
    /// Runs off `queue`.
    private static func runSendLoop(_ connection: NetworkConnection<UDP>, stream: AsyncStream<Data>) async throws {
        for await datagram in stream {
            try? await connection.send(datagram)
        }
    }

    /// Continuously receives datagrams, starting the connection on the first read.
    /// A receive failure is terminal. Runs off `queue`.
    private static func runReceiveLoop(
        _ connection: NetworkConnection<UDP>,
        bridge: NGTCP2ConcurrencyBridge,
        carrier: WeakCarrier
    ) async throws {
        do {
            while true {
                let message = try await connection.receive()
                let data = message.content
                if !data.isEmpty {
                    bridge.enqueue { carrier.value?.deliverPacket(data) }
                }
            }
        } catch {
            let code = TransportError.errnoCode(from: error)
            bridge.enqueue { carrier.value?.deliverError(code) }
            throw error
        }
    }

    // MARK: - State handling (on queue)

    /// First `.ready`: caches the interface, then fires `onReady` once.
    private func handleReady(interfaceType: NWInterface.InterfaceType?) {
        guard !closed, !ready else { return }
        ready = true
        cachedInterfaceType = interfaceType
        if let onReady {
            self.onReady = nil
            onReady()
        }
    }

    /// A `.waiting` report: once ready, prefer migration; otherwise it's terminal.
    private func handleWaiting(_ code: Int32) {
        guard !closed else { return }
        if ready, let onPathDown {
            onPathDown()
        } else {
            deliverError(code)
        }
    }

    /// Egress under a ready connection went away. Must run on `queue`.
    private func handleViabilityLost() {
        guard !closed, ready else { return }
        if let onPathDown {
            onPathDown()
        } else {
            deliverError(POSIXErrorCode.ENETDOWN.rawValue)
        }
    }

    /// A better path appeared while the current one still works. Must run on `queue`.
    private func handleBetterPath() {
        guard !closed, ready else { return }
        onBetterPath?()
    }

    // MARK: - Delivery (on queue)

    /// Delivers a datagram, or buffers it if no handler is armed yet. Must run on
    /// `queue`.
    private func deliverPacket(_ data: Data) {
        guard !closed else { return }
        if let packetHandler {
            packetHandler(data)
        } else {
            if pendingPackets.count >= Self.maxPendingPackets {
                pendingPackets.removeFirst()
                if !didWarnPendingOverflow {
                    didWarnPendingOverflow = true
                    logger.warning("[QUIC] Pre-handler buffer overflowed (cap \(Self.maxPendingPackets)); dropping oldest until startReceiving arms")
                }
            }
            pendingPackets.append(data)
        }
    }

    /// Delivers a terminal error code once, or latches it until `startReceiving`
    /// arms the handler. Must run on `queue`.
    private func deliverError(_ code: Int32) {
        guard !closed else { return }
        if let handler = recvErrorHandler {
            recvErrorHandler = nil
            handler(code)
        } else {
            pendingError = code
        }
    }

    /// Balances `FlowGauge` exactly once per carrier. Must run on `queue`.
    private func releaseFlowCount() {
        guard flowCounted else { return }
        flowCounted = false
        FlowGauge.decrementUDP()
    }

    // MARK: - Address conversion

    /// Converts a `sockaddr_storage` (IPv4/IPv6) to an `NWEndpoint` host/port.
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

    /// Fills `localAddr` with a family-matched `ANY` placeholder; the real local
    /// 4-tuple is unused for routing (path identity lives in `QUICConnection`).
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
