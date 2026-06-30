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

// MARK: - QUICDatagramCarrier

/// The direct UDP carrier for ngtcp2, backed by a connected `NWConnection.udp`.
/// I/O runs inline on `queue` (ngtcp2 is single-threaded). Path identity is owned
/// by `QUICConnection`, so this 4-tuple is cosmetic — `connect` fills a family `ANY`.
nonisolated final class QUICDatagramCarrier: @unchecked Sendable {

    private typealias QUICError = QUICConnection.QUICError

    private let queue: DispatchQueue

    private var connection: NWConnection?

    private var packetHandler: ((Data) -> Void)?
    /// Fires once with the `errno` on terminal failure.
    private var recvErrorHandler: ((Int32) -> Void)?
    /// A failure seen before `startReceiving` armed the handler.
    private var pendingError: Int32?

    /// When set, a viability drop calls this instead of surfacing a terminal error,
    /// letting the owner attempt QUIC migration first. Fires on `queue`.
    var onPathDown: (() -> Void)?
    /// Fires (on `queue`) when NWConnection reports a better path — the cue for a
    /// proactive migration while still healthy.
    var onBetterPath: (() -> Void)?
    /// Fires once (on `queue`) when the connection first reaches `.ready`; lets a
    /// proactive migration wait for the target path before switching.
    var onReady: (() -> Void)?

    private var ready = false
    /// Guards against double-arming the receive loop.
    private var receiving = false

    init(queue: DispatchQueue) {
        self.queue = queue
    }

    /// The egress interface type in use, or nil before `.ready`. Lets the owner
    /// confirm a migration target is a *different* interface. Read on `queue`.
    var currentInterfaceType: NWInterface.InterfaceType? {
        connection?.currentPath?.availableInterfaces.first?.type
    }

    // MARK: - Connect

    /// Creates a connected UDP `NWConnection` to `remoteAddr` and fills `localAddr`
    /// with a family-matched placeholder. The connection becomes ready
    /// asynchronously; sends issued before then are buffered by the framework.
    /// Must run on `queue`.
    func connect(remoteAddr: sockaddr_storage, localAddr: inout sockaddr_storage) throws {
        guard let endpoint = Self.nwEndpoint(from: remoteAddr) else {
            throw QUICError.connectionFailed("invalid remote address")
        }
        Self.fillAnyLocalAddr(&localAddr, family: remoteAddr.ss_family)

        let connection = NWConnection(to: endpoint, using: .udp)
        self.connection = connection
        connection.stateUpdateHandler = { [weak self] state in
            self?.handleState(state, for: connection)
        }
        // Egress under a ready connection went away: hand off to `onPathDown` if set
        // (the owner migrates), else deliver a network error so ngtcp2 tears down
        // instead of waiting on its PTO/idle timers. Identity guards stale callbacks.
        connection.viabilityUpdateHandler = { [weak self] viable in
            guard let self, self.connection === connection, !viable, self.ready else { return }
            if let onPathDown = self.onPathDown {
                onPathDown()
            } else {
                self.deliverError(.posix(.ENETDOWN))
            }
        }
        // A better path exists (e.g. Wi-Fi returns while on cellular) — cue a
        // proactive migration before the current path degrades.
        connection.betterPathUpdateHandler = { [weak self] better in
            guard let self, self.connection === connection, better, self.ready else { return }
            self.onBetterPath?()
        }
        connection.start(queue: queue)
    }

    /// Tracks readiness and arms the receive loop once ready. Stale callbacks from
    /// a superseded connection are ignored. Must run on `queue`.
    private func handleState(_ state: NWConnection.State, for connection: NWConnection) {
        guard self.connection === connection else { return }
        switch state {
        case .ready:
            ready = true
            if packetHandler != nil, !receiving {
                receiving = true
                receiveLoop(connection)
            }
            if let onReady {
                self.onReady = nil
                onReady()
            }
        case .failed(let error):
            deliverError(error)
        case .waiting(let error):
            if isDefinitiveConnectError(error) { deliverError(error) }
        default:
            break
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
        if ready, let connection, !receiving {
            receiving = true
            receiveLoop(connection)
        }
    }

    /// Receives one datagram and re-arms. Must run on `queue`.
    private func receiveLoop(_ connection: NWConnection) {
        connection.receiveMessage { [weak self] data, _, _, error in
            guard let self, self.connection === connection else { return }
            if let data, !data.isEmpty {
                self.packetHandler?(data)
            }
            if let error {
                self.deliverError(error)
                return
            }
            // The handler may synchronously close the carrier; re-check identity.
            if self.connection === connection {
                self.receiveLoop(connection)
            }
        }
    }

    /// Maps an `NWError` to an `errno` and delivers it once, or latches it until
    /// `startReceiving` arms the handler. Must run on `queue`.
    private func deliverError(_ error: NWError) {
        let code: Int32 = { if case .posix(let posix) = error { return posix.rawValue }; return -1 }()
        if let handler = recvErrorHandler {
            recvErrorHandler = nil
            handler(code)
        } else {
            pendingError = code
        }
    }

    // MARK: - Send

    /// Sends `length` bytes; errors drop the packet (ngtcp2's loss recovery
    /// retransmits). Copies out of ngtcp2's reused buffer. Must run on `queue`.
    func send(_ bytes: UnsafePointer<UInt8>, length: Int) {
        guard let connection, length > 0 else { return }
        let datagram = Data(bytes: bytes, count: length)
        connection.send(content: datagram, completion: .idempotent)
    }

    // MARK: - Close

    /// Cancels the connection. Idempotent; must run on `queue`.
    func close() {
        if let connection {
            self.connection = nil
            connection.stateUpdateHandler = nil
            connection.cancel()
        }
        packetHandler = nil
        recvErrorHandler = nil
        onPathDown = nil
        onBetterPath = nil
        onReady = nil
        ready = false
        receiving = false
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
