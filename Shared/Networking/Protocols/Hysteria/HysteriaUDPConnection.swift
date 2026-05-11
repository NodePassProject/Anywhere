//
//  HysteriaUDPConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/13/26.
//

import Foundation
import Security

private let logger = AnywhereLogger(category: "Hysteria-UDP")

nonisolated final class HysteriaUDPConnection: ProxyConnection {

    enum State { case idle, ready, closed }

    private let session: HysteriaSession
    private let destination: String
    private var state: State = .idle
    private var sessionID: UInt32 = 0

    /// Per-datagram FIFO. Hysteria delivers one UDP packet per QUIC DATAGRAM,
    /// so the packet boundary is already preserved on the wire — no
    /// stream-style length framing is involved.
    ///
    /// Bounded at `maxQueuedPackets` with drop-oldest semantics when the
    /// receiver can't keep up — matches the reference Go client's 1024-slot
    /// `ReceiveCh` (core/client/udp.go:18) and preserves UDP's lossy
    /// contract instead of growing memory without bound.
    private var packetQueue: [Data] = []
    private let packetLock = UnfairLock()
    private static let maxQueuedPackets = 1024

    private var pendingReceive: ((Data?, Error?) -> Void)?

    /// Single-packet defragmenter. Hysteria guarantees that a new PacketID
    /// invalidates any partial state from a previous PacketID — matches the
    /// reference Defragger implementation.
    private var pendingPacketID: UInt16 = 0
    private var pendingFragments: [Data?] = []
    private var pendingFragmentsReceived = 0
    private var pendingFragmentCount: UInt8 = 0

    init(session: HysteriaSession, destination: String) {
        self.session = session
        self.destination = destination
        super.init()
    }

    override var isConnected: Bool {
        session.isOnQueue ? (state == .ready) : session.queue.sync { state == .ready }
    }

    override var outerTLSVersion: TLSVersion? { .tls13 }

    // MARK: - Open

    func open(completion: @escaping (Error?) -> Void) {
        session.registerUDPSession(self) { [weak self] sid in
            guard let self else { completion(HysteriaError.streamClosed); return }
            guard let sid else {
                completion(HysteriaError.udpNotSupported)
                return
            }
            self.sessionID = sid
            self.state = .ready
            completion(nil)
        }
    }

    // MARK: - Incoming datagrams (from session)

    func handleIncomingDatagram(_ msg: HysteriaProtocol.UDPMessage) {
        // On session queue.
        let assembled: Data?
        if msg.fragCount <= 1 {
            assembled = msg.data
        } else {
            assembled = assembleFragment(msg)
        }
        guard let payload = assembled else { return }

        packetLock.lock()
        if let cb = pendingReceive {
            pendingReceive = nil
            packetLock.unlock()
            cb(payload, nil)
            return
        }
        if packetQueue.count >= Self.maxQueuedPackets {
            packetQueue.removeFirst()
        }
        packetQueue.append(payload)
        packetLock.unlock()
    }

    private func assembleFragment(_ msg: HysteriaProtocol.UDPMessage) -> Data? {
        // Drop fragments with invalid indices.
        guard msg.fragID < msg.fragCount, msg.fragCount > 0 else { return nil }

        if msg.packetID != pendingPacketID || pendingFragmentCount != msg.fragCount {
            pendingPacketID = msg.packetID
            pendingFragmentCount = msg.fragCount
            pendingFragments = Array(repeating: nil, count: Int(msg.fragCount))
            pendingFragmentsReceived = 0
        }
        if pendingFragments[Int(msg.fragID)] == nil {
            pendingFragments[Int(msg.fragID)] = msg.data
            pendingFragmentsReceived += 1
        }
        guard pendingFragmentsReceived == Int(pendingFragmentCount) else { return nil }

        var full = Data()
        for part in pendingFragments {
            guard let part else { return nil }
            full.append(part)
        }
        pendingFragments.removeAll(keepingCapacity: false)
        pendingFragmentsReceived = 0
        pendingFragmentCount = 0
        return full
    }

    // MARK: - ProxyConnection overrides

    /// Called by LWIPUDPFlow with one raw UDP payload per call (see the
    /// `.hysteria` branch of `LWIPUDPFlow.connectViaProxyClient`). Wraps the
    /// payload in a Hysteria UDP datagram, fragmenting when the QUIC
    /// DATAGRAM MTU would be exceeded.
    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        session.queue.async { [weak self] in
            guard let self else { completion(HysteriaError.streamClosed); return }
            guard self.state == .ready else {
                completion(self.state == .closed ? HysteriaError.streamClosed : HysteriaError.notReady)
                return
            }
            let maxSize = max(1, self.session.maxDatagramPayloadSize)
            let packetID = HysteriaUDPConnection.newPacketID()
            let fragments = HysteriaProtocol.fragmentUDP(
                sessionID: self.sessionID,
                packetID: packetID,
                address: self.destination,
                data: data,
                maxDatagramSize: maxSize
            )
            guard !fragments.isEmpty else {
                completion(HysteriaError.connectionFailed("UDP payload too large to fragment"))
                return
            }
            let encoded = fragments.map { HysteriaProtocol.encodeUDPMessage($0) }
            self.session.writeDatagrams(encoded, completion: completion)
        }
    }

    override func sendRaw(data: Data) {
        sendRaw(data: data) { _ in }
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        packetLock.lock()
        if !packetQueue.isEmpty {
            let packet = packetQueue.removeFirst()
            packetLock.unlock()
            completion(packet, nil)
            return
        }
        packetLock.unlock()

        session.queue.async { [weak self] in
            guard let self else { completion(nil, HysteriaError.streamClosed); return }
            if self.state == .closed {
                completion(nil, nil)
                return
            }
            self.pendingReceive = completion
        }
    }

    override func cancel() {
        session.queue.async { [weak self] in
            guard let self, self.state != .closed else { return }
            self.state = .closed
            self.session.releaseUDPSession(self.sessionID)
            if let cb = self.pendingReceive {
                self.pendingReceive = nil
                cb(nil, HysteriaError.streamClosed)
            }
            self.packetLock.lock()
            self.packetQueue.removeAll()
            self.packetLock.unlock()
        }
    }

    func handleSessionError(_ error: Error) {
        session.queue.async { [weak self] in
            guard let self, self.state != .closed else { return }
            self.state = .closed
            if let cb = self.pendingReceive {
                self.pendingReceive = nil
                cb(nil, error)
            }
        }
    }

    // MARK: - Helpers

    /// PacketID: 1...0xFFFF. 0 is reserved for "not fragmented" signalling
    /// by some Hysteria servers — stay away from it.
    private static func newPacketID() -> UInt16 {
        var v: UInt16 = 0
        _ = withUnsafeMutableBytes(of: &v) { buf in
            SecRandomCopyBytes(kSecRandomDefault, buf.count, buf.baseAddress!)
        }
        let candidate = UInt16(v & 0xFFFF)
        return candidate == 0 ? 1 : candidate
    }
}
