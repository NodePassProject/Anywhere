//
//  HysteriaUDPConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 4/13/26.
//

import Foundation

private let logger = AnywhereLogger(category: "Hysteria-UDP")

nonisolated final class HysteriaUDPConnection: ProxyConnection {

    enum State { case idle, ready, closed }

    private let session: HysteriaSession
    private let destination: String

    /// Confined to `session.queue`. The setter mirrors readiness into
    /// `_isReady` so `isConnected` avoids a sync hop onto `session.queue` —
    /// one half of a udpQueue⇄quic.queue deadlock.
    private var _state: State = .idle
    private var state: State {
        get { _state }
        set {
            _state = newValue
            readyLock.withLock { _isReady = (newValue == .ready) }
        }
    }
    private let readyLock = UnfairLock()
    private var _isReady = false

    private var sessionID: UInt32 = 0

    /// Bounded FIFO with drop-oldest semantics (UDP is lossy). Mutated on `session.queue`.
    private var packetQueue: [Data] = []
    private static let maxQueuedPackets = 1024

    private var pendingReceive: ((Data?, Error?) -> Void)?

    /// Error stashed when the session tears down with no pending receive;
    /// surfaced on the next `receiveRaw`.
    private var closureError: Error?

    /// Per-PacketID reassembly slot; fragments arrive interleaved, so each
    /// PacketID owns one. Evicted on completion, TTL expiry, or cap overflow.
    private struct DefragSlot {
        var fragments: [Data?]
        var received: Int
        let fragmentCount: Int
        let createdAt: DispatchTime
    }
    private var defragSlots: [UInt16: DefragSlot] = [:]
    private static let defragSlotTTLNanos: UInt64 = 10 * 1_000_000_000
    /// Concurrent reassembly cap; 32 bounds worst-case memory to ~11 MB
    /// while keeping LRU eviction rare.
    private static let maxDefragSlots = 32

    /// Monotonic PacketID, wrapping 0xFFFF → 1 and skipping 0 ("unfragmented"
    /// to some servers); colliding IDs would merge two packets into one
    /// corrupt defrag slot. Mutated on `session.queue`.
    private var nextPacketID: UInt16 = 1

    init(session: HysteriaSession, destination: String) {
        self.session = session
        self.destination = destination
        super.init()
    }

    /// Lock-guarded readiness mirror; callable from any queue.
    override var isConnected: Bool {
        readyLock.withLock { _isReady }
    }

    override var outerTLSVersion: TLSVersion? { .tls13 }
    override var deliversDatagrams: Bool { true }

    // MARK: - Open

    func open(completion: @escaping (Error?) -> Void) {
        session.registerUDPSession(self) { [weak self] result in
            guard let self else { completion(HysteriaError.streamClosed); return }
            switch result {
            case .failure(let error):
                completion(error)
            case .success(let sid):
                self.sessionID = sid
                self.state = .ready
                completion(nil)
            }
        }
    }

    // MARK: - Incoming datagrams (from session)

    func handleIncomingDatagram(_ msg: HysteriaProtocol.UDPMessage) {
        // On session queue. `cancel()` defers `releaseUDPSession`; datagrams
        // in that window must not repopulate a dead connection.
        if state == .closed { return }
        let assembled: Data?
        if msg.fragCount <= 1 {
            assembled = msg.data
        } else {
            assembled = assembleFragment(msg)
        }
        // Drop empty payloads: receiveLoop treats empty Data as EOF, so a
        // zero-byte datagram would close the flow.
        guard let payload = assembled, !payload.isEmpty else { return }

        if let cb = pendingReceive {
            pendingReceive = nil
            // Hop so the completion never fires from ngtcp2's recv_datagram call stack.
            session.queue.async { cb(payload, nil) }
            return
        }
        if packetQueue.count >= Self.maxQueuedPackets {
            packetQueue.removeFirst()
        }
        packetQueue.append(payload)
    }

    private func assembleFragment(_ msg: HysteriaProtocol.UDPMessage) -> Data? {
        guard msg.fragID < msg.fragCount, msg.fragCount > 0 else { return nil }

        let now = DispatchTime.now()
        let nowNs = now.uptimeNanoseconds

        // Lazy TTL eviction: a full-dict scan per fragment is noticeable at the cap.
        let existing = defragSlots[msg.packetID]
        let existingIsExpired = existing.map {
            nowNs &- $0.createdAt.uptimeNanoseconds > Self.defragSlotTTLNanos
        } ?? false

        var slot: DefragSlot
        if let existing, !existingIsExpired,
           existing.fragmentCount == Int(msg.fragCount) {
            slot = existing
        } else {
            // New slot at cap: evict expired slots first, else the oldest.
            if existing == nil || existingIsExpired,
               defragSlots.count >= Self.maxDefragSlots {
                let victim: UInt16? = defragSlots
                    .lazy
                    .map { (key: $0.key, slot: $0.value) }
                    .min { lhs, rhs in
                        // Prefer expired slots over live ones, then oldest.
                        let lhsExpired = nowNs &- lhs.slot.createdAt.uptimeNanoseconds > Self.defragSlotTTLNanos
                        let rhsExpired = nowNs &- rhs.slot.createdAt.uptimeNanoseconds > Self.defragSlotTTLNanos
                        if lhsExpired != rhsExpired { return lhsExpired }
                        return lhs.slot.createdAt < rhs.slot.createdAt
                    }?.key
                if let victim {
                    defragSlots.removeValue(forKey: victim)
                }
            }
            slot = DefragSlot(
                fragments: Array(repeating: nil, count: Int(msg.fragCount)),
                received: 0,
                fragmentCount: Int(msg.fragCount),
                createdAt: now
            )
        }

        if slot.fragments[Int(msg.fragID)] == nil {
            slot.fragments[Int(msg.fragID)] = msg.data
            slot.received += 1
        }

        if slot.received < slot.fragmentCount {
            defragSlots[msg.packetID] = slot
            return nil
        }

        defragSlots.removeValue(forKey: msg.packetID)
        var full = Data()
        for part in slot.fragments {
            guard let part else { return nil }
            full.append(part)
        }
        return full
    }

    // MARK: - ProxyConnection overrides

    /// Wraps `data` in a Hysteria UDP datagram, fragmenting at the QUIC DATAGRAM MTU.
    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        // The wire format requires ≥1 data byte after the address; the
        // server silently discards zero-byte payloads.
        guard !data.isEmpty else {
            completion(nil)
            return
        }
        session.queue.async { [weak self] in
            guard let self else { completion(HysteriaError.streamClosed); return }
            guard self.state == .ready else {
                completion(self.state == .closed ? HysteriaError.streamClosed : HysteriaError.notReady)
                return
            }
            self.attemptSend(data: data, maxSizeOverride: nil, retriesLeft: 1, completion: completion)
        }
    }

    override func sendRaw(data: Data) {
        sendRaw(data: data) { _ in }
    }

    /// Fragments `data` and submits to QUIC; on `datagramTooLarge` (PMTU
    /// shrank mid-send) retries once with the bound from the error.
    /// Called on `session.queue`.
    private func attemptSend(
        data: Data,
        maxSizeOverride: Int?,
        retriesLeft: Int,
        completion: @escaping (Error?) -> Void
    ) {
        // maxSize 0 (DATAGRAM unsupported / MTU collapsed) is permanent for
        // this fixed destination — surface a terminal error.
        let maxSize = maxSizeOverride ?? self.session.maxDatagramPayloadSize
        let headerSize = HysteriaProtocol.udpHeaderSize(address: self.destination)
        guard maxSize > headerSize else {
            completion(HysteriaError.destinationTooLargeForDatagram(
                maxFrame: maxSize, headerSize: headerSize
            ))
            return
        }
        let packetID = self.newPacketID()
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
        let encoded = fragments.map { $0.encoded }
        self.session.writeDatagrams(encoded) { [weak self] error in
            // Fires on `session.queue`, so direct recursion into `attemptSend` is safe.
            if let qErr = error as? QUICConnection.QUICError,
               case .datagramTooLarge(let maxBound) = qErr,
               retriesLeft > 0,
               let self = self {
                guard self.state == .ready else {
                    completion(self.state == .closed
                        ? HysteriaError.streamClosed
                        : HysteriaError.notReady)
                    return
                }
                self.attemptSend(
                    data: data,
                    maxSizeOverride: maxBound,
                    retriesLeft: retriesLeft - 1,
                    completion: completion
                )
                return
            }
            completion(error)
        }
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        // Hop to the owning queue for packetQueue/pendingReceive/closureError.
        session.queue.async { [weak self] in
            guard let self else {
                completion(nil, HysteriaError.streamClosed)
                return
            }
            // Drain buffered packets before surfacing errors — they arrived
            // before the failure and represent good data.
            if !self.packetQueue.isEmpty {
                let packet = self.packetQueue.removeFirst()
                completion(packet, nil)
                return
            }
            // Surface any error stashed by a teardown between calls.
            if let err = self.closureError {
                self.closureError = nil
                completion(nil, err)
                return
            }
            // No buffered data, no stashed error, already closed → EOF.
            if self.state == .closed {
                completion(nil, nil)
                return
            }
            // Overlapping receives are an API violation; fail the stale
            // completion rather than dropping it (it captures the receive
            // loop closure and would hang it permanently).
            let stale = self.pendingReceive
            self.pendingReceive = completion
            stale?(nil, HysteriaError.connectionFailed("overlapping receiveRaw on Hysteria UDP"))
        }
    }

    override func cancel() {
        session.queue.async { [weak self] in
            guard let self, self.state != .closed else { return }
            self.state = .closed
            self.session.releaseUDPSession(self.sessionID)
            let cb = self.pendingReceive
            self.pendingReceive = nil
            self.packetQueue.removeAll()
            self.defragSlots.removeAll()
            cb?(nil, HysteriaError.streamClosed)
        }
    }

    func handleSessionError(_ error: Error) {
        session.queue.async { [weak self] in
            guard let self, self.state != .closed else { return }
            self.state = .closed
            let cb = self.pendingReceive
            self.pendingReceive = nil
            // No pending receive: stash so the next `receiveRaw` surfaces it.
            if cb == nil {
                self.closureError = error
            }
            cb?(nil, error)
        }
    }

    // MARK: - Helpers

    private func newPacketID() -> UInt16 {
        dispatchPrecondition(condition: .onQueue(session.queue))
        let pid = nextPacketID
        nextPacketID = nextPacketID == UInt16.max ? 1 : nextPacketID + 1
        return pid
    }
}
